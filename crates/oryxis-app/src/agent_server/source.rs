//! The key source an agent connection signs against.
//!
//! The protocol layer ([`super::protocol`]) is generic over this trait
//! so it can be exercised with a [`MockKeySource`] in tests and backed
//! by the vault in production (`VaultKeySource`, Phase 2). Vault keys
//! are strictly read-only over the wire; when the user opts in
//! (Phase 4), external clients such as KeePassXC may ADD keys, which
//! live in an in-memory [`EphemeralStore`] beside the vault roster and
//! are never persisted.
//!
//! Security contract for the vault-backed impl: [`sign`](AgentKeySource::sign)
//! decrypts exactly one private key, uses it, and drops it; nothing is
//! cached across calls. A locked vault makes [`list`](AgentKeySource::list)
//! return empty and [`sign`](AgentKeySource::sign) fail, so an external
//! `git` sees "agent has no identities" instead of a hang. Ephemeral
//! keys are swept on lock: a locked Oryxis serves nothing at all.

use ssh_key::HashAlg;

/// One public key the agent advertises: its SSH wire blob (the bytes an
/// `IDENTITIES_ANSWER` carries) and a human comment (the vault label).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentPublicKey {
    /// The public key encoded as an SSH wire blob (`KeyData` encoding).
    pub blob: Vec<u8>,
    /// Comment shown by `ssh-add -l` etc.; the vault key's label.
    pub comment: String,
    /// The client asked for a per-signature confirm when it added this
    /// key (`SSH_AGENT_CONSTRAIN_CONFIRM`); prompts even when the
    /// global confirm setting is off. Always `false` for vault keys
    /// (their prompting is the global setting's call).
    pub requires_confirm: bool,
}

/// Why a sign request could not be answered. The protocol layer maps
/// every variant to a single `FAILURE` on the wire (the ssh-agent
/// protocol has no error detail), but the distinction drives logging.
#[derive(Debug)]
pub(crate) enum AgentSignError {
    /// No exposed key matches the requested blob.
    UnknownKey,
    /// The vault is locked (or the key is gone); nothing to sign with.
    Unavailable,
    /// The key material could not be parsed or the signature failed.
    SignFailed(String),
}

/// The RSA hash the client asked for, decoded from the `SIGN_REQUEST`
/// flag bits. Ed25519 / ECDSA ignore it (their hash is fixed by the
/// algorithm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignHash {
    /// No RSA flag set: default to SHA-256. Legacy ssh-rsa (SHA-1) is
    /// deprecated and rejected by modern servers, so we never emit it;
    /// a client that sets no flag is rare and SHA-256 is universally
    /// accepted.
    Default,
    Sha256,
    Sha512,
}

impl SignHash {
    /// The `ssh-key` hash for RSA signing (`None` for non-RSA keys,
    /// which the caller passes through unchanged).
    pub(crate) fn rsa_hash(self) -> Option<HashAlg> {
        match self {
            Self::Sha512 => Some(HashAlg::Sha512),
            // Default and explicit 256 both sign with SHA-256.
            Self::Default | Self::Sha256 => Some(HashAlg::Sha256),
        }
    }
}

/// A source of SSH keys for the agent to serve. `Send + Sync` so one
/// instance is shared across per-connection tasks. The write ops
/// default to refusing (a read-only signing oracle); sources that
/// accept external keys override them with an [`EphemeralStore`].
pub(crate) trait AgentKeySource: Send + Sync {
    /// The keys to advertise right now. Empty while the vault is locked
    /// or when the user has exposed none.
    fn list(&self) -> Vec<AgentPublicKey>;

    /// Sign `data` with the key whose wire blob is `key_blob`, honoring
    /// the requested RSA hash. Returns the SSH signature wire blob (the
    /// `string signature` a `SIGN_RESPONSE` carries).
    fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        hash: SignHash,
    ) -> Result<Vec<u8>, AgentSignError>;

    /// Accept a client-added key (`ADD_IDENTITY`). `false` = refused
    /// (the wire answer is FAILURE). Read-only by default.
    fn add(
        &self,
        _private: ssh_key::PrivateKey,
        _comment: String,
        _requires_confirm: bool,
        _expires_at: Option<std::time::Instant>,
    ) -> bool {
        false
    }

    /// Remove a client-added key by its public blob. Vault keys are
    /// never removable over the wire. Read-only by default.
    fn remove(&self, _key_blob: &[u8]) -> bool {
        false
    }

    /// Remove every client-added key (`REMOVE_ALL_IDENTITIES`); the
    /// vault roster is untouched. Read-only by default.
    fn remove_all(&self) -> bool {
        false
    }
}

/// Sign `data` with an in-memory private key, honoring the requested
/// RSA hash, and encode the signature as its SSH wire blob. Shared by
/// the vault decrypt-at-sign path and the ephemeral store.
pub(crate) fn sign_blob(
    private: &ssh_key::PrivateKey,
    data: &[u8],
    hash: SignHash,
) -> Result<Vec<u8>, AgentSignError> {
    use ssh_encoding::Encode;
    use ssh_key::private::KeypairData;

    let sig: ssh_key::Signature = match private.key_data() {
        KeypairData::Rsa(pair) => signature::Signer::try_sign(&(pair, hash.rsa_hash()), data)
            .map_err(|e| AgentSignError::SignFailed(e.to_string()))?,
        _ => signature::Signer::try_sign(private, data)
            .map_err(|e| AgentSignError::SignFailed(e.to_string()))?,
    };
    let mut out = Vec::new();
    sig.encode(&mut out)
        .map_err(|e| AgentSignError::SignFailed(e.to_string()))?;
    Ok(out)
}

/// A key pushed in by an external client (KeePassXC et al). Lives in
/// memory only; the vault never sees it.
struct EphemeralKey {
    blob: Vec<u8>,
    private: ssh_key::PrivateKey,
    comment: String,
    requires_confirm: bool,
    /// Lifetime constraint deadline; `None` = until removed / swept.
    expires_at: Option<std::time::Instant>,
}

/// The in-memory roster of client-added keys. Expired entries are
/// pruned lazily on every access (no timer to leak); [`clear`] is the
/// sweep hook for vault lock / toggle-off.
///
/// [`clear`]: EphemeralStore::clear
#[derive(Default)]
pub(crate) struct EphemeralStore {
    keys: std::sync::Mutex<Vec<EphemeralKey>>,
    /// Bumped on every accepted ADD, never decremented. Lets the app
    /// notice "a key just landed" by comparing two readings, without
    /// walking the roster (which holds private material) and without a
    /// push channel into the update loop. A re-add of the same blob
    /// counts: KeePassXC re-pushes on every database unlock, and that
    /// unlock IS the event a waiting connection cares about.
    adds: std::sync::atomic::AtomicU64,
}

impl EphemeralStore {
    fn prune(keys: &mut Vec<EphemeralKey>) {
        let now = std::time::Instant::now();
        keys.retain(|k| k.expires_at.is_none_or(|t| t > now));
    }

    pub(crate) fn list(&self) -> Vec<AgentPublicKey> {
        let Ok(mut keys) = self.keys.lock() else {
            return Vec::new();
        };
        Self::prune(&mut keys);
        keys.iter()
            .map(|k| AgentPublicKey {
                blob: k.blob.clone(),
                comment: k.comment.clone(),
                requires_confirm: k.requires_confirm,
            })
            .collect()
    }

    /// Store a key, replacing any existing entry for the same public
    /// blob (a re-add refreshes comment and constraints, matching
    /// OpenSSH). `false` only when the public blob cannot be encoded.
    pub(crate) fn add(
        &self,
        private: ssh_key::PrivateKey,
        comment: String,
        requires_confirm: bool,
        expires_at: Option<std::time::Instant>,
    ) -> bool {
        use ssh_encoding::Encode;
        let mut blob = Vec::new();
        if private.public_key().key_data().encode(&mut blob).is_err() {
            return false;
        }
        let Ok(mut keys) = self.keys.lock() else {
            return false;
        };
        Self::prune(&mut keys);
        keys.retain(|k| k.blob != blob);
        keys.push(EphemeralKey {
            blob,
            private,
            comment,
            requires_confirm,
            expires_at,
        });
        self.adds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    /// Monotonic count of accepted ADDs (see [`EphemeralStore::adds`]).
    pub(crate) fn add_generation(&self) -> u64 {
        self.adds.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Drop the entry for `blob`; `false` when no added key matches
    /// (vault keys deliberately land here).
    pub(crate) fn remove(&self, blob: &[u8]) -> bool {
        let Ok(mut keys) = self.keys.lock() else {
            return false;
        };
        Self::prune(&mut keys);
        let before = keys.len();
        keys.retain(|k| k.blob != blob);
        keys.len() < before
    }

    /// Sweep every added key (vault lock, toggle-off, REMOVE_ALL).
    pub(crate) fn clear(&self) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.clear();
        }
    }

    /// Number of live (non-expired) client-added keys. Feeds the
    /// settings status line so "the agent is up but currently holds
    /// zero external keys" is visible instead of a silent auth
    /// failure (issue #98).
    pub(crate) fn live_count(&self) -> usize {
        let Ok(mut keys) = self.keys.lock() else {
            return 0;
        };
        Self::prune(&mut keys);
        keys.len()
    }

    /// Sign with an added key if `blob` is ours; `None` hands the
    /// lookup back to the caller (a vault key or unknown).
    pub(crate) fn sign(
        &self,
        blob: &[u8],
        data: &[u8],
        hash: SignHash,
    ) -> Option<Result<Vec<u8>, AgentSignError>> {
        let Ok(mut keys) = self.keys.lock() else {
            return None;
        };
        Self::prune(&mut keys);
        let key = keys.iter().find(|k| k.blob == blob)?;
        Some(sign_blob(&key.private, data, hash))
    }
}

/// The production [`AgentKeySource`]: a dedicated unlocked `VaultStore`
/// handle (its own SQLite handle on the same file, like `sync_runtime`;
/// WAL keeps concurrent handles safe). Keys are advertised by their
/// public blob; the private key is decrypted only inside [`sign`] and
/// dropped immediately. A `locked` gate flips on vault lock so the
/// agent goes dark without tearing down the listener.
pub(crate) struct VaultKeySource {
    vault: std::sync::Mutex<oryxis_vault::VaultStore>,
    locked: std::sync::atomic::AtomicBool,
    /// The `agent_server_allow_add` setting, baked at spawn (the
    /// runtime restarts on toggle). Off = pure read-only oracle.
    allow_add: bool,
    /// Client-added keys (Phase 4). Only ever populated when
    /// `allow_add` is on; swept on lock.
    ephemeral: EphemeralStore,
}

impl VaultKeySource {
    pub(crate) fn new(vault: oryxis_vault::VaultStore, allow_add: bool) -> Self {
        Self {
            vault: std::sync::Mutex::new(vault),
            locked: std::sync::atomic::AtomicBool::new(false),
            allow_add,
            ephemeral: EphemeralStore::default(),
        }
    }

    /// Live count of client-added keys (settings status line).
    pub(crate) fn external_key_count(&self) -> usize {
        self.ephemeral.live_count()
    }

    /// Monotonic ADD counter, compared reading-to-reading by the
    /// port-forward healer to spot "an external tool just pushed a key".
    pub(crate) fn external_add_generation(&self) -> u64 {
        self.ephemeral.add_generation()
    }

    /// Flip the gate and lock the dedicated handle (zeroize its key) so
    /// nothing can be decrypted while the app vault is locked. Added
    /// keys are swept too: a locked Oryxis serves nothing (clients like
    /// KeePassXC re-add after the next unlock).
    pub(crate) fn lock(&self) {
        self.locked.store(true, std::sync::atomic::Ordering::SeqCst);
        self.ephemeral.clear();
        if let Ok(mut v) = self.vault.lock() {
            v.lock();
        }
    }

    /// Re-unlock the dedicated handle with the master password and open
    /// the gate. `None` password re-opens a passwordless vault.
    pub(crate) fn unlock(&self, master_password: Option<&str>) {
        if let Ok(mut v) = self.vault.lock() {
            let ok = match master_password {
                Some(pw) => v.unlock(pw).is_ok(),
                None => v.open_without_password().is_ok(),
            };
            if ok {
                // Sweep again before reopening the gate: an `add` that
                // read `locked == false` just before `lock()` flipped it
                // could have inserted its key AFTER `lock()`'s clear (the
                // gate check is outside the ephemeral mutex). That key is
                // invisible while locked but would resurface here; clear
                // it so "swept on lock" holds across the race window.
                self.ephemeral.clear();
                self.locked.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    /// The public blob (KeyData wire encoding) of a stored key's
    /// OpenSSH public line, or `None` when it does not parse.
    fn blob_of(public_line: &str) -> Option<Vec<u8>> {
        use ssh_encoding::Encode;
        let pk = ssh_key::PublicKey::from_openssh(public_line).ok()?;
        let mut blob = Vec::new();
        pk.key_data().encode(&mut blob).ok()?;
        Some(blob)
    }
}

impl AgentKeySource for VaultKeySource {
    fn list(&self) -> Vec<AgentPublicKey> {
        if self.locked.load(std::sync::atomic::Ordering::SeqCst) {
            return Vec::new();
        }
        let Ok(vault) = self.vault.lock() else {
            return Vec::new();
        };
        vault
            .list_keys()
            .unwrap_or_default()
            .into_iter()
            // Security-key rows are never served here, whether or not
            // they hold material. The app signs with a token natively
            // (the stored blob is a FIDO2 credential handle, not a
            // scalar), so a `has_private` row can still be one this
            // agent must not advertise: `sign` below would hand the
            // handle to a software signer. The algorithm check is what
            // keeps `list()` symmetric with `sign()`; `has_private`
            // additionally covers a plain public-only import.
            .filter(|k| {
                k.expose_via_agent && k.has_private && !k.algorithm.is_security_key()
            })
            .filter_map(|k| {
                Self::blob_of(&k.public_key).map(|blob| AgentPublicKey {
                    blob,
                    comment: k.label,
                    requires_confirm: false,
                })
            })
            .chain(self.ephemeral.list())
            .collect()
    }

    fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        hash: SignHash,
    ) -> Result<Vec<u8>, AgentSignError> {
        use ssh_key::PrivateKey;

        if self.locked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AgentSignError::Unavailable);
        }
        // Client-added keys sign from memory; the vault path below only
        // ever sees vault keys.
        if let Some(result) = self.ephemeral.sign(key_blob, data, hash) {
            return result;
        }
        let vault = self.vault.lock().map_err(|_| AgentSignError::Unavailable)?;

        // Find the exposed key whose public blob matches, then decrypt
        // exactly that one private key.
        let key = vault
            .list_keys()
            .map_err(|e| AgentSignError::SignFailed(e.to_string()))?
            .into_iter()
            .find(|k| {
                k.expose_via_agent
                    && k.has_private
                    && !k.algorithm.is_security_key()
                    && Self::blob_of(&k.public_key).as_deref() == Some(key_blob)
            })
            .ok_or(AgentSignError::UnknownKey)?;

        // The vault getter hands back a plain `String`; wrap it so the
        // decrypted PEM (the same key material as the parsed key) is
        // wiped when it drops, not left in freed heap. Honours the
        // module's decrypt-per-signature / nothing-cached contract.
        let pem = zeroize::Zeroizing::new(
            vault
                .get_key_private(&key.id)
                .map_err(|e| AgentSignError::SignFailed(e.to_string()))?
                .ok_or(AgentSignError::Unavailable)?,
        );
        // The parsed key is zeroized on drop by ssh_key; the PEM above
        // by the Zeroizing wrapper.
        let private = PrivateKey::from_openssh(&*pem)
            .map_err(|e| AgentSignError::SignFailed(e.to_string()))?;

        sign_blob(&private, data, hash)
    }

    fn add(
        &self,
        private: ssh_key::PrivateKey,
        comment: String,
        requires_confirm: bool,
        expires_at: Option<std::time::Instant>,
    ) -> bool {
        // Adds are refused while locked (the whole agent is dark) and
        // when the user has not opted in.
        if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        self.ephemeral.add(private, comment, requires_confirm, expires_at)
    }

    fn remove(&self, key_blob: &[u8]) -> bool {
        if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        self.ephemeral.remove(key_blob)
    }

    fn remove_all(&self) -> bool {
        if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        // Clearing an already-empty roster is still a success.
        self.ephemeral.clear();
        true
    }
}

#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use ssh_encoding::Encode;
    use ssh_key::PrivateKey;

    /// In-memory key source for protocol tests: holds decrypted keys
    /// directly (a test convenience the vault-backed impl never does).
    /// `new` mirrors the read-only default; [`writable`] mirrors the
    /// opt-in `allow_add` mode.
    ///
    /// [`writable`]: MockKeySource::writable
    pub(crate) struct MockKeySource {
        keys: Vec<(Vec<u8>, PrivateKey, String)>,
        pub locked: std::sync::atomic::AtomicBool,
        allow_add: bool,
        ephemeral: EphemeralStore,
    }

    impl MockKeySource {
        pub(crate) fn new(keys: Vec<(PrivateKey, String)>) -> Self {
            Self::build(keys, false)
        }

        /// A source that accepts ADD/REMOVE, like a production source
        /// with `agent_server_allow_add` on.
        pub(crate) fn writable(keys: Vec<(PrivateKey, String)>) -> Self {
            Self::build(keys, true)
        }

        fn build(keys: Vec<(PrivateKey, String)>, allow_add: bool) -> Self {
            let keys = keys
                .into_iter()
                .map(|(k, label)| {
                    let mut blob = Vec::new();
                    k.public_key().key_data().encode(&mut blob).unwrap();
                    (blob, k, label)
                })
                .collect();
            Self {
                keys,
                locked: std::sync::atomic::AtomicBool::new(false),
                allow_add,
                ephemeral: EphemeralStore::default(),
            }
        }
    }

    impl AgentKeySource for MockKeySource {
        fn list(&self) -> Vec<AgentPublicKey> {
            if self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return Vec::new();
            }
            self.keys
                .iter()
                .map(|(blob, _, comment)| AgentPublicKey {
                    blob: blob.clone(),
                    comment: comment.clone(),
                    requires_confirm: false,
                })
                .chain(self.ephemeral.list())
                .collect()
        }

        fn sign(
            &self,
            key_blob: &[u8],
            data: &[u8],
            hash: SignHash,
        ) -> Result<Vec<u8>, AgentSignError> {
            if self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(AgentSignError::Unavailable);
            }
            if let Some(result) = self.ephemeral.sign(key_blob, data, hash) {
                return result;
            }
            let (_, key, _) = self
                .keys
                .iter()
                .find(|(blob, _, _)| blob == key_blob)
                .ok_or(AgentSignError::UnknownKey)?;
            sign_blob(key, data, hash)
        }

        fn add(
            &self,
            private: PrivateKey,
            comment: String,
            requires_confirm: bool,
            expires_at: Option<std::time::Instant>,
        ) -> bool {
            if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            self.ephemeral.add(private, comment, requires_confirm, expires_at)
        }

        fn remove(&self, key_blob: &[u8]) -> bool {
            if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            self.ephemeral.remove(key_blob)
        }

        fn remove_all(&self) -> bool {
            if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            self.ephemeral.clear();
            true
        }
    }
}

/// Unit tests for the ephemeral store's own mechanics (expiry pruning,
/// same-blob replacement); the wire-level behavior is covered by the
/// protocol tests.
#[cfg(test)]
mod ephemeral_tests {
    use super::*;

    fn key(label: &str) -> ssh_key::PrivateKey {
        let g = oryxis_vault::generate_key(label, "", oryxis_vault::GenerateSpec::Ed25519)
            .unwrap();
        ssh_key::PrivateKey::from_openssh(&g.private_pem).unwrap()
    }

    #[test]
    fn expired_key_is_pruned_on_access() {
        let store = EphemeralStore::default();
        assert!(store.add(key("a"), "a".into(), false, Some(std::time::Instant::now())));
        // The deadline has passed by the next access (retain keeps only
        // strictly-future deadlines).
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(store.list().is_empty(), "expired key no longer advertised");
        let blob = {
            use ssh_encoding::Encode;
            let k = key("b");
            let mut blob = Vec::new();
            k.public_key().key_data().encode(&mut blob).unwrap();
            blob
        };
        assert!(store.sign(&blob, b"x", SignHash::Default).is_none());
    }

    #[test]
    fn re_add_replaces_same_key() {
        let store = EphemeralStore::default();
        let k = key("a");
        assert!(store.add(k.clone(), "first".into(), false, None));
        assert!(store.add(k, "second".into(), true, None));
        let listed = store.list();
        assert_eq!(listed.len(), 1, "same blob is replaced, not duplicated");
        assert_eq!(listed[0].comment, "second");
        assert!(listed[0].requires_confirm, "constraints refreshed on re-add");
    }
}

/// Integration tests for the production [`VaultKeySource`] against a
/// real on-disk vault, exercising the two-handle model the runtime
/// uses (the app writes through one `VaultStore`, the agent reads
/// through its own). These cover the runtime guarantees the protocol
/// tests only prove on the mock: a live `expose_via_agent` toggle
/// crossing handles, and the lock gate.
#[cfg(test)]
mod vault_source_tests {
    use super::*;
    use oryxis_vault::{generate_key, GenerateSpec, VaultStore};

    /// Open a fresh password-protected vault, save one exposed key
    /// through the "app" handle, and return the temp dir (kept alive),
    /// the db path, and the key id.
    fn seed_vault() -> (tempfile::TempDir, std::path::PathBuf, uuid::Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let mut app = VaultStore::open(&path).unwrap();
        app.set_master_password("master").unwrap();
        let generated = generate_key("agent-key", "", GenerateSpec::Ed25519).unwrap();
        let id = generated.key.id;
        app.save_key(&generated.key, Some(&generated.private_pem)).unwrap();
        (dir, path, id)
    }

    /// A second handle on the same file, unlocked, wrapped as the
    /// production source, mirroring `AgentRuntime::spawn`.
    fn agent_source(path: &std::path::Path) -> VaultKeySource {
        agent_source_with(path, false)
    }

    fn agent_source_with(path: &std::path::Path, allow_add: bool) -> VaultKeySource {
        let mut agent = VaultStore::open(path).unwrap();
        agent.unlock("master").unwrap();
        VaultKeySource::new(agent, allow_add)
    }

    /// A decrypted in-memory key, as an external ADD would deliver it.
    fn external_key(label: &str) -> ssh_key::PrivateKey {
        let g = generate_key(label, "", GenerateSpec::Ed25519).unwrap();
        ssh_key::PrivateKey::from_openssh(&g.private_pem).unwrap()
    }

    #[test]
    fn exposed_key_lists_and_signs() {
        use signature::Verifier;
        use ssh_encoding::Decode;

        let (_dir, path, _id) = seed_vault();
        let source = agent_source(&path);

        let listed = source.list();
        assert_eq!(listed.len(), 1, "the exposed key is advertised");

        // The advertised blob signs, and the signature verifies against
        // the same public key: the decrypt-at-sign path is real crypto.
        let blob = listed[0].blob.clone();
        let data = b"cross-handle sign";
        let sig_blob = source.sign(&blob, data, SignHash::Default).unwrap();
        let sig = ssh_key::Signature::decode(&mut sig_blob.as_slice()).unwrap();
        let key_data = ssh_key::public::KeyData::decode(&mut blob.as_slice()).unwrap();
        key_data.verify(data, &sig).expect("signature verifies");
    }

    #[test]
    fn expose_toggle_crosses_handles_live() {
        let (_dir, path, id) = seed_vault();
        let source = agent_source(&path);
        assert_eq!(source.list().len(), 1);
        let blob = source.list()[0].blob.clone();

        // Flip the flag through a SEPARATE app handle (the write path
        // the UI uses), then confirm the already-running agent source
        // drops the key on its very next read. This is the guarantee
        // the "Hidden from agent" menu item makes.
        let app = {
            let mut v = VaultStore::open(&path).unwrap();
            v.unlock("master").unwrap();
            v
        };
        let mut key = app.list_keys().unwrap().into_iter().find(|k| k.id == id).unwrap();
        key.expose_via_agent = false;
        app.save_key(&key, None).unwrap();

        assert!(source.list().is_empty(), "hidden key is no longer advertised");
        // The sign path re-checks the flag independently: even a stale
        // blob from a client that listed earlier cannot sign now.
        assert!(
            matches!(source.sign(&blob, b"x", SignHash::Default), Err(AgentSignError::UnknownKey)),
            "a hidden key refuses to sign",
        );

        // Re-expose: the key comes back on the next read, no restart.
        key.expose_via_agent = true;
        app.save_key(&key, None).unwrap();
        assert_eq!(source.list().len(), 1, "re-exposed key is advertised again");
    }

    #[test]
    fn lock_gate_hides_and_restores_roster() {
        let (_dir, path, _id) = seed_vault();
        let source = agent_source(&path);
        assert_eq!(source.list().len(), 1);
        let blob = source.list()[0].blob.clone();

        source.lock();
        assert!(source.list().is_empty(), "a locked vault serves no identities");
        assert!(
            matches!(source.sign(&blob, b"x", SignHash::Default), Err(AgentSignError::Unavailable)),
            "a locked vault cannot sign",
        );

        source.unlock(Some("master"));
        assert_eq!(source.list().len(), 1, "unlock restores the roster");
        assert!(source.sign(&blob, b"x", SignHash::Default).is_ok(), "unlock restores signing");
    }

    #[test]
    fn add_refused_unless_opted_in() {
        let (_dir, path, _id) = seed_vault();

        // Default (allow_add off): the read-only oracle refuses every
        // write op even though the vault is unlocked.
        let source = agent_source(&path);
        assert!(!source.add(external_key("ext"), "ext".into(), false, None));
        assert!(!source.remove_all());

        // Opted in: the add lands beside the vault key.
        let source = agent_source_with(&path, true);
        assert!(source.add(external_key("ext"), "ext".into(), false, None));
        assert_eq!(source.list().len(), 2, "vault key + added key");
    }

    #[test]
    fn lock_sweeps_added_keys() {
        let (_dir, path, _id) = seed_vault();
        let source = agent_source_with(&path, true);
        assert!(source.add(external_key("ext"), "ext".into(), false, None));
        assert_eq!(source.list().len(), 2);

        // Lock: everything goes dark, INCLUDING the added key, and it
        // stays gone after unlock (the client re-adds when it wants to).
        source.lock();
        assert!(source.list().is_empty());
        assert!(!source.add(external_key("ext2"), "ext2".into(), false, None), "locked refuses adds");
        source.unlock(Some("master"));
        assert_eq!(source.list().len(), 1, "only the vault key survives the lock");

        // REMOVE_ALL sweeps added keys but never the vault roster.
        assert!(source.add(external_key("ext"), "ext".into(), false, None));
        assert_eq!(source.list().len(), 2);
        assert!(source.remove_all());
        assert_eq!(source.list().len(), 1, "vault key untouched by REMOVE_ALL");
    }
}
