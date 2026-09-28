//! The key a host reads off disk: `Connection.use_disk_key` +
//! `identity_file`, the third key source next to the vault key and the
//! agent.
//!
//! OpenSSH has three; we had two, and the gap was invisible: a user with
//! `~/.ssh/id_ed25519` and no agent watched `ssh` authenticate and Oryxis
//! fall through to a password prompt, with nothing on screen saying why.
//! This is the third source, shaped like the two fixed-path probes the
//! SSH engine already runs (`~/.ssh/pageant.conf` in `engine::agent`,
//! `~/.Xauthority` in `x11::xauth`): an explicit value wins, a fixed
//! path is the fallback, and every failure is a value rather than an
//! error.
//!
//! It lives next to [`super::import_key`] rather than in the app because
//! that function is what makes it format-agnostic (PPK, legacy OpenSSL
//! PEM, PKCS#8 all normalize into what russh decodes), and because BOTH
//! consumers need the same answer: the app's `resolve_credentials` and
//! the MCP server's own dial. A host that authenticates in the UI must
//! not fail over MCP for want of a key source.
//!
//! ONE key is resolved, never a list. The engine takes a single
//! `KeyMaterial`, and widening that would ripple through the jump
//! resolver and the whole auth path to buy something the user can
//! already express: the resolved path is shown in the host editor, and
//! typing a path overrides the pick. The budget matters too, `Auto`
//! already spends one publickey attempt plus every agent identity
//! before the password, and `MaxAuthTries` defaults to 6.

use std::path::{Path, PathBuf};

/// Default private-key names scanned when no `identity_file` is set,
/// best-first rather than in OpenSSH's own order: OpenSSH tries all of
/// them and we offer one, so leading with `id_rsa` (its historical
/// first) would pick the weakest key on a machine that has several.
///
/// `id_ed25519_sk` is last rather than absent. The app signs with a
/// security-key file natively now (the file is a FIDO2 credential
/// handle, not a scalar), so a machine whose only key is a token handle
/// can use this source — but it goes at the END because "first usable
/// wins": a software key that works without hardware must never be
/// shadowed by one that needs a token plugged in. `id_ecdsa_sk` stays
/// out entirely until the ECDSA-SK signing path exists, since offering
/// a key we would only refuse is worse than not offering it.
/// `id_dsa` is absent because DSA is disabled server-side in current
/// OpenSSH; an explicit `identity_file` can still name any of them.
const DEFAULT_KEY_NAMES: &[&str] = &["id_ed25519", "id_ecdsa", "id_rsa", "id_ed25519_sk"];

/// What the disk source resolved to for one host. Every variant except
/// `Ready` is a reason the host editor can show, which is the point:
/// the failure that started this feature was a key being silently
/// absent from the auth attempt.
#[derive(Debug, Clone)]
pub enum DiskKey {
    /// `use_disk_key` is off, or the auth method uses no key at all.
    Off,
    /// Scanned `~/.ssh` and found none of the default names (or there
    /// is no home directory to scan).
    NotFound,
    /// An explicit `identity_file` that could not be read (absent, or
    /// not readable by this user).
    Unreadable(PathBuf, String),
    /// The file is a key but needs a passphrase, which nothing here can
    /// ask for: the engine decodes with no passphrase and the vault
    /// stores keys already decrypted. Importing it is the way in.
    Encrypted(PathBuf),
    /// The file exists and is not a key we can parse.
    Unusable(PathBuf, String),
    /// Ready to offer, normalized to the OpenSSH PEM russh decodes (so
    /// a PPK or a legacy OpenSSL PEM on disk works too), plus the
    /// signed user certificate sitting next to it when there is one.
    Ready {
        path: PathBuf,
        pem: String,
        certificate: Option<String>,
    },
}

impl DiskKey {
    /// What the engine offers, if this resolved to a usable key: the
    /// PEM and the certificate resolved from the SAME file, never a
    /// pair assembled from two sources (the invariant `KeyMaterial`
    /// exists to hold).
    pub fn material(self) -> Option<(String, Option<String>)> {
        match self {
            DiskKey::Ready {
                pem, certificate, ..
            } => Some((pem, certificate)),
            _ => None,
        }
    }

    /// The same answer without the key material, for the host editor.
    /// The hint is rebuilt whenever the form's inputs change, so it must
    /// not carry a secret around between frames.
    pub fn status(&self) -> DiskKeyStatus {
        let shown = |p: &PathBuf| display_path(p);
        match self {
            DiskKey::Off => DiskKeyStatus::Off,
            DiskKey::NotFound => DiskKeyStatus::NotFound,
            DiskKey::Unreadable(p, e) => DiskKeyStatus::Unreadable(shown(p), e.clone()),
            DiskKey::Encrypted(p) => DiskKeyStatus::Encrypted(shown(p)),
            DiskKey::Unusable(p, e) => DiskKeyStatus::Unusable(shown(p), e.clone()),
            DiskKey::Ready {
                path, certificate, ..
            } => DiskKeyStatus::Ready {
                path: shown(path),
                certificate: certificate.is_some(),
            },
        }
    }
}

/// [`DiskKey`] minus the key material: what the host editor renders.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DiskKeyStatus {
    #[default]
    Off,
    NotFound,
    Unreadable(String, String),
    Encrypted(String),
    Unusable(String, String),
    /// Resolved. `certificate` reports whether a `<key>-cert.pub` came
    /// with it, which is the difference between working and failing
    /// under `AuthMethod::Certificate` and therefore has to be visible
    /// rather than inferred.
    Ready { path: String, certificate: bool },
}

/// Resolve the disk key for a host.
///
/// `identity_file` wins over the scan (typing a path IS the choice of
/// which key), and `use_disk_key` gates both: a host that never opted in
/// offers nothing from disk, however many keys sit in `~/.ssh`.
pub fn resolve_disk_key(use_disk_key: bool, identity_file: Option<&str>) -> DiskKey {
    if !use_disk_key {
        return DiskKey::Off;
    }
    let explicit = identity_file
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(expand_tilde);
    resolve_paths(explicit.as_deref(), ssh_dir().as_deref())
}

/// The user's own home, from the environment rather than through
/// `dirs`, for two reasons: `dirs::home_dir()` is a WinAPI call that
/// ignores `$HOME` on Windows, and the headless harness relocates the
/// home it sandboxes so a test run never reads the developer's real
/// `~/.ssh`. Deliberately NOT `oryxis_core::paths::home_dir`, whose
/// `ORYXIS_HOME` override governs the app's own data tree only: a
/// portable vault must not relocate the user's SSH configuration.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

fn ssh_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".ssh"))
}

/// Expand a leading `~/` against the home directory. Anything else
/// (absolute, relative, a Windows drive path) is taken verbatim.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = home_dir()
    {
        return home.join(rest);
    }
    if path == "~"
        && let Some(home) = home_dir()
    {
        return home;
    }
    PathBuf::from(path)
}

/// The resolution itself, over paths already expanded, so tests drive it
/// with a temp directory instead of the machine's real home.
fn resolve_paths(explicit: Option<&Path>, ssh_dir: Option<&Path>) -> DiskKey {
    if let Some(path) = explicit {
        return match std::fs::read_to_string(path) {
            Ok(text) => classify(path, &text),
            Err(e) => DiskKey::Unreadable(path.to_path_buf(), e.to_string()),
        };
    }
    let Some(dir) = ssh_dir else {
        return DiskKey::NotFound;
    };
    // First USABLE name wins, not first present: a passphrase-protected
    // `id_ed25519` next to a plain `id_rsa` must not dead-end the host.
    // The first problem is kept so "nothing worked" can still say what
    // was in the way instead of reporting an empty directory.
    let mut first_problem: Option<DiskKey> = None;
    for name in DEFAULT_KEY_NAMES {
        let path = dir.join(name);
        // An unreadable default is skipped silently: unlike an explicit
        // path, nobody asked for this particular file.
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match classify(&path, &text) {
            ready @ DiskKey::Ready { .. } => return ready,
            problem => {
                if first_problem.is_none() {
                    first_problem = Some(problem);
                }
            }
        }
    }
    first_problem.unwrap_or(DiskKey::NotFound)
}

/// Turn one file's contents into a verdict. [`super::import_key`] is the
/// same multi-format reader the Keychain import uses, so PPK and legacy
/// OpenSSL PEMs normalize here exactly as they would on import, and
/// "needs a passphrase" is its own answer rather than a parse failure.
fn classify(path: &Path, text: &str) -> DiskKey {
    match super::import_key("", text, None) {
        Ok(key) => DiskKey::Ready {
            certificate: sibling_certificate(path),
            path: path.to_path_buf(),
            pem: key.private_pem,
        },
        Err(crate::VaultError::KeyNeedsPassphrase) => DiskKey::Encrypted(path.to_path_buf()),
        Err(e) => DiskKey::Unusable(path.to_path_buf(), e.to_string()),
    }
}

/// OpenSSH's implicit certificate lookup: a signed user cert sits next
/// to its key as `<key>-cert.pub`. Picking it up here is what lets
/// `AuthMethod::Certificate` work off disk at all, since that method
/// offers the certificate and nothing else. Same probe the Keychain
/// import runs (`dispatch_keys/import.rs`), including the parse filter:
/// a stray same-named file must not poison the offer.
fn sibling_certificate(path: &Path) -> Option<String> {
    let cert = std::fs::read_to_string(format!("{}-cert.pub", path.display())).ok()?;
    ssh_key::Certificate::from_openssh(cert.trim())
        .ok()
        .map(|_| cert.trim().to_string())
}

/// Render a resolved path with the home directory folded back to `~`, so
/// the hint reads like what the user typed (and does not leak the
/// account name into a screenshot).
fn display_path(path: &Path) -> String {
    let full = path.display().to_string();
    let Some(home) = home_dir() else {
        return full;
    };
    let home = home.display().to_string();
    match full.strip_prefix(&home) {
        Some(rest) => format!("~{rest}"),
        None => full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A usable Ed25519 private key, as it would sit on disk.
    fn plain_pem() -> String {
        super::super::generate_ed25519("test").unwrap().private_pem
    }

    /// The same key, passphrase-protected the way `ssh-keygen` writes one.
    fn encrypted_pem() -> String {
        super::super::encrypt_private_pem(&plain_pem(), "hunter2").unwrap()
    }

    /// A CA-signed user certificate for the key in `pem`, as its
    /// OpenSSH public line, the way `ssh-keygen -s` writes one next to
    /// the key it certifies.
    fn signed_cert(pem: &str) -> String {
        use ssh_key::{certificate, Algorithm, PrivateKey};
        let user = PrivateKey::from_openssh(pem).unwrap();
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            user.public_key(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.serial(1).unwrap();
        builder.key_id("t").unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        builder.valid_principal("tester").unwrap();
        builder.sign(&ca).unwrap().to_openssh().unwrap()
    }

    fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn the_source_is_off_until_the_host_opts_in() {
        let dir = tempfile::tempdir().unwrap();
        let key = write(dir.path(), "id_ed25519", &plain_pem());
        // The gate is checked before anything is read: a usable key at a
        // named path still resolves to nothing.
        assert!(matches!(resolve_disk_key(false, None), DiskKey::Off));
        assert!(matches!(
            resolve_disk_key(false, Some(&key.display().to_string())),
            DiskKey::Off
        ));
    }

    #[test]
    fn an_explicit_path_wins_over_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "id_ed25519", &plain_pem());
        let named = write(dir.path(), "work_key", &plain_pem());
        match resolve_paths(Some(&named), Some(dir.path())) {
            DiskKey::Ready { path, .. } => assert_eq!(path, named),
            other => panic!("expected the named key, got {other:?}"),
        }
    }

    #[test]
    fn an_explicit_path_that_is_not_there_says_so() {
        let dir = tempfile::tempdir().unwrap();
        // Falling back to the scan here would be the wrong kindness: the
        // user named a file, and silently authenticating with another
        // key is exactly the surprise this source exists to remove.
        let missing = dir.path().join("nope");
        assert!(matches!(
            resolve_paths(Some(&missing), Some(dir.path())),
            DiskKey::Unreadable(p, _) if p == missing
        ));
    }

    #[test]
    fn the_scan_prefers_ed25519_over_rsa() {
        let dir = tempfile::tempdir().unwrap();
        // Same material under both names: what is asserted is the ORDER,
        // not which algorithm parses.
        write(dir.path(), "id_rsa", &plain_pem());
        let preferred = write(dir.path(), "id_ed25519", &plain_pem());
        match resolve_paths(None, Some(dir.path())) {
            DiskKey::Ready { path, .. } => assert_eq!(path, preferred),
            other => panic!("expected the ed25519 name first, got {other:?}"),
        }
    }

    #[test]
    fn a_passphrase_protected_key_is_reported_never_offered() {
        let dir = tempfile::tempdir().unwrap();
        let locked = write(dir.path(), "id_ed25519", &encrypted_pem());
        match resolve_paths(Some(&locked), None) {
            DiskKey::Encrypted(p) => assert_eq!(p, locked),
            other => panic!("expected Encrypted, got {other:?}"),
        }
        // And nothing about it reaches the engine.
        assert!(resolve_paths(Some(&locked), None).material().is_none());
    }

    #[test]
    fn a_locked_default_does_not_shadow_a_usable_one() {
        let dir = tempfile::tempdir().unwrap();
        // `id_ed25519` sorts first and cannot be used; the scan has to
        // keep going rather than report the directory as locked.
        write(dir.path(), "id_ed25519", &encrypted_pem());
        let usable = write(dir.path(), "id_rsa", &plain_pem());
        match resolve_paths(None, Some(dir.path())) {
            DiskKey::Ready { path, .. } => assert_eq!(path, usable),
            other => panic!("expected the plain key, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_of_locked_keys_reports_the_first_reason() {
        let dir = tempfile::tempdir().unwrap();
        let locked = write(dir.path(), "id_ed25519", &encrypted_pem());
        // Nothing usable anywhere, so the answer is the obstacle rather
        // than "no key found", which would send the user looking for a
        // file that is sitting right there.
        match resolve_paths(None, Some(dir.path())) {
            DiskKey::Encrypted(p) => assert_eq!(p, locked),
            other => panic!("expected Encrypted, got {other:?}"),
        }
    }

    #[test]
    fn a_file_that_is_not_a_key_is_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let junk = write(
            dir.path(),
            "id_ed25519",
            "ssh-ed25519 AAAAC3Nz not-a-private-key\n",
        );
        assert!(matches!(
            resolve_paths(Some(&junk), None),
            DiskKey::Unusable(p, _) if p == junk
        ));
    }

    #[test]
    fn an_empty_ssh_dir_finds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            resolve_paths(None, Some(dir.path())),
            DiskKey::NotFound
        ));
        // No home to scan is the same answer, never an error.
        assert!(matches!(resolve_paths(None, None), DiskKey::NotFound));
    }

    #[test]
    fn what_reaches_the_engine_is_the_normalized_pem() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "id_ed25519", &plain_pem());
        // `import_key` is what makes the source format-agnostic; the PEM
        // handed over is its normalized output, not the raw bytes, which
        // is why a PPK or a legacy PEM works here too.
        match resolve_paths(Some(&path), None) {
            DiskKey::Ready {
                pem, certificate, ..
            } => {
                assert!(pem.contains("BEGIN OPENSSH PRIVATE KEY"));
                assert!(ssh_key::PrivateKey::from_openssh(&pem).is_ok());
                // No `<key>-cert.pub` next to it, so nothing is offered
                // as a certificate.
                assert!(certificate.is_none());
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn a_sibling_cert_travels_with_the_key_it_certifies() {
        let dir = tempfile::tempdir().unwrap();
        let pem = plain_pem();
        let path = write(dir.path(), "id_ed25519", &pem);
        let cert = signed_cert(&pem);
        write(dir.path(), "id_ed25519-cert.pub", &cert);
        // OpenSSH's implicit lookup, and the only reason
        // `AuthMethod::Certificate` can work off disk: that method
        // offers the certificate and nothing else.
        match resolve_paths(Some(&path), None) {
            DiskKey::Ready { certificate, .. } => {
                assert_eq!(certificate.as_deref(), Some(cert.trim()));
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn a_sibling_that_is_not_a_cert_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "id_ed25519", &plain_pem());
        write(dir.path(), "id_ed25519-cert.pub", "not a certificate\n");
        // A stray same-named file must not poison the offer: the key
        // still authenticates, just without a certificate.
        match resolve_paths(Some(&path), None) {
            DiskKey::Ready { certificate, .. } => assert!(certificate.is_none()),
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn the_status_carries_the_path_and_not_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "id_ed25519", &plain_pem());
        let resolved = resolve_paths(Some(&path), None);
        let pem = match &resolved {
            DiskKey::Ready { pem, .. } => pem.clone(),
            other => panic!("expected Ready, got {other:?}"),
        };
        match resolved.status() {
            DiskKeyStatus::Ready {
                path: shown,
                certificate,
            } => {
                assert!(shown.ends_with("id_ed25519"));
                assert!(!shown.contains(&pem));
                assert!(!shown.contains("PRIVATE KEY"));
                assert!(!certificate, "no sibling cert was written");
            }
            other => panic!("expected Ready status, got {other:?}"),
        }
    }
}
