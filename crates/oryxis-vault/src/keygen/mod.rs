use ssh_key::{Algorithm, HashAlg, PrivateKey};

use oryxis_core::models::key::{KeyAlgorithm, SshKey};

use crate::store::VaultError;

mod disk;
mod pem;
mod ppk;

pub use disk::{resolve_disk_key, DiskKey, DiskKeyStatus, DiskKeyWanted};
pub use pem::is_traditional_encrypted;

/// Generated key pair, private PEM + SshKey model.
#[derive(Debug)]
pub struct GeneratedKey {
    pub key: SshKey,
    pub private_pem: String,
}

/// Generate an Ed25519 SSH key pair.
pub fn generate_ed25519(label: &str) -> Result<GeneratedKey, VaultError> {
    generate_key(label, "", GenerateSpec::Ed25519)
}

/// What to generate. Ed25519 is the recommended default; RSA covers
/// legacy servers (bit size selectable, 4096 default in the UI);
/// ECDSA covers constrained gear that speaks neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateSpec {
    Ed25519,
    Rsa { bits: RsaBits },
    Ecdsa { curve: EcdsaCurveChoice },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaBits {
    B2048,
    B3072,
    B4096,
}

impl RsaBits {
    pub fn bits(self) -> usize {
        match self {
            Self::B2048 => 2048,
            Self::B3072 => 3072,
            Self::B4096 => 4096,
        }
    }
}

impl std::fmt::Display for RsaBits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bits())
    }
}

impl std::fmt::Display for EcdsaCurveChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurveChoice {
    P256,
    P384,
    P521,
}

/// Generate a fresh SSH key pair for `spec`. `comment` (usually
/// `user@host` or an email) lands in the key's comment field and thus
/// in the public line; empty is fine. RSA generation takes seconds,
/// callers run this off the UI thread.
pub fn generate_key(
    label: &str,
    comment: &str,
    spec: GenerateSpec,
) -> Result<GeneratedKey, VaultError> {
    use ssh_key::private::{EcdsaKeypair, KeypairData, RsaKeypair};

    let mut rng = rand::rng();
    let map_err = |e: ssh_key::Error| VaultError::Crypto(format!("Key generation failed: {}", e));
    let mut private_key = match spec {
        GenerateSpec::Ed25519 => {
            PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(map_err)?
        }
        // `PrivateKey::random` hardcodes RSA at 4096; go through
        // `RsaKeypair::random` so every offered size works.
        GenerateSpec::Rsa { bits } => {
            let pair = RsaKeypair::random(&mut rng, bits.bits()).map_err(map_err)?;
            PrivateKey::new(KeypairData::from(pair), comment).map_err(map_err)?
        }
        GenerateSpec::Ecdsa { curve } => {
            let curve = match curve {
                EcdsaCurveChoice::P256 => ssh_key::EcdsaCurve::NistP256,
                EcdsaCurveChoice::P384 => ssh_key::EcdsaCurve::NistP384,
                EcdsaCurveChoice::P521 => ssh_key::EcdsaCurve::NistP521,
            };
            let pair = EcdsaKeypair::random(&mut rng, curve).map_err(map_err)?;
            PrivateKey::new(KeypairData::from(pair), comment).map_err(map_err)?
        }
    };
    if !comment.is_empty() {
        private_key.set_comment(comment);
    }

    finalize(label, private_key)
}

/// Re-encode an OpenSSH private PEM with a passphrase (OpenSSH's own
/// aes256-ctr + bcrypt KDF), for the "export private key" action. The
/// vault stores keys passphrase-free (the master key protects them);
/// the passphrase exists only on the exported copy.
pub fn encrypt_private_pem(pem: &str, passphrase: &str) -> Result<String, VaultError> {
    let key = PrivateKey::from_openssh(pem)
        .map_err(|e| VaultError::Crypto(format!("Failed to parse private key: {}", e)))?;
    let mut rng = rand::rng();
    let encrypted = key
        .encrypt(&mut rng, passphrase)
        .map_err(|e| VaultError::Crypto(format!("Key encryption failed: {}", e)))?;
    Ok(encrypted
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| VaultError::Crypto(format!("Private key encoding failed: {}", e)))?
        .to_string())
}

/// Cheap structural check: returns `true` if the key file looks
/// encrypted. Used by the UI to surface the passphrase field as soon
/// as the user picks the file, without waiting for a Save click.
/// Conservative, false negatives are fine (Save will still surface
/// `KeyNeedsPassphrase`); false positives would prompt unnecessarily.
pub fn is_key_encrypted(private_pem: &str) -> bool {
    let stripped = private_pem.strip_prefix('\u{FEFF}').unwrap_or(private_pem);
    let normalized = stripped.replace("\r\n", "\n").replace('\r', "\n");
    let trimmed = normalized.trim();

    if ppk::is_ppk(trimmed) {
        return ppk::is_encrypted(trimmed);
    }

    if is_traditional_encrypted(trimmed) {
        return true;
    }

    // OpenSSH format, parse cheaply just to read the cipher field.
    if trimmed.contains("BEGIN OPENSSH PRIVATE KEY")
        && let Ok(parsed) = ssh_key::PrivateKey::from_openssh(trimmed) {
            return parsed.is_encrypted();
        }
    false
}

/// Import an SSH key from any supported format:
/// - OpenSSH (`BEGIN OPENSSH PRIVATE KEY`), supports passphrase-encrypted keys
/// - PuTTY PPK v2 / v3 (`PuTTY-User-Key-File-2/3:`), supports passphrase-encrypted keys
/// - PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`)
/// - PKCS#8 (`BEGIN PRIVATE KEY`), RSA, ECDSA P-256/P-384/P-521, Ed25519
/// - Encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`), RSA, ECDSA P-256/P-384/P-521
/// - SEC1 EC (`BEGIN EC PRIVATE KEY`), P-256, P-384, P-521
/// - OpenSSL-legacy traditional PEM (`Proc-Type: 4,ENCRYPTED` + `DEK-Info`),
///   PKCS#1 RSA and SEC1 EC, decrypted with EVP_BytesToKey + AES/3DES-CBC
///
/// `passphrase` is consulted only when the key is detected as encrypted.
/// Returns `KeyNeedsPassphrase` if the key is encrypted and `passphrase` is
/// `None`/empty, or `WrongKeyPassphrase` if decryption fails. The decrypted
/// key is stored unencrypted (the vault's master key already protects it).
pub fn import_key(
    label: &str,
    private_pem: &str,
    passphrase: Option<&str>,
) -> Result<GeneratedKey, VaultError> {
    // Strip a UTF-8 BOM if present, Windows editors (Notepad, some
    // PowerShell redirects) write keys with a BOM and PEM parsers see
    // the leading bytes as junk before `-----BEGIN`. Then normalize
    // line endings (CRLF → LF) so Base64 decoding doesn't trip on \r.
    let stripped = private_pem.strip_prefix('\u{FEFF}').unwrap_or(private_pem);
    let normalized = stripped.replace("\r\n", "\n").replace('\r', "\n");
    let trimmed = normalized.trim();

    let private_key = if ppk::is_ppk(trimmed) {
        ppk::parse(trimmed, passphrase)?
    } else if trimmed.contains("BEGIN OPENSSH PRIVATE KEY") {
        // Try the input as-is first (preserves OpenSSH's native 70-char
        // wrapping). If that fails with a Base64 error, retry after
        // rewrapping at 64 chars: PuTTYgen's "Export OpenSSH key (force
        // new file format)" emits a 76-char body that `ssh-key`'s PEM
        // decoder rejects with a misleading "invalid Base64 encoding".
        let parsed = match PrivateKey::from_openssh(trimmed) {
            Ok(k) => k,
            Err(first_err) => {
                let rewrapped = pem::rewrap_pem_body_at(trimmed, 70);
                PrivateKey::from_openssh(&rewrapped).map_err(|_| {
                    VaultError::Crypto(format!("Failed to parse OpenSSH key: {}", first_err))
                })?
            }
        };
        if parsed.is_encrypted() {
            let pass = passphrase.unwrap_or("");
            if pass.is_empty() {
                return Err(VaultError::KeyNeedsPassphrase);
            }
            parsed
                .decrypt(pass.as_bytes())
                .map_err(|_| VaultError::WrongKeyPassphrase)?
        } else {
            parsed
        }
    } else {
        pem::parse(trimmed, passphrase)?
    };

    finalize(label, private_key)
}

/// Map an `ssh_key::PrivateKey` to the `KeyAlgorithm` enum and an
/// OpenSSH-encoded PEM, then build the resulting `GeneratedKey`.
/// Returns an error for algorithms we don't claim to support, rather
/// than silently mislabeling them.
///
/// Security keys take this path too, and that is deliberate. An
/// `id_ed25519_sk` / `id_ecdsa_sk` file is an OpenSSH PRIVATE key file
/// whose body is not a private scalar but a FIDO2 credential handle plus
/// the application string and flags; the scalar never leaves the token.
/// Storing it is what lets the app sign natively, but it is not software
/// key material, so the row stays out of the agent (see `expose_via_agent`
/// below) and every consumer that assumes a scalar must keep off it.
fn finalize(label: &str, private_key: PrivateKey) -> Result<GeneratedKey, VaultError> {
    let public_key = private_key.public_key();
    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
    let public_key_str = public_key.to_openssh()
        .map_err(|e| VaultError::Crypto(format!("Public key encoding failed: {}", e)))?;

    let algorithm = match private_key.algorithm() {
        Algorithm::Ed25519 => KeyAlgorithm::Ed25519,
        // Label RSA by its real modulus size; odd sizes fall back to
        // the 4096 bucket (also keeps every stored "rsa4096" row and
        // sync/export payload valid, the variants are additive).
        Algorithm::Rsa { .. } => match &private_key.key_data() {
            ssh_key::private::KeypairData::Rsa(pair) => match pair.key_size() {
                0..=2560 => KeyAlgorithm::Rsa2048,
                2561..=3584 => KeyAlgorithm::Rsa3072,
                _ => KeyAlgorithm::Rsa4096,
            },
            _ => KeyAlgorithm::Rsa4096,
        },
        Algorithm::Ecdsa { curve } => match curve {
            ssh_key::EcdsaCurve::NistP256 => KeyAlgorithm::EcdsaP256,
            ssh_key::EcdsaCurve::NistP384 => KeyAlgorithm::EcdsaP384,
            ssh_key::EcdsaCurve::NistP521 => KeyAlgorithm::EcdsaP521,
        },
        Algorithm::SkEd25519 => KeyAlgorithm::SkEd25519,
        Algorithm::SkEcdsaSha2NistP256 => KeyAlgorithm::SkEcdsaP256,
        other => {
            return Err(VaultError::UnsupportedKeyKind(other.as_str().to_string()));
        }
    };

    let private_pem = private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| VaultError::Crypto(format!("Private key encoding failed: {}", e)))?
        .to_string();

    let mut key = SshKey::new(label, algorithm);
    key.fingerprint = fingerprint;
    key.public_key = public_key_str;
    // A security-key row is stored here so the app can drive the token
    // itself, but our ssh-agent cannot: `sign` would have to hand a
    // credential handle to a software signer. Leave it out of the
    // agent's offering, and the user can still enable it by hand if a
    // future agent learns the CTAP2 path.
    if key.algorithm.is_security_key() {
        key.expose_via_agent = false;
    }

    Ok(GeneratedKey { key, private_pem })
}

/// Map an `ssh_key::Algorithm` to the vault's `KeyAlgorithm`, covering
/// the security-key families (B3) alongside the four private-importable
/// ones. RSA size cannot be told from the algorithm name alone, so
/// public-only RSA imports land in the 4096 bucket (display-only; the
/// blob is stored verbatim).
fn map_public_algorithm(algorithm: &Algorithm) -> Result<KeyAlgorithm, VaultError> {
    Ok(match algorithm {
        Algorithm::Ed25519 => KeyAlgorithm::Ed25519,
        Algorithm::Rsa { .. } => KeyAlgorithm::Rsa4096,
        Algorithm::Ecdsa { curve } => match curve {
            ssh_key::EcdsaCurve::NistP256 => KeyAlgorithm::EcdsaP256,
            ssh_key::EcdsaCurve::NistP384 => KeyAlgorithm::EcdsaP384,
            ssh_key::EcdsaCurve::NistP521 => KeyAlgorithm::EcdsaP521,
        },
        Algorithm::SkEd25519 => KeyAlgorithm::SkEd25519,
        Algorithm::SkEcdsaSha2NistP256 => KeyAlgorithm::SkEcdsaP256,
        other => {
            return Err(VaultError::UnsupportedKeyKind(other.as_str().to_string()));
        }
    })
}

/// Import a public-only key from an OpenSSH public line (B3): the entry
/// point for FIDO2 security keys (`sk-ssh-ed25519@openssh.com` /
/// `sk-ecdsa-sha2-nistp256@openssh.com`), whose private half is a handle
/// living on the authenticator, and for any other bare `.pub` line. A
/// certificate line is accepted too: the underlying public key is
/// derived from it and the full line lands in `SshKey.certificate` (the
/// B2 column), so an sk- cert identity round-trips in one paste.
///
/// The returned model carries NO private material by construction; the
/// caller persists it with `save_key(&key, Some(""))` (explicit NULL).
/// Private input is not accepted here at all: a `BEGIN` block fails the
/// public-line parse, and the UI routes it to the private import first.
pub fn import_public_key(label: &str, line: &str) -> Result<SshKey, VaultError> {
    let trimmed = line.strip_prefix('\u{FEFF}').unwrap_or(line).trim();

    // Certificate public line: derive the bare key, keep the cert.
    if let Ok(cert) = ssh_key::Certificate::from_openssh(trimmed) {
        let public = ssh_key::PublicKey::new(cert.public_key().clone(), cert.comment());
        let algorithm = map_public_algorithm(&public.algorithm())?;
        let mut key = SshKey::new(label, algorithm);
        key.fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
        key.public_key = public
            .to_openssh()
            .map_err(|e| VaultError::Crypto(format!("Public key encoding failed: {}", e)))?;
        key.certificate = Some(trimmed.to_string());
        return Ok(key);
    }

    let public = ssh_key::PublicKey::from_openssh(trimmed)
        .map_err(|e| VaultError::Crypto(format!("Not an OpenSSH public key line: {}", e)))?;
    let algorithm = map_public_algorithm(&public.algorithm())?;
    let mut key = SshKey::new(label, algorithm);
    key.fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    key.public_key = trimmed.to_string();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ed25519_produces_valid_key() {
        let result = generate_ed25519("test-key").unwrap();
        assert_eq!(result.key.label, "test-key");
        assert_eq!(result.key.algorithm, KeyAlgorithm::Ed25519);
        assert!(!result.key.fingerprint.is_empty());
        assert!(result.key.public_key.starts_with("ssh-ed25519 "));
        assert!(result.private_pem.contains("BEGIN OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn generate_ed25519_unique_keys() {
        let a = generate_ed25519("key-a").unwrap();
        let b = generate_ed25519("key-b").unwrap();
        assert_ne!(a.key.fingerprint, b.key.fingerprint);
        assert_ne!(a.private_pem, b.private_pem);
    }

    #[test]
    fn import_roundtrip() {
        let generated = generate_ed25519("original").unwrap();
        let imported = import_key("imported", &generated.private_pem, None).unwrap();
        assert_eq!(imported.key.fingerprint, generated.key.fingerprint);
        assert_eq!(imported.key.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(imported.key.public_key, generated.key.public_key);
    }

    #[test]
    fn import_invalid_pem_fails() {
        let result = import_key("bad", "this is not a key", None);
        assert!(result.is_err());
    }

    // Public security-key fixtures from the ssh-key crate's test suite
    // (public material only, nothing secret).
    const SK_ED25519_PUB: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAICFo/k5LU8863u66YC9eUO2170QduohPURkQnbLa/dczAAAABHNzaDo= user@example.com";
    const SK_ECDSA_P256_PUB: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBIELQJ2DgvaX1yQlKFokfWM2suuaCFI2qp0eJodHyg6O4ifxc3XpRKd1OS8dNYQtE/YjdXSrA+AOnMF5ns2Nkx4AAAAEc3NoOg== user@example.com";
    const SK_ED25519_CERT: &str = "sk-ssh-ed25519-cert-v01@openssh.com AAAAI3NrLXNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIG/VTdX1zj24l7+wPGYDN/QPXBDyBjGwUj7wTk1vgC9iAAAAICFo/k5LU8863u66YC9eUO2170QduohPURkQnbLa/dczAAAABHNzaDoAAAAAAAAAAAAAAAEAAAAKc2stZWQyNTUxOQAAAAAAAAAAYk3NxAAAAAD01mbEAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgsz6u836i33yqAQ3v3qNOJB9l8bUppPQ+0UMn9cVKq2IAAABTAAAAC3NzaC1lZDI1NTE5AAAAQFnv46uyvpzZFXBXGRkGEgp/HsMM4iYexEfU+rHJFi25s4RfVktxwJptE6QaUzm5TcZW9pyP8+DHkJp20QItuwg= user@example.com";

    #[test]
    fn import_public_sk_ed25519() {
        let key = import_public_key("yubi", SK_ED25519_PUB).unwrap();
        assert_eq!(key.algorithm, KeyAlgorithm::SkEd25519);
        assert!(key.algorithm.is_security_key());
        assert_eq!(key.public_key, SK_ED25519_PUB);
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert_eq!(key.certificate, None);
        // Fingerprint is stable across imports.
        let again = import_public_key("yubi2", SK_ED25519_PUB).unwrap();
        assert_eq!(again.fingerprint, key.fingerprint);
    }

    #[test]
    fn import_public_sk_ecdsa_p256() {
        let key = import_public_key("yubi-ec", SK_ECDSA_P256_PUB).unwrap();
        assert_eq!(key.algorithm, KeyAlgorithm::SkEcdsaP256);
        assert_eq!(key.public_key, SK_ECDSA_P256_PUB);
    }

    #[test]
    fn import_public_sk_certificate_line_keeps_cert_and_derives_key() {
        let key = import_public_key("yubi-cert", SK_ED25519_CERT).unwrap();
        assert_eq!(key.algorithm, KeyAlgorithm::SkEd25519);
        assert_eq!(key.certificate.as_deref(), Some(SK_ED25519_CERT));
        // The derived public line is the bare sk- key, not the cert.
        assert!(key.public_key.starts_with("sk-ssh-ed25519@openssh.com "));
    }

    #[test]
    fn import_public_plain_key_maps_family() {
        let generated = generate_ed25519("plain").unwrap();
        let key = import_public_key("plain-pub", &generated.key.public_key).unwrap();
        assert_eq!(key.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(key.fingerprint, generated.key.fingerprint);
    }

    // -----------------------------------------------------------------------
    // Security-key handles (native FIDO2)
    // -----------------------------------------------------------------------

    /// The flags `ssh-keygen -O` can set, mirrored from `sk-api.h` so the
    /// assertions below read as protocol rather than magic numbers.
    const SK_USER_PRESENCE: u8 = 0x01;
    const SK_RESIDENT: u8 = 0x20;

    /// Encode an `id_ed25519_sk` file the way `ssh-keygen -t ed25519-sk`
    /// does. The body is a credential handle plus the application string
    /// and flags, with no Ed25519 scalar in it at all, which is the whole
    /// point of the format and why this "private key import" must not be
    /// treated as software key material.
    fn sk_ed25519_private(public: [u8; 32], flags: u8, handle: &[u8]) -> String {
        use ssh_key::private::{KeypairData, SkEd25519};
        use ssh_key::public::{Ed25519PublicKey, SkEd25519 as SkEd25519Public};

        let public = SkEd25519Public::new(Ed25519PublicKey(public), "ssh:");
        let keypair = SkEd25519::new(public, flags, handle.to_vec())
            .expect("handle fits the file's one-byte length");
        PrivateKey::new(KeypairData::SkEd25519(keypair), "user@example.com")
            .expect("not encrypted")
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("encodes")
            .to_string()
    }

    /// Importing an `id_ed25519_sk` file must keep the credential handle
    /// byte for byte: that text is the only thing that can drive the token
    /// later, and it is what distinguishes "native FIDO2" from "we kept
    /// the public half and hoped an external agent was running".
    #[test]
    fn import_security_key_keeps_the_credential_handle() {
        let handle = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let pem = sk_ed25519_private([7u8; 32], SK_USER_PRESENCE, &handle);

        let imported = import_key("yubi", &pem, None).unwrap();
        assert_eq!(imported.key.algorithm, KeyAlgorithm::SkEd25519);
        assert!(imported.key.algorithm.is_security_key());
        assert!(
            imported.key.public_key.starts_with("sk-ssh-ed25519@openssh.com "),
            "{}",
            imported.key.public_key
        );
        assert!(imported.key.fingerprint.starts_with("SHA256:"));

        let reparsed = PrivateKey::from_openssh(&imported.private_pem).unwrap();
        assert_eq!(reparsed.algorithm(), Algorithm::SkEd25519);
        let sk = reparsed
            .key_data()
            .sk_ed25519()
            .expect("the stored text is still a security-key handle");
        assert_eq!(sk.key_handle(), handle);
        assert_eq!(sk.flags(), SK_USER_PRESENCE);
        assert_eq!(sk.public().application(), "ssh:");
        // The public line we stored describes exactly the stored handle's
        // public half, so a fingerprint match on the server is meaningful.
        assert_eq!(
            reparsed.public_key().fingerprint(HashAlg::Sha256).to_string(),
            imported.key.fingerprint
        );
    }

    /// A resident (discoverable) credential has an empty handle; the
    /// import must not confuse that with "no key material" and must keep
    /// the resident flag, since that decides whether an allow-list is sent.
    #[test]
    fn import_security_key_keeps_a_resident_credential_flag() {
        let pem = sk_ed25519_private([9u8; 32], SK_USER_PRESENCE | SK_RESIDENT, &[]);
        let imported = import_key("resident", &pem, None).unwrap();
        assert_eq!(imported.key.algorithm, KeyAlgorithm::SkEd25519);

        let reparsed = PrivateKey::from_openssh(&imported.private_pem).unwrap();
        let sk = reparsed.key_data().sk_ed25519().unwrap();
        assert!(sk.key_handle().is_empty());
        assert_eq!(sk.flags() & SK_RESIDENT, SK_RESIDENT);
    }

    /// A security key is stored so the app can drive the token itself, but
    /// our ssh-agent cannot sign for one: it would have to feed a
    /// credential handle to a software signer. The row must therefore
    /// arrive with the agent switch off, or the agent would advertise an
    /// identity it can never complete a signature for.
    #[test]
    fn import_security_key_is_not_offered_to_the_agent() {
        let pem = sk_ed25519_private([1u8; 32], SK_USER_PRESENCE, &[1, 2, 3]);
        let imported = import_key("yubi", &pem, None).unwrap();
        assert!(!imported.key.expose_via_agent);
    }

    /// `sk-ecdsa-sha2-nistp256` is the other security-key family, and it
    /// imports the same way: labelled as what it is, handle kept.
    #[test]
    fn import_security_key_maps_the_ecdsa_family() {
        use ssh_key::private::{KeypairData, SkEcdsaSha2NistP256};

        let public = ssh_key::PublicKey::from_openssh(SK_ECDSA_P256_PUB).unwrap();
        let sk_public = public.key_data().sk_ecdsa_p256().unwrap().clone();
        let keypair = SkEcdsaSha2NistP256::new(sk_public, SK_USER_PRESENCE, vec![4, 5, 6])
            .expect("handle fits");
        let pem = PrivateKey::new(
            KeypairData::SkEcdsaSha2NistP256(keypair),
            "user@example.com",
        )
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();

        let imported = import_key("yubi-ec", &pem, None).unwrap();
        assert_eq!(imported.key.algorithm, KeyAlgorithm::SkEcdsaP256);
        assert!(imported.key.algorithm.is_security_key());
        assert!(!imported.key.expose_via_agent);
        // Same key as the public-line import of the same fixture.
        let from_public = import_public_key("yubi-ec-pub", SK_ECDSA_P256_PUB).unwrap();
        assert_eq!(imported.key.fingerprint, from_public.fingerprint);
    }

    /// A plain Ed25519 private key must not be mistaken for a security
    /// key: it goes through the same `finalize`, and the agent switch
    /// must stay on for it.
    #[test]
    fn a_plain_key_is_still_offered_to_the_agent() {
        let generated = generate_ed25519("plain").unwrap();
        assert!(generated.key.expose_via_agent);
        assert!(!generated.key.algorithm.is_security_key());
    }

    #[test]
    fn import_public_rejects_private_material_and_garbage() {
        let generated = generate_ed25519("priv").unwrap();
        // A private block never parses as a public line; the UI routes it
        // to the private import, but the entry point must refuse it too.
        assert!(import_public_key("bad", &generated.private_pem).is_err());
        assert!(import_public_key("bad", "not a key at all").is_err());
    }

    #[test]
    fn import_encrypted_openssh_round_trips_with_passphrase() {
        // Build an encrypted OpenSSH key in-process (no embedded secret, no
        // external `ssh-keygen`): generate one, then encrypt it. Guards the
        // passphrase path the host-key import UI depends on.
        let src = generate_ed25519("enc-src").unwrap();
        let key = PrivateKey::from_openssh(&src.private_pem).unwrap();
        let mut rng = rand::rng();
        let enc_pem = key
            .encrypt(&mut rng, "pw123")
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();

        // No passphrase: the UI is told to prompt for one.
        assert!(matches!(
            import_key("k", &enc_pem, None),
            Err(VaultError::KeyNeedsPassphrase)
        ));
        // Wrong passphrase: a distinct, surfaceable error.
        assert!(matches!(
            import_key("k", &enc_pem, Some("nope")),
            Err(VaultError::WrongKeyPassphrase)
        ));
        // Correct passphrase: imported, same key.
        let imported = import_key("k", &enc_pem, Some("pw123")).unwrap();
        assert_eq!(imported.key.fingerprint, src.key.fingerprint);
    }

    #[test]
    fn import_strips_utf8_bom() {
        let generated = generate_ed25519("bom-test").unwrap();
        let with_bom = format!("\u{FEFF}{}", generated.private_pem);
        let imported = import_key("bom", &with_bom, None).unwrap();
        assert_eq!(imported.key.fingerprint, generated.key.fingerprint);
    }

    #[test]
    fn import_handles_crlf() {
        let generated = generate_ed25519("crlf-test").unwrap();
        let crlf = generated.private_pem.replace('\n', "\r\n");
        let imported = import_key("crlf", &crlf, None).unwrap();
        assert_eq!(imported.key.fingerprint, generated.key.fingerprint);
    }

    #[test]
    fn import_with_whitespace() {
        let generated = generate_ed25519("ws-test").unwrap();
        let padded = format!("\n  {}  \n", generated.private_pem);
        let imported = import_key("trimmed", &padded, None).unwrap();
        assert_eq!(imported.key.fingerprint, generated.key.fingerprint);
    }

    #[test]
    fn import_openssh_with_76_char_lines() {
        // Mimic PuTTYgen's "Export OpenSSH key (force new file format)"
        // output: same base64 body, but wrapped at 76 chars instead of
        // RFC 7468's 64. Used to fail with "invalid Base64 encoding".
        let generated = generate_ed25519("force-new-format").unwrap();
        let begin = generated.private_pem.find('\n').unwrap() + 1;
        let end_tag = "-----END";
        let end = generated.private_pem.find(end_tag).unwrap();
        let body: String = generated.private_pem[begin..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut rewrapped = String::new();
        rewrapped.push_str(&generated.private_pem[..begin]);
        for chunk in body.as_bytes().chunks(76) {
            rewrapped.push_str(std::str::from_utf8(chunk).unwrap());
            rewrapped.push('\n');
        }
        rewrapped.push_str(&generated.private_pem[end..]);

        let imported = import_key("force-new-format", &rewrapped, None).unwrap();
        assert_eq!(imported.key.fingerprint, generated.key.fingerprint);
    }

    /// Every spec the generate UI offers: generated key reimports with
    /// a matching fingerprint, carries the right algorithm label, the
    /// public line starts with the right type, and a sign/verify
    /// roundtrip works. RSA sizes are verified from the parsed key.
    #[test]
    fn generate_key_all_specs_roundtrip_and_sign() {
        use ssh_key::private::KeypairData;
        // The `signature` traits reach us re-exported through `rsa`
        // (already in the tree via ssh-key); no new dependency.
        use rsa::signature::{Signer, Verifier};

        let cases: [(GenerateSpec, KeyAlgorithm, &str); 7] = [
            (GenerateSpec::Ed25519, KeyAlgorithm::Ed25519, "ssh-ed25519 "),
            (GenerateSpec::Rsa { bits: RsaBits::B2048 }, KeyAlgorithm::Rsa2048, "ssh-rsa "),
            (GenerateSpec::Rsa { bits: RsaBits::B3072 }, KeyAlgorithm::Rsa3072, "ssh-rsa "),
            (GenerateSpec::Rsa { bits: RsaBits::B4096 }, KeyAlgorithm::Rsa4096, "ssh-rsa "),
            (
                GenerateSpec::Ecdsa { curve: EcdsaCurveChoice::P256 },
                KeyAlgorithm::EcdsaP256,
                "ecdsa-sha2-nistp256 ",
            ),
            (
                GenerateSpec::Ecdsa { curve: EcdsaCurveChoice::P384 },
                KeyAlgorithm::EcdsaP384,
                "ecdsa-sha2-nistp384 ",
            ),
            (
                GenerateSpec::Ecdsa { curve: EcdsaCurveChoice::P521 },
                KeyAlgorithm::EcdsaP521,
                "ecdsa-sha2-nistp521 ",
            ),
        ];

        for (spec, algo, prefix) in cases {
            let generated = generate_key("gen", "user@oryxis", spec).unwrap();
            assert_eq!(generated.key.algorithm, algo, "{spec:?}");
            assert!(
                generated.key.public_key.starts_with(prefix),
                "{spec:?}: {}",
                generated.key.public_key
            );
            // Comment lands in the public line.
            assert!(
                generated.key.public_key.trim_end().ends_with("user@oryxis"),
                "{spec:?}: comment missing"
            );

            let imported = import_key("re", &generated.private_pem, None).unwrap();
            assert_eq!(imported.key.fingerprint, generated.key.fingerprint, "{spec:?}");
            assert_eq!(imported.key.algorithm, algo, "{spec:?}");

            let parsed = PrivateKey::from_openssh(&generated.private_pem).unwrap();
            if let GenerateSpec::Rsa { bits } = spec {
                let KeypairData::Rsa(pair) = parsed.key_data() else {
                    panic!("{spec:?}: not RSA");
                };
                assert_eq!(pair.key_size() as usize, bits.bits(), "{spec:?}");
            }

            // Sign/verify through ssh_key's signature traits.
            let msg = b"oryxis keygen sign test";
            let signature: ssh_key::Signature =
                Signer::try_sign(&parsed, msg).expect("sign");
            Verifier::verify(parsed.public_key(), msg, &signature).expect("verify");
        }
    }

    #[test]
    fn export_pem_encrypts_with_passphrase() {
        let generated = generate_ed25519("exp").unwrap();
        let enc = encrypt_private_pem(&generated.private_pem, "hunter2").unwrap();
        assert!(enc.contains("BEGIN OPENSSH PRIVATE KEY"));
        // The exported copy demands the passphrase; the right one
        // yields the same key.
        assert!(matches!(
            import_key("k", &enc, None),
            Err(VaultError::KeyNeedsPassphrase)
        ));
        let back = import_key("k", &enc, Some("hunter2")).unwrap();
        assert_eq!(back.key.fingerprint, generated.key.fingerprint);
    }

    /// Legacy DB rows labeled "rsa4096" must keep loading, and an
    /// imported 2048-bit key now gets the honest label.
    #[test]
    fn rsa_import_is_labeled_by_real_size() {
        let generated =
            generate_key("r2", "", GenerateSpec::Rsa { bits: RsaBits::B2048 }).unwrap();
        let imported = import_key("r2", &generated.private_pem, None).unwrap();
        assert_eq!(imported.key.algorithm, KeyAlgorithm::Rsa2048);
    }

    #[test]
    fn import_encrypted_openssh_requires_passphrase() {
        use ssh_key::{Algorithm, PrivateKey};
        let mut rng = rand::rng();
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let encrypted = key.encrypt(&mut rng, b"hunter2").unwrap();
        let pem = encrypted.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();

        let err = import_key("enc", &pem, None).unwrap_err();
        assert!(matches!(err, VaultError::KeyNeedsPassphrase));

        let err = import_key("enc", &pem, Some("")).unwrap_err();
        assert!(matches!(err, VaultError::KeyNeedsPassphrase));

        let err = import_key("enc", &pem, Some("nope")).unwrap_err();
        assert!(matches!(err, VaultError::WrongKeyPassphrase));

        let imported = import_key("enc", &pem, Some("hunter2")).unwrap();
        assert!(imported.private_pem.contains("BEGIN OPENSSH PRIVATE KEY"));
        let reparsed = PrivateKey::from_openssh(&imported.private_pem).unwrap();
        assert!(!reparsed.is_encrypted());
    }
}
