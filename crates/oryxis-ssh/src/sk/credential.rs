//! The handle half of an OpenSSH security-key private file.
//!
//! `ssh-keygen -t ed25519-sk` (or `ecdsa-sk`) writes two files: the
//! ordinary `.pub`, and a "private" file whose body is NOT a private key:
//! it is the FIDO2 credential handle the token finds the key by, plus the
//! application string and the flags the key was made with. The private
//! scalar never leaves the token, so what this file buys an attacker is
//! the ability to ask THIS token for a signature, which still takes the
//! token and a touch.

use russh::keys::ssh_key::{Algorithm, PrivateKey, PublicKey};

use super::SkError;

/// The application string OpenSSH scopes a security key to by default. It
/// is the FIDO2 relying-party id, and it is hashed into every signature.
pub const DEFAULT_APPLICATION: &str = "ssh:";

/// `SSH_SK_USER_PRESENCE_REQD` (OpenSSH `sk-api.h`): the token must see a
/// touch before it signs.
pub const FLAG_USER_PRESENCE_REQUIRED: u8 = 0x01;
/// `SSH_SK_USER_VERIFICATION_REQD`: the token must verify the user (PIN or
/// biometric) as well.
pub const FLAG_USER_VERIFICATION_REQUIRED: u8 = 0x04;
/// `SSH_SK_RESIDENT_KEY`: the credential is discoverable (stored on the
/// token). The file still carries the handle `ssh-keygen -K` read back.
pub const FLAG_RESIDENT_KEY: u8 = 0x20;

/// The two security-key families OpenSSH defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkAlgorithm {
    /// `sk-ssh-ed25519@openssh.com`
    Ed25519,
    /// `sk-ecdsa-sha2-nistp256@openssh.com`
    EcdsaP256,
}

/// What an OpenSSH security-key file tells us about asking a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkCredential {
    algorithm: SkAlgorithm,
    /// The public key, exactly as the vault stores it.
    public_key: PublicKey,
    /// The relying-party id ("ssh:" unless made with `-O application=`).
    application: String,
    /// The opaque handle the token finds the credential by.
    key_handle: Vec<u8>,
    /// The `sk_flags` byte from the file: what the REQUEST must ask the
    /// token for. The flags in the signature blob are the token's answer.
    flags: u8,
}

impl SkCredential {
    /// Parse an OpenSSH security-key private file.
    ///
    /// Takes the raw text, so the vault keeps the bytes the user imported
    /// and this stays the one place that knows the shape.
    pub fn from_openssh_private(text: &str) -> Result<Self, SkError> {
        // Same normalization `import_key` does: a BOM from a Windows
        // editor or CRLF from a text field must not become a parse error.
        let stripped = text.strip_prefix('\u{FEFF}').unwrap_or(text);
        let normalized = stripped.replace("\r\n", "\n").replace('\r', "\n");
        let private = PrivateKey::from_openssh(normalized.trim())
            .map_err(|e| SkError::NotASecurityKey(e.to_string()))?;

        if private.is_encrypted() {
            return Err(SkError::EncryptedHandle);
        }

        let (algorithm, application, key_handle, flags) = match private.algorithm() {
            Algorithm::SkEd25519 => {
                let sk = private.key_data().sk_ed25519().ok_or_else(|| {
                    SkError::NotASecurityKey("missing sk-ed25519 key data".into())
                })?;
                (
                    SkAlgorithm::Ed25519,
                    sk.public().application().to_string(),
                    sk.key_handle().to_vec(),
                    sk.flags(),
                )
            }
            Algorithm::SkEcdsaSha2NistP256 => {
                let sk = private.key_data().sk_ecdsa_p256().ok_or_else(|| {
                    SkError::NotASecurityKey("missing sk-ecdsa key data".into())
                })?;
                (
                    SkAlgorithm::EcdsaP256,
                    sk.public().application().to_string(),
                    sk.key_handle().to_vec(),
                    sk.flags(),
                )
            }
            other => {
                return Err(SkError::NotASecurityKey(format!(
                    "it is a {} key",
                    other.as_str()
                )));
            }
        };

        Ok(Self {
            algorithm,
            public_key: private.public_key().clone(),
            application,
            key_handle,
            flags,
        })
    }

    pub fn algorithm(&self) -> SkAlgorithm {
        self.algorithm
    }

    /// The public key, for offering to the server.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The relying-party id hashed into the signature.
    pub fn application(&self) -> &str {
        &self.application
    }

    /// The credential handle. Empty only for a hand-made file.
    pub fn key_handle(&self) -> &[u8] {
        &self.key_handle
    }

    /// Whether the credential is discoverable (stored on the token).
    pub fn is_resident(&self) -> bool {
        self.flags & FLAG_RESIDENT_KEY != 0
    }

    /// Whether the key was made with `-O verify-required`.
    pub fn require_user_verification(&self) -> bool {
        self.flags & FLAG_USER_VERIFICATION_REQUIRED != 0
    }

    /// Whether the token must see a touch: every key `ssh-keygen` makes
    /// without `-O no-touch-required`. A key that asks for verification
    /// needs presence too, whatever the file's UP bit says.
    pub fn require_user_presence(&self) -> bool {
        self.flags & FLAG_USER_PRESENCE_REQUIRED != 0 || self.require_user_verification()
    }

    /// `SHA256:...`, the fingerprint the vault shows for the public half.
    pub fn fingerprint(&self) -> String {
        self.public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string()
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! A syntactically real `id_ed25519_sk` file around an arbitrary
    //! Ed25519 public key, so tests can pair a credential with a software
    //! "token" that actually holds the private half. Built through
    //! `ssh-key` rather than by hand: the container format is not what
    //! these tests are about.

    use russh::keys::ssh_key::LineEnding;
    use russh::keys::ssh_key::private::{KeypairData, SkEd25519 as SkPrivateKey};
    use russh::keys::ssh_key::public::{Ed25519PublicKey, SkEd25519 as SkPublicKey};

    pub(crate) use super::{
        FLAG_RESIDENT_KEY as RESIDENT, FLAG_USER_PRESENCE_REQUIRED as USER_PRESENCE,
    };

    /// Encode `id_ed25519_sk` text for `public`, with the given `flags`
    /// and credential `handle`.
    pub(crate) fn sk_private_key(public: [u8; 32], flags: u8, handle: &[u8]) -> String {
        let public_key = SkPublicKey::new(Ed25519PublicKey(public), super::DEFAULT_APPLICATION);
        let private_key = SkPrivateKey::new(public_key, flags, handle.to_vec())
            .expect("handle fits in the file's one-byte length");
        let key = russh::keys::ssh_key::PrivateKey::new(
            KeypairData::SkEd25519(private_key),
            "oryxis-test",
        )
        .expect("not encrypted");
        key.to_openssh(LineEnding::LF)
            .expect("encodes")
            .to_string()
    }

    /// Encode `id_ecdsa_sk` text for the SEC1 uncompressed `point`.
    pub(crate) fn sk_ecdsa_private_key(point: &[u8], flags: u8, handle: &[u8]) -> String {
        use russh::keys::ssh_key::private::SkEcdsaSha2NistP256 as SkPrivate;
        use russh::keys::ssh_key::public::{EcdsaPublicKey, SkEcdsaSha2NistP256 as SkPublic};

        let EcdsaPublicKey::NistP256(point) =
            EcdsaPublicKey::from_sec1_bytes(point).expect("a P-256 point")
        else {
            panic!("not P-256");
        };
        let public = SkPublic::new(point, super::DEFAULT_APPLICATION);
        let private = SkPrivate::new(public, flags, handle.to_vec()).expect("handle fits");
        russh::keys::ssh_key::PrivateKey::new(
            KeypairData::SkEcdsaSha2NistP256(private),
            "oryxis-test",
        )
        .expect("not encrypted")
        .to_openssh(LineEnding::LF)
        .expect("encodes")
        .to_string()
    }

    /// The Ed25519 public half from the ssh-key crate's own sk fixture.
    pub(crate) const FIXTURE_PUBLIC: [u8; 32] = [
        0x21, 0x68, 0xfe, 0x4e, 0x4b, 0x53, 0xcf, 0x3a, 0xde, 0xee, 0xba, 0x60, 0x2f, 0x5e, 0x50,
        0xed, 0xb5, 0xef, 0x44, 0x1d, 0xba, 0x88, 0x4f, 0x51, 0x19, 0x10, 0x9d, 0xb2, 0xda, 0xfd,
        0xd7, 0x33,
    ];
    pub(crate) const FIXTURE_HANDLE: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
}

#[cfg(test)]
mod tests {
    use super::fixture::{FIXTURE_HANDLE, FIXTURE_PUBLIC, RESIDENT, USER_PRESENCE, sk_private_key};
    use super::*;

    #[test]
    fn parses_handle_application_and_flags() {
        let credential =
            SkCredential::from_openssh_private(&sk_private_key(FIXTURE_PUBLIC, USER_PRESENCE, &FIXTURE_HANDLE))
                .unwrap();
        assert_eq!(credential.application(), DEFAULT_APPLICATION);
        assert_eq!(credential.key_handle(), &FIXTURE_HANDLE);
        assert!(credential.require_user_presence());
        assert!(!credential.require_user_verification());
        assert!(!credential.is_resident());
        assert_eq!(credential.algorithm(), SkAlgorithm::Ed25519);
        assert_eq!(credential.public_key().algorithm(), Algorithm::SkEd25519);
        assert!(credential.fingerprint().starts_with("SHA256:"));
    }

    /// `-O verify-required` sets the UV bit, and a UV key needs presence
    /// too even if the file were to omit the UP bit.
    #[test]
    fn verify_required_implies_user_presence() {
        let text = sk_private_key(
            FIXTURE_PUBLIC,
            FLAG_USER_VERIFICATION_REQUIRED,
            &FIXTURE_HANDLE,
        );
        let credential = SkCredential::from_openssh_private(&text).unwrap();
        assert!(credential.require_user_verification());
        assert!(credential.require_user_presence());
    }

    /// A resident key keeps its handle in the file `ssh-keygen -K` wrote,
    /// and the flag alone is what marks it discoverable.
    #[test]
    fn a_resident_credential_keeps_its_handle() {
        let text = sk_private_key(FIXTURE_PUBLIC, USER_PRESENCE | RESIDENT, &FIXTURE_HANDLE);
        let credential = SkCredential::from_openssh_private(&text).unwrap();
        assert!(credential.is_resident());
        assert_eq!(credential.key_handle(), &FIXTURE_HANDLE);
    }

    #[test]
    fn parses_an_ecdsa_security_key() {
        let point = p256::SecretKey::from_slice(&[5u8; 32])
            .unwrap()
            .public_key()
            .to_sec1_bytes();
        let text = super::fixture::sk_ecdsa_private_key(&point, USER_PRESENCE, &FIXTURE_HANDLE);
        let credential = SkCredential::from_openssh_private(&text).unwrap();
        assert_eq!(credential.algorithm(), SkAlgorithm::EcdsaP256);
        assert_eq!(
            credential.public_key().algorithm(),
            Algorithm::SkEcdsaSha2NistP256
        );
        assert_eq!(credential.key_handle(), &FIXTURE_HANDLE);
    }

    /// A CRLF copy through a text field must still parse: the vault hands
    /// this function whatever the user pasted.
    #[test]
    fn tolerates_crlf_and_a_bom() {
        let text = format!(
            "\u{FEFF}{}",
            sk_private_key(FIXTURE_PUBLIC, USER_PRESENCE, &FIXTURE_HANDLE)
        );
        let text = text.replace('\n', "\r\n");
        let credential = SkCredential::from_openssh_private(&text).unwrap();
        assert_eq!(credential.key_handle(), &FIXTURE_HANDLE);
    }

    #[test]
    fn rejects_something_that_is_not_a_key() {
        // A software key must never be routed into the hardware path.
        let err = SkCredential::from_openssh_private("not a key at all").unwrap_err();
        assert!(matches!(err, SkError::NotASecurityKey(_)));
    }
}
