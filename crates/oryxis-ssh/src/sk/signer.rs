//! The `russh` signer that hands the signing to the token.
//!
//! `russh` already has the hook for this: [`russh::Signer`], the trait
//! the ssh-agent path implements, called once per auth attempt with the
//! exact bytes OpenSSH would hash. Everything after that — the client
//! data hash, the CTAP2 round trip, the signature blob — is ours.
//!
//! The token call runs on a blocking task. A human staring at "touch your
//! key" is a multi-second wait, and doing it on the connection's own task
//! would stall the runtime thread driving the SSH transport.

use std::sync::Arc;

use russh::keys::HashAlg;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::PublicKey;

use super::SkError;
use super::authenticator::{AssertionRequest, SkAuthenticator};
use super::credential::SkCredential;
use super::signature;

/// Signs `sk-ssh-ed25519@openssh.com` userauth requests with a token.
pub struct SkSigner {
    credential: SkCredential,
    authenticator: Arc<dyn SkAuthenticator>,
    /// The PIN, when the key was made with `-O verify-required`. Phase 1
    /// carries it through to the authenticator, which refuses it with a
    /// named error rather than silently dropping it.
    pin: Option<String>,
}

impl SkSigner {
    pub fn new(credential: SkCredential, authenticator: Arc<dyn SkAuthenticator>) -> Self {
        Self {
            credential,
            authenticator,
            pin: None,
        }
    }

    /// Attach the PIN from the vault, if the user stored one.
    pub fn with_pin(mut self, pin: Option<String>) -> Self {
        self.pin = pin;
        self
    }

    /// The public key to offer the server.
    pub fn public_key(&self) -> &PublicKey {
        self.credential.public_key()
    }

    /// The parsed handle, for diagnostics.
    pub fn credential(&self) -> &SkCredential {
        &self.credential
    }
}

/// The whole signing path, without any of the async plumbing: build the
/// request, ask the token, encode the blob.
///
/// Split out from [`russh::Signer::auth_sign`] so it can be tested (and
/// reasoned about) without a runtime or an `AgentIdentity`, both of which
/// only exist to satisfy the trait.
fn sign_with(
    credential: &SkCredential,
    authenticator: &dyn SkAuthenticator,
    pin: Option<&str>,
    mut to_sign: Vec<u8>,
) -> Result<Vec<u8>, SkError> {
    let request = AssertionRequest {
        application: credential.application().to_string(),
        // OpenSSH hands us the userauth blob itself; each transport hashes
        // it its own way, so what travels here is the message.
        message: to_sign.clone(),
        // A resident credential has no handle; asking with an empty
        // allow-list is what makes the token search its own store.
        key_handle: (!credential.is_resident()).then(|| credential.key_handle().to_vec()),
        require_user_presence: credential.require_user_presence(),
        require_user_verification: credential.require_user_verification(),
        pin: pin.map(str::to_string),
    };
    let assertion = authenticator.get_assertion(&request)?;
    let signature = signature::encode_sk_ed25519_signature(
        &assertion.signature,
        assertion.flags,
        assertion.counter,
    )?;

    // `russh::Signer` follows the ssh-agent contract: the return value is
    // the original userauth data with one SSH `string` signature appended,
    // not the signature blob by itself. `russh` later strips the session-id
    // prefix and writes the remaining packet. Returning only `signature`
    // makes it slice that blob at the old prefix offset, producing a
    // malformed USERAUTH_REQUEST after the token was touched successfully.
    to_sign.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    to_sign.extend_from_slice(&signature);
    Ok(to_sign)
}

impl russh::Signer for SkSigner {
    type Error = SkError;

    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        // Everything the blocking task needs, owned: the credential is
        // small and the token call must not borrow the connection.
        let credential = self.credential.clone();
        let authenticator = Arc::clone(&self.authenticator);
        let pin = self.pin.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                sign_with(&credential, authenticator.as_ref(), pin.as_deref(), to_sign)
            })
            .await
            .map_err(|e| SkError::Internal(format!("security-key signing task failed: {e}")))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sk::authenticator::Assertion;
    use crate::sk::credential::fixture;
    use crate::sk::signature::signing_input;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

    /// A software stand-in for a FIDO2 token: it holds the Ed25519
    /// private half and answers exactly the way a real token does,
    /// signing `SHA256(application) || flags || counter || clientDataHash`.
    ///
    /// This is what makes the wire format testable without hardware — and
    /// the verification below is OpenSSH's own reconstruction, so a
    /// mismatch in any field fails here rather than at a customer's
    /// server.
    struct SoftToken {
        signing_key: SigningKey,
        handle: Vec<u8>,
        counter: u32,
        /// What the test asserts the request must carry.
        expected_application: String,
        expected_message: Vec<u8>,
    }

    impl SkAuthenticator for SoftToken {
        fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, SkError> {
            assert_eq!(request.application, self.expected_application);
            assert_eq!(request.message, self.expected_message);
            assert_eq!(request.key_handle.as_deref(), Some(self.handle.as_slice()));
            assert!(request.require_user_presence);
            assert!(!request.require_user_verification);
            assert!(request.pin.is_none());

            let flags = 0x01; // user present
            let input = signing_input(
                &request.application,
                flags,
                self.counter,
                &signature::sha256(&request.message),
            );
            Ok(Assertion {
                signature: self.signing_key.sign(&input).to_bytes().to_vec(),
                flags,
                counter: self.counter,
            })
        }
    }

    /// The whole point of the module: a blob the token produced verifies
    /// against the public key we offered, under OpenSSH's reconstruction.
    #[test]
    fn the_token_signature_verifies_like_openssh_verifies_it() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing_key.verifying_key().to_bytes();
        let handle = vec![0x11, 0x22, 0x33, 0x44];
        let text = fixture::sk_private_key(public, fixture::USER_PRESENCE, &handle);
        let credential = SkCredential::from_openssh_private(&text).unwrap();

        // `to_sign` is whatever russh hands us; a realistic shape is
        // session_id + userauth request, but any bytes exercise the path.
        let to_sign = b"session-id + ssh-userauth publickey request".to_vec();
        let token = SoftToken {
            signing_key: signing_key.clone(),
            handle: handle.clone(),
            counter: 12,
            expected_application: "ssh:".to_string(),
            expected_message: to_sign.clone(),
        };

        let signed = sign_with(&credential, &token, None, to_sign.clone()).unwrap();

        // The external-signer contract preserves every byte russh asked us
        // to sign and appends one length-prefixed signature field.
        assert_eq!(&signed[..to_sign.len()], to_sign.as_slice());
        let (blob, rest) = read_string(&signed[to_sign.len()..]);
        assert!(rest.is_empty(), "exactly one signature field is appended");

        // Parse the blob the way OpenSSH does: algorithm, signature,
        // flags, counter.
        let (algorithm, rest) = read_string(blob);
        assert_eq!(algorithm, signature::SK_ED25519.as_bytes());
        let (signature, rest) = read_string(rest);
        assert_eq!(signature.len(), 64);
        let flags = rest[0];
        let counter = u32::from_be_bytes(rest[1..5].try_into().unwrap());
        assert_eq!(flags, 0x01);
        assert_eq!(counter, 12);
        assert_eq!(rest.len(), 5, "nothing may follow the counter");

        // And verify it the way OpenSSH does.
        let input = signing_input("ssh:", flags, counter, &signature::sha256(&to_sign));
        signing_key
            .verifying_key()
            .verify(
                &input,
                &ed25519_dalek::Signature::from_bytes(signature.try_into().unwrap()),
            )
            .expect("the token's signature must verify over OpenSSH's signed string");
    }

    /// A token that answers with something other than 64 bytes must be
    /// refused before it reaches the wire.
    #[test]
    fn a_short_signature_is_refused() {
        struct Truncating(SoftToken);
        impl SkAuthenticator for Truncating {
            fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, SkError> {
                let mut assertion = self.0.get_assertion(request)?;
                assertion.signature.truncate(32);
                Ok(assertion)
            }
        }

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let public = signing_key.verifying_key().to_bytes();
        let handle = vec![1u8, 2, 3];
        let text = fixture::sk_private_key(public, fixture::USER_PRESENCE, &handle);
        let credential = SkCredential::from_openssh_private(&text).unwrap();
        let to_sign = b"payload".to_vec();
        let token = Truncating(SoftToken {
            signing_key,
            handle,
            counter: 0,
            expected_application: "ssh:".to_string(),
            expected_message: to_sign.clone(),
        });

        let err = sign_with(&credential, &token, None, to_sign).unwrap_err();
        assert!(matches!(err, SkError::Malformed(_)), "got {err:?}");
    }

    /// A resident credential must be asked for without an allow-list.
    #[test]
    fn a_resident_credential_drops_the_allow_list() {
        struct ResidentCheck;
        impl SkAuthenticator for ResidentCheck {
            fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, SkError> {
                assert!(
                    request.key_handle.is_none(),
                    "a discoverable credential must not be addressed by handle"
                );
                Ok(Assertion {
                    signature: vec![0u8; 64],
                    flags: 0x01,
                    counter: 0,
                })
            }
        }

        let public = SigningKey::from_bytes(&[3u8; 32])
            .verifying_key()
            .to_bytes();
        let text = fixture::sk_private_key(public, fixture::USER_PRESENCE | fixture::RESIDENT, &[]);
        let credential = SkCredential::from_openssh_private(&text).unwrap();
        assert!(credential.is_resident());
        sign_with(&credential, &ResidentCheck, None, b"x".to_vec()).unwrap();
    }

    /// SSH `string` reader for the test's own blob parse.
    fn read_string(mut bytes: &[u8]) -> (&[u8], &[u8]) {
        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        bytes = &bytes[4..];
        bytes.split_at(len)
    }
}
