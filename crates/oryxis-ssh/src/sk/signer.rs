//! The `russh` signer that hands the signing to the token.
//!
//! `russh` already has the hook: [`russh::Signer`], the trait the agent
//! path implements, called once per auth attempt with the exact bytes
//! OpenSSH would hash. The token call runs on a blocking task, because a
//! person reaching for a key is a multi-second wait and the connection's
//! own task drives the SSH transport.
//!
//! Dropping the future does not stop a blocking task, so each call carries
//! a [`CancelToken`] that a guard inside the future fires on drop. That is
//! what takes a Windows Hello dialog (or a HID wait) down when the dial it
//! belongs to is aborted: the connect card closed, the pane closed.

use std::sync::Arc;

use oryxis_fido2::{AssertionRequest, Authenticator, CancelToken, Interaction};
use russh::keys::HashAlg;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::PublicKey;

use super::SkError;
use super::credential::SkCredential;
use super::signature;

/// Signs security-key userauth requests with a token.
pub struct SkSigner {
    credential: SkCredential,
    authenticator: Arc<dyn Authenticator>,
    /// Events and the PIN source; the cancel token is minted per call.
    interaction: Interaction,
}

impl SkSigner {
    pub fn new(credential: SkCredential, authenticator: Arc<dyn Authenticator>) -> Self {
        Self {
            credential,
            authenticator,
            interaction: Interaction::default(),
        }
    }

    /// Where "touch your key" goes, and who is asked for a PIN.
    pub fn with_interaction(mut self, interaction: Interaction) -> Self {
        self.interaction = interaction;
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

/// The whole signing path without the async plumbing: build the request,
/// ask the token, frame the answer. Split out so it tests without a
/// runtime or an `AgentIdentity`, which only exist to satisfy the trait.
fn sign_with(
    credential: &SkCredential,
    authenticator: &dyn Authenticator,
    interaction: &Interaction,
    mut to_sign: Vec<u8>,
) -> Result<Vec<u8>, SkError> {
    let request = AssertionRequest {
        application: credential.application().to_string(),
        // Each transport hashes the message its own way.
        message: to_sign.clone(),
        // The handle whenever the file has one, resident or not: with no
        // allow-list a token holding several discoverable credentials for
        // "ssh:" answers with whichever it likes, and a signature from the
        // wrong one fails on the server for no visible reason.
        allow_credential: (!credential.key_handle().is_empty())
            .then(|| credential.key_handle().to_vec()),
        user_presence: credential.require_user_presence(),
        user_verification: credential.require_user_verification(),
    };
    let assertion = authenticator.get_assertion(&request, interaction)?;
    let signature = signature::encode_sk_signature(
        credential.algorithm(),
        &assertion.signature,
        assertion.flags,
        assertion.counter,
    )?;

    // `russh::Signer` follows the ssh-agent contract: the return value is
    // the userauth data with one SSH `string` signature appended, not the
    // blob by itself. `russh` strips the session-id prefix afterwards.
    to_sign.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    to_sign.extend_from_slice(&signature);
    Ok(to_sign)
}

/// Cancels the token request when the signing future is dropped.
struct CancelOnDrop(CancelToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        // After a finished call this is a no-op: the transports unhook
        // their cancel paths when they return.
        self.0.cancel();
    }
}

impl russh::Signer for SkSigner {
    type Error = SkError;

    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let credential = self.credential.clone();
        let authenticator = Arc::clone(&self.authenticator);
        let cancel = CancelToken::new();
        let interaction = Interaction {
            cancel: cancel.clone(),
            ..self.interaction.clone()
        };
        async move {
            let _cancel_on_drop = CancelOnDrop(cancel);
            tokio::task::spawn_blocking(move || {
                sign_with(&credential, authenticator.as_ref(), &interaction, to_sign)
            })
            .await
            .map_err(|e| SkError::Internal(format!("security-key signing task failed: {e}")))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sk::credential::fixture;
    use crate::sk::signature::signing_input;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
    use oryxis_fido2::Assertion;

    /// A software stand-in for a FIDO2 token: it holds the private half and
    /// signs `SHA256(application) || flags || counter || clientDataHash`,
    /// exactly what a real token signs. The verification below is
    /// OpenSSH's reconstruction, so a mismatch in any field fails here
    /// rather than at a server.
    struct SoftToken {
        signing_key: SigningKey,
        handle: Vec<u8>,
        counter: u32,
        expected_message: Vec<u8>,
    }

    impl Authenticator for SoftToken {
        fn get_assertion(
            &self,
            request: &AssertionRequest,
            _: &Interaction,
        ) -> Result<Assertion, oryxis_fido2::Error> {
            assert_eq!(request.application, "ssh:");
            assert_eq!(request.message, self.expected_message);
            assert_eq!(request.allow_credential.as_deref(), Some(self.handle.as_slice()));
            assert!(request.user_presence);
            assert!(!request.user_verification);

            let flags = 0x01;
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

    #[test]
    fn the_token_signature_verifies_like_openssh_verifies_it() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing_key.verifying_key().to_bytes();
        let handle = vec![0x11, 0x22, 0x33, 0x44];
        let text = fixture::sk_private_key(public, fixture::USER_PRESENCE, &handle);
        let credential = SkCredential::from_openssh_private(&text).unwrap();

        let to_sign = b"session-id + ssh-userauth publickey request".to_vec();
        let token = SoftToken {
            signing_key: signing_key.clone(),
            handle,
            counter: 12,
            expected_message: to_sign.clone(),
        };

        let signed =
            sign_with(&credential, &token, &Interaction::default(), to_sign.clone()).unwrap();

        // Every byte russh asked us to sign survives, plus one field.
        assert_eq!(&signed[..to_sign.len()], to_sign.as_slice());
        let (blob, rest) = read_string(&signed[to_sign.len()..]);
        assert!(rest.is_empty(), "exactly one signature field is appended");

        let (algorithm, rest) = read_string(blob);
        assert_eq!(algorithm, signature::SK_ED25519.as_bytes());
        let (signature, rest) = read_string(rest);
        assert_eq!(signature.len(), 64);
        let flags = rest[0];
        let counter = u32::from_be_bytes(rest[1..5].try_into().unwrap());
        assert_eq!((flags, counter), (0x01, 12));
        assert_eq!(rest.len(), 5, "nothing may follow the counter");

        let input = signing_input("ssh:", flags, counter, &signature::sha256(&to_sign));
        signing_key
            .verifying_key()
            .verify(
                &input,
                &ed25519_dalek::Signature::from_bytes(signature.try_into().unwrap()),
            )
            .expect("the token's signature must verify over OpenSSH's signed string");
    }

    /// The same end-to-end check for `sk-ecdsa-sha2-nistp256`, verified
    /// through `ssh-key`'s own security-key verifier, which rebuilds the
    /// signed string the way OpenSSH's `sk_ecdsa_verify` does.
    #[test]
    fn an_ecdsa_token_signature_verifies_through_ssh_key() {
        use p256::ecdsa::signature::Signer as _;

        struct EcdsaToken(p256::ecdsa::SigningKey);
        impl Authenticator for EcdsaToken {
            fn get_assertion(
                &self,
                request: &AssertionRequest,
                _: &Interaction,
            ) -> Result<Assertion, oryxis_fido2::Error> {
                let input = signing_input(
                    &request.application,
                    0x01,
                    5,
                    &signature::sha256(&request.message),
                );
                let sig: p256::ecdsa::Signature = self.0.sign(&input);
                Ok(Assertion {
                    signature: sig.to_der().as_bytes().to_vec(),
                    flags: 0x01,
                    counter: 5,
                })
            }
        }

        let signing_key = p256::ecdsa::SigningKey::from_slice(&[6u8; 32]).unwrap();
        let point = signing_key.verifying_key().to_sec1_point(false);
        let text =
            fixture::sk_ecdsa_private_key(point.as_bytes(), fixture::USER_PRESENCE, &[9, 9, 9]);
        let credential = SkCredential::from_openssh_private(&text).unwrap();

        let to_sign = b"userauth request".to_vec();
        let signed = sign_with(
            &credential,
            &EcdsaToken(signing_key),
            &Interaction::default(),
            to_sign.clone(),
        )
        .unwrap();
        let (blob, _) = read_string(&signed[to_sign.len()..]);
        let parsed = russh::keys::ssh_key::Signature::try_from(blob).unwrap();
        // Fully qualified: `PublicKey` also has an inherent `verify`, for
        // `ssh-keygen -Y` blobs rather than auth signatures.
        <PublicKey as ed25519_dalek::Verifier<russh::keys::ssh_key::Signature>>::verify(
            credential.public_key(),
            &to_sign,
            &parsed,
        )
        .expect("ssh-key verifies the framed ECDSA-SK signature");
    }

    #[test]
    fn a_short_signature_is_refused() {
        struct Truncating(SoftToken);
        impl Authenticator for Truncating {
            fn get_assertion(
                &self,
                request: &AssertionRequest,
                interaction: &Interaction,
            ) -> Result<Assertion, oryxis_fido2::Error> {
                let mut assertion = self.0.get_assertion(request, interaction)?;
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
            expected_message: to_sign.clone(),
        });

        let err = sign_with(&credential, &token, &Interaction::default(), to_sign).unwrap_err();
        assert!(matches!(err, SkError::Malformed(_)), "got {err:?}");
    }

    /// A resident credential is still addressed by its handle: a token
    /// with several discoverable "ssh:" credentials must sign with THIS one.
    #[test]
    fn a_resident_credential_is_still_asked_for_by_handle() {
        struct HandleCheck;
        impl Authenticator for HandleCheck {
            fn get_assertion(
                &self,
                request: &AssertionRequest,
                _: &Interaction,
            ) -> Result<Assertion, oryxis_fido2::Error> {
                assert_eq!(request.allow_credential.as_deref(), Some(&[7u8, 7][..]));
                Ok(Assertion {
                    signature: vec![0u8; 64],
                    flags: 0x01,
                    counter: 0,
                })
            }
        }

        let public = SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes();
        let text =
            fixture::sk_private_key(public, fixture::USER_PRESENCE | fixture::RESIDENT, &[7, 7]);
        let credential = SkCredential::from_openssh_private(&text).unwrap();
        assert!(credential.is_resident());
        sign_with(&credential, &HandleCheck, &Interaction::default(), b"x".to_vec()).unwrap();
    }

    /// Dropping the signing future (the dial was aborted) cancels the
    /// blocking token call instead of leaving it waiting for a touch.
    #[tokio::test]
    async fn dropping_the_future_cancels_the_token_request() {
        use russh::Signer as _;

        struct WaitsForCancel(std::sync::mpsc::Sender<()>);
        impl Authenticator for WaitsForCancel {
            fn get_assertion(
                &self,
                _: &AssertionRequest,
                interaction: &Interaction,
            ) -> Result<Assertion, oryxis_fido2::Error> {
                while !interaction.cancel.is_cancelled() {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                let _ = self.0.send(());
                Err(oryxis_fido2::Error::Cancelled)
            }
        }

        let public = SigningKey::from_bytes(&[4u8; 32]).verifying_key().to_bytes();
        let text = fixture::sk_private_key(public, fixture::USER_PRESENCE, &[1]);
        let credential = SkCredential::from_openssh_private(&text).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut signer = SkSigner::new(credential.clone(), Arc::new(WaitsForCancel(tx)));
        let identity = AgentIdentity::from(credential.public_key().clone());

        let signing = signer.auth_sign(&identity, None, b"x".to_vec());
        let timed_out =
            tokio::time::timeout(std::time::Duration::from_millis(50), signing).await;
        assert!(timed_out.is_err(), "the token never answered");
        // The timeout dropped the future; the blocking call must notice.
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("the token request was cancelled");
    }

    fn read_string(bytes: &[u8]) -> (&[u8], &[u8]) {
        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        bytes[4..].split_at(len)
    }
}
