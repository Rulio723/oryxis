//! The wire shape of an OpenSSH security-key signature.
//!
//! Two byte strings matter here and both are easy to get subtly wrong:
//!
//! 1. what the *token* signs, and
//! 2. what the *server* is handed as the signature blob.
//!
//! Neither is `to_sign`. OpenSSH's `sk_ed25519_verify` reconstructs (1)
//! from `SHA256(application)`, the assertion's flags and counter, and
//! `SHA256(data)`; and it parses (2) as the algorithm name, the raw
//! Ed25519 signature, then a flags byte and a big-endian counter — where
//! a plain `ssh-ed25519` signature would have stopped after the
//! signature.
//!
//! `ssh_key::Signature` models that tail as well (`Algorithm::SkEd25519`
//! carries `sig || flags || counter`), so this is not the only way to
//! build the blob. It is here because the token hands the three pieces
//! back loose, and assembling them — length check included — in one place
//! keeps the wire shape visible instead of implied by a constructor.

use russh::keys::ssh_key::sha2::{Digest, Sha256};

use super::SkError;

/// The OpenSSH algorithm name an Ed25519 security-key signature carries.
pub const SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";

/// The raw Ed25519 signature length the token returns.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// `SHA256(data)`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The byte string the token's signature covers.
///
/// `SHA256(application) || flags || counter_be || client_data_hash` —
/// the FIDO2 relying-party-id hash, the `authenticatorData` header the
/// token will return, and the client data hash. The token computes the
/// same string internally from the `rpId`/`clientDataHash` we send it,
/// and OpenSSH recomputes it at verification time; three independent
/// derivations of one value, so any disagreement is a silent
/// `Signature invalid` at the far end.
pub fn signing_input(
    application: &str,
    flags: u8,
    counter: u32,
    client_data_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 1 + 4 + 32);
    out.extend_from_slice(&sha256(application.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(client_data_hash);
    out
}

/// Encode the SSH signature blob for a security-key assertion.
///
/// `string "sk-ssh-ed25519@openssh.com" || string signature || byte flags
/// || uint32 counter`. [`super::signer`] wraps this blob in the outer SSH
/// `string` field and appends it to russh's userauth data.
pub fn encode_sk_ed25519_signature(
    signature: &[u8],
    flags: u8,
    counter: u32,
) -> Result<Vec<u8>, SkError> {
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(SkError::Malformed(format!(
            "expected a {ED25519_SIGNATURE_LEN}-byte Ed25519 signature, got {}",
            signature.len()
        )));
    }
    let mut out = Vec::with_capacity(4 + SK_ED25519.len() + 4 + ED25519_SIGNATURE_LEN + 5);
    put_string(&mut out, SK_ED25519.as_bytes());
    put_string(&mut out, signature);
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    Ok(out)
}

/// SSH `string`: a big-endian length, then the bytes.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The blob layout, field by field. A plain `ssh-ed25519` signature
    /// would end after the second field; the flags/counter tail is the
    /// whole difference and the reason this cannot reuse
    /// `ssh_key::Signature`.
    #[test]
    fn signature_blob_has_the_security_key_tail() {
        let signature = [0xabu8; ED25519_SIGNATURE_LEN];
        let blob = encode_sk_ed25519_signature(&signature, 0x05, 42).unwrap();

        let mut expected = Vec::new();
        put_string(&mut expected, SK_ED25519.as_bytes());
        put_string(&mut expected, &signature);
        expected.push(0x05);
        expected.extend_from_slice(&42u32.to_be_bytes());
        assert_eq!(blob, expected);

        // Trailing five bytes: flags then counter, big-endian.
        let tail = &blob[blob.len() - 5..];
        assert_eq!(tail, &[0x05, 0x00, 0x00, 0x00, 42]);
    }

    /// A token that returns something other than a 64-byte Ed25519
    /// signature (an ECDSA SK, a truncated read) must not reach the wire
    /// as a blob the server will read as garbage.
    #[test]
    fn a_wrong_length_signature_is_refused() {
        assert!(encode_sk_ed25519_signature(&[0u8; 63], 0x01, 0).is_err());
        assert!(encode_sk_ed25519_signature(&[], 0x01, 0).is_err());
    }

    /// The signed input is 69 bytes and starts with the application
    /// hash: this is what `sk_ed25519_verify` rebuilds, so the offsets
    /// are load-bearing.
    #[test]
    fn signing_input_matches_the_openssh_reconstruction() {
        let client_data_hash = sha256(b"client data");
        let input = signing_input("ssh:", 0x01, 7, &client_data_hash);

        assert_eq!(input.len(), 69);
        assert_eq!(&input[..32], &sha256(b"ssh:")[..]);
        assert_eq!(input[32], 0x01);
        assert_eq!(&input[33..37], &7u32.to_be_bytes());
        assert_eq!(&input[37..], &client_data_hash[..]);
    }

    /// The application is part of the signed bytes, so a key scoped to a
    /// different relying party cannot verify against `ssh:`.
    #[test]
    fn a_different_application_hashes_differently() {
        let hash = sha256(b"client data");
        assert_ne!(
            signing_input("ssh:", 1, 0, &hash),
            signing_input("other:", 1, 0, &hash)
        );
    }
}
