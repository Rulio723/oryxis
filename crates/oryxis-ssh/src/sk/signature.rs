//! The wire shape of an OpenSSH security-key signature.
//!
//! Two byte strings matter and both are easy to get subtly wrong:
//!
//! 1. what the TOKEN signs, and
//! 2. what the SERVER is handed as the signature blob.
//!
//! Neither is `to_sign`. OpenSSH's `sk_*_verify` rebuilds (1) as
//! `SHA256(application) || flags || counter || SHA256(data)` for both
//! families, and parses (2) as the algorithm name, the family's own
//! signature encoding, then a flags byte and a big-endian counter, where a
//! plain key's signature would have stopped after the signature.

use russh::keys::ssh_key::sha2::{Digest, Sha256};

use super::SkError;
use super::credential::SkAlgorithm;

/// The algorithm name an Ed25519 security-key signature carries.
pub const SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// The algorithm name an ECDSA P-256 security-key signature carries.
pub const SK_ECDSA_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// The raw Ed25519 signature length the token returns.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// `SHA256(data)`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The byte string the token's signature covers.
///
/// The token computes the same string from the `rpId` / `clientDataHash`
/// we send, and OpenSSH recomputes it at verification time: three
/// derivations of one value, so any disagreement is a silent `Signature
/// invalid` at the far end.
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

/// Encode the SSH signature blob for an assertion.
///
/// - Ed25519: `string name || string sig(64) || byte flags || uint32 counter`
/// - ECDSA: `string name || string (mpint r || mpint s) || byte flags ||
///   uint32 counter`, the token's DER signature re-encoded as the two
///   integers SSH uses for every ECDSA signature.
pub fn encode_sk_signature(
    algorithm: SkAlgorithm,
    signature: &[u8],
    flags: u8,
    counter: u32,
) -> Result<Vec<u8>, SkError> {
    let (name, inner) = match algorithm {
        SkAlgorithm::Ed25519 => {
            if signature.len() != ED25519_SIGNATURE_LEN {
                return Err(SkError::Malformed(format!(
                    "expected a {ED25519_SIGNATURE_LEN}-byte Ed25519 signature, got {}",
                    signature.len()
                )));
            }
            (SK_ED25519, signature.to_vec())
        }
        SkAlgorithm::EcdsaP256 => {
            let (r, s) = der_ecdsa_signature(signature)?;
            let mut inner = Vec::with_capacity(2 * (4 + 33));
            put_mpint(&mut inner, r);
            put_mpint(&mut inner, s);
            (SK_ECDSA_P256, inner)
        }
    };
    let mut out = Vec::with_capacity(4 + name.len() + 4 + inner.len() + 5);
    put_string(&mut out, name.as_bytes());
    put_string(&mut out, &inner);
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    Ok(out)
}

/// `SEQUENCE { INTEGER r, INTEGER s }`, the ECDSA signature a FIDO2 token
/// returns. Strict about the outer shape (a trailing byte is an error),
/// because what comes out goes on the wire.
fn der_ecdsa_signature(der: &[u8]) -> Result<(&[u8], &[u8]), SkError> {
    let malformed = || SkError::Malformed("the ECDSA signature is not DER".into());
    let (sequence, rest) = der_element(der, 0x30).ok_or_else(malformed)?;
    if !rest.is_empty() {
        return Err(malformed());
    }
    let (r, rest) = der_element(sequence, 0x02).ok_or_else(malformed)?;
    let (s, rest) = der_element(rest, 0x02).ok_or_else(malformed)?;
    if !rest.is_empty() || r.is_empty() || s.is_empty() || r.len() > 33 || s.len() > 33 {
        return Err(malformed());
    }
    Ok((r, s))
}

/// One DER TLV with the expected tag: its contents and what follows.
/// Short-form lengths only, which is all a P-256 signature needs (at most
/// 72 bytes); a long form is refused rather than half-read.
fn der_element(bytes: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, rest) = bytes.split_first()?;
    let (&len, rest) = rest.split_first()?;
    if found != tag || len & 0x80 != 0 || rest.len() < len as usize {
        return None;
    }
    Some(rest.split_at(len as usize))
}

/// SSH `mpint` of a non-negative big-endian integer: no redundant leading
/// zeros, and one zero byte in front when the top bit is set so it does
/// not read as negative.
fn put_mpint(out: &mut Vec<u8>, integer: &[u8]) {
    let first = integer.iter().position(|b| *b != 0).unwrap_or(integer.len());
    let magnitude = &integer[first..];
    let pad = magnitude.first().is_some_and(|b| b & 0x80 != 0);
    out.extend_from_slice(&((magnitude.len() + usize::from(pad)) as u32).to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(magnitude);
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
    /// whole difference.
    #[test]
    fn signature_blob_has_the_security_key_tail() {
        let signature = [0xabu8; ED25519_SIGNATURE_LEN];
        let blob = encode_sk_signature(SkAlgorithm::Ed25519, &signature, 0x05, 42).unwrap();

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
    /// signature (a truncated read) must not reach the wire as a blob the
    /// server will read as garbage.
    #[test]
    fn a_wrong_length_signature_is_refused() {
        assert!(encode_sk_signature(SkAlgorithm::Ed25519, &[0u8; 63], 0x01, 0).is_err());
        assert!(encode_sk_signature(SkAlgorithm::Ed25519, &[], 0x01, 0).is_err());
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

    #[test]
    fn an_ecdsa_signature_becomes_two_mpints() {
        // r with its top bit set (DER pads it with a zero, and so must the
        // mpint), s with a redundant leading zero DER would not have.
        let r = [0x80u8; 32];
        let s = [0x01u8; 32];
        let mut der = vec![0x30, 0x45, 0x02, 0x21, 0x00];
        der.extend_from_slice(&r);
        der.extend_from_slice(&[0x02, 0x20]);
        der.extend_from_slice(&s);

        let blob = encode_sk_signature(SkAlgorithm::EcdsaP256, &der, 0x01, 3).unwrap();
        let mut inner = Vec::new();
        inner.extend_from_slice(&33u32.to_be_bytes());
        inner.push(0);
        inner.extend_from_slice(&r);
        inner.extend_from_slice(&32u32.to_be_bytes());
        inner.extend_from_slice(&s);
        let mut expected = Vec::new();
        put_string(&mut expected, SK_ECDSA_P256.as_bytes());
        put_string(&mut expected, &inner);
        expected.push(0x01);
        expected.extend_from_slice(&3u32.to_be_bytes());
        assert_eq!(blob, expected);
    }

    #[test]
    fn a_malformed_ecdsa_signature_is_refused() {
        for der in [
            vec![],
            vec![0x30, 0x02, 0x02, 0x00],
            vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            // A trailing byte after the sequence.
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
            // A long-form length.
            vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        ] {
            assert!(
                encode_sk_signature(SkAlgorithm::EcdsaP256, &der, 1, 0).is_err(),
                "{der:02x?}"
            );
        }
    }

    #[test]
    fn mpint_strips_and_pads_like_openssh() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0x00, 0x00, 0x7f]);
        assert_eq!(out, vec![0, 0, 0, 1, 0x7f]);
        out.clear();
        put_mpint(&mut out, &[0x00, 0x80]);
        assert_eq!(out, vec![0, 0, 0, 2, 0x00, 0x80]);
        out.clear();
        put_mpint(&mut out, &[0x00]);
        assert_eq!(out, vec![0, 0, 0, 0]);
    }
}
