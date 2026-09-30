//! The CTAP2 PIN/UV auth protocols (CTAP 2.1, section 6.5).
//!
//! A PIN never travels to the token in the clear, and the token never
//! hands back its pinUvAuthToken in the clear either: both sides agree an
//! ECDH secret over P-256 first, and everything PIN-shaped rides inside
//! AES-256-CBC under it. The token then proves the request came from
//! whoever knows the PIN by checking an HMAC over the client data hash,
//! keyed with that token.
//!
//! Two protocol versions exist and tokens in the field speak either:
//!
//! - **1**: the key is `SHA-256(Z)` for both AES and HMAC, the IV is all
//!   zeros, and the HMAC is truncated to 16 bytes.
//! - **2**: HKDF-SHA-256 splits `Z` into an HMAC key and an AES key, every
//!   ciphertext carries its own random IV in front, and the HMAC is whole.
//!
//! Both are implemented because a token lists what it supports and the
//! first one it lists is the one to use.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

type HmacSha256 = hmac::Hmac<Sha256>;

/// A pinUvAuthProtocol this implementation speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    One,
    Two,
}

impl Protocol {
    pub(crate) fn id(self) -> u64 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }

    /// The first protocol in the token's list that we speak. The token
    /// orders the list by preference; CTAP 2.0 tokens send no list at all
    /// and speak protocol 1.
    pub(crate) fn negotiate(offered: &[u64]) -> Option<Self> {
        if offered.is_empty() {
            return Some(Self::One);
        }
        offered.iter().find_map(|id| match id {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            _ => None,
        })
    }

    /// `authenticate(key, message)`: the HMAC a token checks.
    pub(crate) fn authenticate(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
            .expect("HMAC takes a key of any length");
        mac.update(message);
        let full = mac.finalize().into_bytes();
        match self {
            Self::One => full[..16].to_vec(),
            Self::Two => full.to_vec(),
        }
    }
}

/// The platform's half of one key agreement: what to send the token, and
/// the secret both sides now share.
pub(crate) struct Agreement {
    /// The platform public key, as COSE x / y coordinates.
    pub(crate) x: [u8; 32],
    pub(crate) y: [u8; 32],
    pub(crate) secret: SharedSecret,
}

pub(crate) struct SharedSecret {
    protocol: Protocol,
    hmac_key: Zeroizing<[u8; 32]>,
    aes_key: Zeroizing<[u8; 32]>,
}

/// Agree a secret with the token whose key-agreement public key is
/// (`token_x`, `token_y`).
pub(crate) fn agree(
    protocol: Protocol,
    token_x: &[u8],
    token_y: &[u8],
) -> Result<Agreement, Error> {
    if token_x.len() != 32 || token_y.len() != 32 {
        return Err(Error::Malformed(
            "the security key's key-agreement point is not a P-256 point".into(),
        ));
    }
    let mut encoded = [0u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(token_x);
    encoded[33..].copy_from_slice(token_y);
    let token_key = p256::PublicKey::from_sec1_bytes(&encoded).map_err(|_| {
        Error::Malformed("the security key's key-agreement point is not on P-256".into())
    })?;

    let ours = ephemeral_key()?;
    let shared = ours.diffie_hellman(&token_key);
    let z = Zeroizing::new(<[u8; 32]>::from(*shared.raw_secret_bytes()));

    let public = ours.public_key().to_sec1_point(false);
    let bytes = public.as_bytes();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);

    Ok(Agreement {
        x,
        y,
        secret: SharedSecret::derive(protocol, &z),
    })
}

/// A fresh P-256 secret from the OS. Rejection-sampled: a 32-byte string
/// is a valid scalar with overwhelming probability, and the loop is what
/// makes "overwhelming" into "always".
pub(crate) fn ephemeral_key() -> Result<p256::SecretKey, Error> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|e| Error::Transport(format!("no randomness for the PIN protocol: {e}")))?;
        if let Ok(key) = p256::SecretKey::from_slice(bytes.as_ref()) {
            return Ok(key);
        }
    }
}

impl SharedSecret {
    pub(crate) fn derive(protocol: Protocol, z: &[u8; 32]) -> Self {
        match protocol {
            Protocol::One => {
                let key: [u8; 32] = Sha256::digest(z).into();
                Self {
                    protocol,
                    hmac_key: Zeroizing::new(key),
                    aes_key: Zeroizing::new(key),
                }
            }
            Protocol::Two => {
                let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
                let mut hmac_key = Zeroizing::new([0u8; 32]);
                let mut aes_key = Zeroizing::new([0u8; 32]);
                hkdf.expand(b"CTAP2 HMAC key", hmac_key.as_mut())
                    .expect("32 bytes is a valid HKDF-SHA-256 length");
                hkdf.expand(b"CTAP2 AES key", aes_key.as_mut())
                    .expect("32 bytes is a valid HKDF-SHA-256 length");
                Self {
                    protocol,
                    hmac_key,
                    aes_key,
                }
            }
        }
    }

    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// `encrypt(key, plaintext)`, `plaintext` a whole number of blocks.
    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let iv = match self.protocol {
            Protocol::One => [0u8; 16],
            Protocol::Two => {
                let mut iv = [0u8; 16];
                getrandom::fill(&mut iv)
                    .map_err(|e| Error::Transport(format!("no randomness for an IV: {e}")))?;
                iv
            }
        };
        let mut buffer = plaintext.to_vec();
        cbc::Encryptor::<Aes256>::new((&*self.aes_key).into(), (&iv).into())
            .encrypt_padded::<NoPadding>(&mut buffer, plaintext.len())
            .map_err(|_| Error::Malformed("PIN protocol plaintext is not block-aligned".into()))?;
        Ok(match self.protocol {
            Protocol::One => buffer,
            Protocol::Two => iv.iter().copied().chain(buffer).collect(),
        })
    }

    /// `decrypt(key, ciphertext)`.
    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (iv, body) = match self.protocol {
            Protocol::One => ([0u8; 16], ciphertext),
            Protocol::Two => {
                if ciphertext.len() < 16 {
                    return Err(Error::Malformed("PIN protocol ciphertext has no IV".into()));
                }
                let mut iv = [0u8; 16];
                iv.copy_from_slice(&ciphertext[..16]);
                (iv, &ciphertext[16..])
            }
        };
        if body.is_empty() || body.len() % 16 != 0 {
            return Err(Error::Malformed(
                "PIN protocol ciphertext is not block-aligned".into(),
            ));
        }
        let mut buffer = Zeroizing::new(body.to_vec());
        cbc::Decryptor::<Aes256>::new((&*self.aes_key).into(), (&iv).into())
            .decrypt_padded::<NoPadding>(buffer.as_mut_slice())
            .map_err(|_| Error::Malformed("PIN protocol ciphertext did not decrypt".into()))?;
        Ok(buffer)
    }

    /// `authenticate` keyed with the shared secret itself.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        self.protocol.authenticate(self.hmac_key.as_ref(), message)
    }
}

/// `LEFT(SHA-256(pin), 16)`, what `pinHashEnc` encrypts.
pub(crate) fn pin_hash(pin: &str) -> Zeroizing<[u8; 16]> {
    let digest = Sha256::digest(pin.as_bytes());
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token's side of the agreement, computed independently, so the
    /// platform side is checked against the spec rather than itself.
    fn token_side(protocol: Protocol, token: &p256::SecretKey, agreement: &Agreement) -> SharedSecret {
        let mut encoded = [0u8; 65];
        encoded[0] = 0x04;
        encoded[1..33].copy_from_slice(&agreement.x);
        encoded[33..].copy_from_slice(&agreement.y);
        let platform = p256::PublicKey::from_sec1_bytes(&encoded).unwrap();
        let shared = token.diffie_hellman(&platform);
        let z = <[u8; 32]>::from(*shared.raw_secret_bytes());
        SharedSecret::derive(protocol, &z)
    }

    fn token_point(token: &p256::SecretKey) -> ([u8; 32], [u8; 32]) {
        let point = token.public_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        (bytes[1..33].try_into().unwrap(), bytes[33..65].try_into().unwrap())
    }

    #[test]
    fn both_sides_derive_the_same_keys_under_either_protocol() {
        for protocol in [Protocol::One, Protocol::Two] {
            let token = ephemeral_key().unwrap();
            let (x, y) = token_point(&token);
            let agreement = agree(protocol, &x, &y).unwrap();
            let theirs = token_side(protocol, &token, &agreement);

            // What the platform encrypts, the token decrypts.
            let pin = pin_hash("123456");
            let sent = agreement.secret.encrypt(pin.as_ref()).unwrap();
            assert_eq!(theirs.decrypt(&sent).unwrap().as_slice(), pin.as_ref());

            // And the token's pinUvAuthToken comes back intact.
            let pin_token = [0x42u8; 32];
            let returned = theirs.encrypt(&pin_token).unwrap();
            assert_eq!(agreement.secret.decrypt(&returned).unwrap().as_slice(), &pin_token);

            assert_eq!(
                agreement.secret.authenticate(b"x"),
                theirs.authenticate(b"x")
            );
        }
    }

    #[test]
    fn protocol_one_is_zero_iv_and_a_truncated_mac() {
        let token = ephemeral_key().unwrap();
        let (x, y) = token_point(&token);
        let agreement = agree(Protocol::One, &x, &y).unwrap();
        let block = [7u8; 16];
        // No IV in front, and a fixed IV means the same input encrypts
        // the same way twice.
        let one = agreement.secret.encrypt(&block).unwrap();
        assert_eq!(one.len(), 16);
        assert_eq!(one, agreement.secret.encrypt(&block).unwrap());
        assert_eq!(Protocol::One.authenticate(&[1; 32], b"m").len(), 16);
    }

    #[test]
    fn protocol_two_carries_a_fresh_iv_and_the_whole_mac() {
        let token = ephemeral_key().unwrap();
        let (x, y) = token_point(&token);
        let agreement = agree(Protocol::Two, &x, &y).unwrap();
        let block = [7u8; 16];
        let one = agreement.secret.encrypt(&block).unwrap();
        assert_eq!(one.len(), 32);
        assert_ne!(one, agreement.secret.encrypt(&block).unwrap());
        assert_eq!(Protocol::Two.authenticate(&[1; 32], b"m").len(), 32);
    }

    #[test]
    fn protocol_two_derives_distinct_keys_with_the_spec_labels() {
        // HKDF-SHA-256(salt = 32 zero bytes, IKM = Z), info strings from
        // CTAP 2.1 section 6.5.7. Pinned against the hkdf crate directly
        // so a relabelled info string fails here.
        let z = [9u8; 32];
        let secret = SharedSecret::derive(Protocol::Two, &z);
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), &z);
        let mut hmac_key = [0u8; 32];
        let mut aes_key = [0u8; 32];
        hkdf.expand(b"CTAP2 HMAC key", &mut hmac_key).unwrap();
        hkdf.expand(b"CTAP2 AES key", &mut aes_key).unwrap();
        assert_eq!(secret.hmac_key.as_ref(), &hmac_key);
        assert_eq!(secret.aes_key.as_ref(), &aes_key);
        assert_ne!(hmac_key, aes_key);
    }

    #[test]
    fn negotiation_takes_the_first_protocol_we_speak() {
        assert_eq!(Protocol::negotiate(&[2, 1]), Some(Protocol::Two));
        assert_eq!(Protocol::negotiate(&[1, 2]), Some(Protocol::One));
        assert_eq!(Protocol::negotiate(&[7, 1]), Some(Protocol::One));
        assert_eq!(Protocol::negotiate(&[]), Some(Protocol::One));
        assert_eq!(Protocol::negotiate(&[7]), None);
    }

    #[test]
    fn a_point_off_the_curve_is_refused() {
        assert!(agree(Protocol::Two, &[1u8; 32], &[2u8; 32]).is_err());
        assert!(agree(Protocol::Two, &[1u8; 31], &[2u8; 32]).is_err());
    }

    /// Known answers computed OUTSIDE this crate (OpenSSL's `enc
    /// -aes-256-cbc -nopad` and Python's `hmac` / `hashlib`, HKDF by hand
    /// per RFC 5869), so a mistake made symmetrically on both sides of the
    /// simulated token (a wrong label, salt or IV rule) still fails here.
    /// Z = 00 01 .. 1f, plaintext = 40 41 .. 4f, message = "client data hash".
    #[test]
    fn known_answers_for_both_protocols() {
        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        }
        let z: [u8; 32] = std::array::from_fn(|i| i as u8);
        let plaintext: [u8; 16] = std::array::from_fn(|i| 0x40 + i as u8);
        let message = b"client data hash";

        let one = SharedSecret::derive(Protocol::One, &z);
        assert_eq!(
            one.aes_key.as_ref().to_vec(),
            hex("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd")
        );
        assert_eq!(one.hmac_key.as_ref(), one.aes_key.as_ref());
        assert_eq!(one.encrypt(&plaintext).unwrap(), hex("78e7e8966d197598397065dd603b79a8"));
        assert_eq!(one.authenticate(message), hex("a39aeb279076e22ab6f9e006603a7535"));

        let two = SharedSecret::derive(Protocol::Two, &z);
        assert_eq!(
            two.hmac_key.as_ref().to_vec(),
            hex("a689b3b92a6ebab91192408da9c4f05c674a2bc5f938d613077716c719a8df39")
        );
        assert_eq!(
            two.aes_key.as_ref().to_vec(),
            hex("0f6ff2ef211829c11638ef2893ea02edf195658c0572393e7680d93bc2b58d44")
        );
        // Protocol 2 picks a random IV, so the known answer is checked on
        // the decrypt side: IV (a5 x 16) || ciphertext from OpenSSL.
        let sealed = hex("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5534c065047cf2bbea682966ed2abe4f0");
        assert_eq!(two.decrypt(&sealed).unwrap().as_slice(), &plaintext);
        assert_eq!(
            two.authenticate(message),
            hex("b29d01f538a5fd69d96f40acf6c6a259ad7629b61eaf574c739120c41aea3ec1")
        );
    }
}
