//! Real-hardware acceptance harness for native FIDO2 security-key auth.
//!
//! Step 4 of the FIDO2 plan is "does it work on a real token". This drives
//! a physical security key through the *same* code the SSH client uses,
//! then verifies the result with `ssh_key`'s own
//! `sk-ssh-ed25519@openssh.com` verifier — the same reconstruction
//! OpenSSH's `sk_ed25519_verify` performs. No ssh-agent, no server, no
//! network: if this passes and a login with the same key still fails, the
//! fault is above the token.
//!
//! On Windows an ordinary process goes through Windows Hello. An elevated
//! process uses direct USB HID so both transport choices can be checked with
//! the same executable.
//!
//! ```text
//! cargo run -p oryxis-ssh --example sk_acceptance -- ~/.ssh/id_ed25519_sk
//! ```
//!
//! It is a manual, hardware-dependent check, which is why it is an example
//! and not a test: `cargo test` has to stay hermetic.

use std::process::ExitCode;

use oryxis_ssh::sk::{SkCredential, SkError, SkSigner, platform_authenticator};
use russh::Signer as _;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::{PublicKey, Signature};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    // The transport's own diagnostics are the whole point when a key is
    // not found, so show them by default rather than hiding them behind
    // RUST_LOG. `RUST_LOG` still overrides.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("oryxis_ssh=debug")),
        )
        .with_target(false)
        .without_time()
        .init();

    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: sk_acceptance <path to an id_ed25519_sk file>");
        eprintln!("       (the private file `ssh-keygen -t ed25519-sk` wrote, not the .pub)");
        return ExitCode::from(2);
    };

    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("FAIL: cannot read {path}: {err}");
            return ExitCode::FAILURE;
        }
    };
    println!("[1/4] read {path} ({} bytes)", text.len());

    let credential = match SkCredential::from_openssh_private(&text) {
        Ok(credential) => credential,
        Err(err) => {
            eprintln!("FAIL: {err}");
            return ExitCode::FAILURE;
        }
    };
    println!("[2/4] parsed the security-key credential");
    println!(
        "      algorithm      : {}",
        credential.public_key().algorithm().as_str()
    );
    println!("      application    : {:?}", credential.application());
    println!(
        "      credential     : {} byte handle{}",
        credential.key_handle().len(),
        if credential.is_resident() {
            " (resident: the token holds it)"
        } else {
            ""
        }
    );
    println!(
        "      touch required : {}",
        credential.require_user_presence()
    );
    println!(
        "      PIN required   : {}",
        credential.require_user_verification()
    );
    println!("      fingerprint    : {}", credential.fingerprint());

    // The bytes `russh` would hand to `Signer::auth_sign` for a publickey
    // attempt with this key. The signature covers whatever we pass, so the
    // shape is not itself under test — but using the real one means a
    // mistake in how the public key gets spliced in surfaces here rather
    // than at a server.
    let to_sign = userauth_request("root", &[0x5a; 32], credential.public_key());

    println!();
    println!("[3/4] talking to the token (Windows Hello on Windows, USB HID elsewhere)");
    println!("      >>> touch your security key now <<<");
    println!();

    let mut signer = SkSigner::new(credential.clone(), platform_authenticator());
    let identity = AgentIdentity::from(credential.public_key().clone());
    let signed = match signer.auth_sign(&identity, None, to_sign.clone()).await {
        Ok(signed) => signed,
        Err(err) => {
            eprintln!("FAIL: the token produced no signature: {err}");
            return sk_error_exit_code(&err);
        }
    };

    let Some(field) = signed.get(to_sign.len()..) else {
        eprintln!("FAIL: the signer discarded part of the userauth request");
        return ExitCode::FAILURE;
    };
    if field.len() < 4 {
        eprintln!("FAIL: the signer returned no SSH signature field");
        return ExitCode::FAILURE;
    }
    let blob_len = u32::from_be_bytes(field[..4].try_into().expect("four bytes")) as usize;
    if field.len() != 4 + blob_len {
        eprintln!("FAIL: the SSH signature field has an invalid length");
        return ExitCode::FAILURE;
    }
    let signature = match Signature::try_from(&field[4..]) {
        Ok(signature) => signature,
        Err(err) => {
            eprintln!("FAIL: the blob we built does not decode: {err}");
            return ExitCode::FAILURE;
        }
    };

    // `Signature` keeps the security-key tail (`sig || flags || counter`)
    // as its payload — exactly the five bytes OpenSSH appends after a
    // plain Ed25519 signature.
    let raw = signature.as_bytes();
    let (signature_bytes, tail) = raw.split_at(raw.len() - 5);
    let flags = tail[0];
    let counter = u32::from_be_bytes(tail[1..5].try_into().expect("four bytes"));

    println!("[4/4] verifying the way OpenSSH's `sk_ed25519_verify` does");
    println!("      signature algo : {}", signature.algorithm().as_str());
    println!("      raw signature  : {} bytes", signature_bytes.len());
    println!(
        "      flags          : 0x{flags:02x} (user present: {}, user verified: {})",
        flags & 0x01 != 0,
        flags & 0x04 != 0
    );
    println!("      counter        : {counter}");

    // Fully qualified: `PublicKey` also has an inherent `verify`, and that
    // one is about `ssh-keygen -Y sign` blobs, not SSH auth signatures.
    // The trait method is the one that rebuilds the security-key signed
    // string, so it has to be named explicitly.
    if let Err(err) = <PublicKey as ed25519_dalek::Verifier<Signature>>::verify(
        credential.public_key(),
        &to_sign,
        &signature,
    ) {
        eprintln!("FAIL: the signature does not verify: {err}");
        return ExitCode::FAILURE;
    }
    println!("      signature      : VALID");

    println!();
    println!("PASS - the token signed natively and the signature verifies.");
    println!("       No ssh-agent took part at any point.");
    ExitCode::SUCCESS
}

/// Keep hardware/transport failures distinguishable when an elevated test
/// runs in a short-lived console whose text cannot be captured by its parent.
fn sk_error_exit_code(error: &SkError) -> ExitCode {
    let code = match error {
        SkError::DeviceNotFound(_) => 10,
        SkError::Transport(_) => 11,
        SkError::PinRequired | SkError::UserVerificationUnavailable => 12,
        SkError::TouchTimeout | SkError::Cancelled => 13,
        SkError::CredentialNotFound => 14,
        SkError::Malformed(_) => 15,
        SkError::NotASecurityKey(_)
        | SkError::UnsupportedAlgorithm(_)
        | SkError::EncryptedHandle
        | SkError::TransportClosed(_)
        | SkError::Internal(_) => 16,
    };
    ExitCode::from(code)
}

/// `session_id || SSH_MSG_USERAUTH_REQUEST` for a publickey attempt with
/// this key — the bytes `russh` hands to the signer.
fn userauth_request(user: &str, session_id: &[u8; 32], public_key: &PublicKey) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(session_id);
    blob.push(50); // SSH_MSG_USERAUTH_REQUEST
    put_string(&mut blob, user.as_bytes());
    put_string(&mut blob, b"ssh-connection");
    put_string(&mut blob, b"publickey");
    blob.push(1); // TRUE: a real signature, not an "is this key acceptable?" probe
    put_string(&mut blob, b"sk-ssh-ed25519@openssh.com");
    put_string(
        &mut blob,
        &public_key.to_bytes().expect("the public key encodes"),
    );
    blob
}

/// SSH `string`: a big-endian length, then the bytes.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
