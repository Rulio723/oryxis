//! Native FIDO2 security-key authentication (`sk-ssh-ed25519@openssh.com`).
//!
//! Oryxis already had two ways to use a hardware key: the vault can hold
//! the *public* half (B3) and an external `ssh-agent` does the signing.
//! This module is the third, and the one the roadmap calls "native
//! FIDO2": the SSH client hands us the bytes to sign, we speak CTAP2 to
//! the token ourselves, and no agent process is involved.
//!
//! - [`credential`] parses an OpenSSH security-key *private* file
//!   (`id_ed25519_sk`). That file holds no secret — only the token's
//!   credential handle and the public key — which is why it can sit in
//!   the vault beside ordinary keys without weakening anything.
//! - [`authenticator`] is the token itself, behind a trait, so the whole
//!   signing path is testable without hardware.
//! - [`signature`] builds the exact wire blob OpenSSH's
//!   `sk_ed25519_verify` parses.
//! - [`signer`] glues the three into a `russh::auth::Signer`, the hook
//!   `russh` already offers for signing outside the process (the agent
//!   path uses the same one).

pub mod authenticator;
pub mod credential;
pub mod signature;
pub mod signer;

#[cfg(target_os = "windows")]
mod ctap;
#[cfg(target_os = "windows")]
mod hid_windows;
#[cfg(target_os = "windows")]
mod webauthn_windows;

pub use authenticator::{Assertion, AssertionRequest, SkAuthenticator, platform_authenticator};
pub use credential::SkCredential;
pub use signer::SkSigner;

use thiserror::Error;

/// Everything that can go wrong between "the user picked a security key"
/// and "the server has a signature".
#[derive(Debug, Error)]
pub enum SkError {
    /// The vault row is not an OpenSSH security-key private file.
    #[error("not an OpenSSH security-key private key: {0}")]
    NotASecurityKey(String),
    /// `sk-ecdsa-sha2-nistp256@openssh.com`, the plan's phase 2.
    #[error("{0} security keys are not supported yet (Ed25519-SK only)")]
    UnsupportedAlgorithm(String),
    /// A passphrase-protected handle file. The handle is not secret, so
    /// this is a usability wall rather than a security one; `ssh-keygen
    /// -p` removes it.
    #[error(
        "the security-key file is passphrase-protected; \
         run `ssh-keygen -p -f <file>` to remove the passphrase first"
    )]
    EncryptedHandle,
    /// No FIDO token on this machine, or the platform has no transport.
    #[error("no security key found: {0}")]
    DeviceNotFound(String),
    /// The token is there but would not talk to us.
    #[error("security key communication failed: {0}")]
    Transport(String),
    /// The token asked for a PIN, which phase 1 cannot supply.
    #[error("the security key requires a PIN, which Oryxis does not support yet")]
    PinRequired,
    /// The token wants the user verified and cannot do it without a PIN.
    #[error("the security key requires user verification (PIN) that Oryxis cannot supply yet")]
    UserVerificationUnavailable,
    /// The user never touched the token.
    #[error("timed out waiting for a touch on the security key")]
    TouchTimeout,
    /// The user dismissed the touch prompt.
    #[error("the security key request was cancelled")]
    Cancelled,
    /// The token knows nothing about this credential handle.
    #[error("the security key does not hold the credential this key file names")]
    CredentialNotFound,
    /// The token returned something we cannot encode.
    #[error("the security key returned a malformed assertion: {0}")]
    Malformed(String),
    /// The SSH transport died while we were signing.
    #[error("ssh transport closed during security-key signing: {0}")]
    TransportClosed(String),
    /// Anything else (task join failure, ...).
    #[error("security key signing failed: {0}")]
    Internal(String),
}

impl From<russh::SendError> for SkError {
    fn from(_: russh::SendError) -> Self {
        Self::TransportClosed("the server connection was lost".into())
    }
}
