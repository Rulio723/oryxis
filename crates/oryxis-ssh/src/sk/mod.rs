//! Native security-key authentication (`sk-ssh-ed25519@openssh.com`,
//! `sk-ecdsa-sha2-nistp256@openssh.com`).
//!
//! Oryxis could already use a hardware key through an external agent
//! (B3): the vault holds the public half and the agent signs. This module
//! signs WITHOUT an agent. The SSH client hands us the bytes to sign, the
//! token is asked for an assertion through `oryxis-fido2`, and the answer
//! is framed the way OpenSSH verifies it.
//!
//! - [`credential`] parses an OpenSSH security-key file (`id_ed25519_sk`,
//!   `id_ecdsa_sk`). That file holds no secret, only the token's
//!   credential handle and the public key.
//! - [`signature`] builds the wire blob OpenSSH's `sk_*_verify` parses.
//! - [`signer`] glues both to the token as a `russh::Signer`, the hook the
//!   agent path uses too.
//!
//! Touching a key is something a PERSON does, so the engine refuses to
//! ask for it unless the dial said someone is there to see the prompt
//! ([`SecurityKeyPrompts`], wired at the attended dial sites only). An
//! unattended dial (MCP, boot forwards, the monitor, sync) gets
//! [`SkError::Unattended`] instead of a dialog nobody asked for.

pub mod credential;
pub mod signature;
pub mod signer;

pub use credential::{SkAlgorithm, SkCredential};
pub use signer::SkSigner;

/// Whether this build can sign with a token natively on this platform.
/// The UI offers the security-key method, and the disk scan the `_sk`
/// files, only where this is true.
pub use oryxis_fido2::platform_supported as native_signing_supported;

use thiserror::Error;

/// Everything that can go wrong between "this host uses a security key"
/// and "the server has a signature".
#[derive(Debug, Error)]
pub enum SkError {
    /// The material is not an OpenSSH security-key file.
    #[error("not an OpenSSH security-key private key: {0}")]
    NotASecurityKey(String),
    /// A passphrase-protected handle file. The handle is not secret, so
    /// this is a usability wall rather than a security one.
    #[error(
        "the security-key file is passphrase-protected; \
         run `ssh-keygen -p -f <file>` to remove the passphrase first"
    )]
    EncryptedHandle,
    /// A dial nobody is watching asked for a touch.
    #[error(
        "this connection runs unattended, and a security key needs a person \
         to touch it; open the host in a terminal tab instead"
    )]
    Unattended,
    /// The token (or the way to it) failed.
    #[error(transparent)]
    Token(#[from] oryxis_fido2::Error),
    /// The token returned something we cannot frame.
    #[error("the security key returned a malformed signature: {0}")]
    Malformed(String),
    /// The SSH transport died while we were signing.
    #[error("ssh transport closed during security-key signing: {0}")]
    TransportClosed(String),
    /// Anything else (task join failure).
    #[error("security key signing failed: {0}")]
    Internal(String),
}

impl From<russh::SendError> for SkError {
    fn from(_: russh::SendError) -> Self {
        Self::TransportClosed("the server connection was lost".into())
    }
}

/// What the token is waiting on a person for, for the dial's UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKeyNotice {
    /// Touch the key.
    Touch,
    /// Verify on the key (fingerprint), or answer the OS dialog that
    /// collects its PIN.
    Verify,
}

/// The attended half of a dial: the permission to ask a person for a
/// touch, the words to ask for a PIN with, and where to say "touch your
/// key". The PIN itself is asked through the dial's keyboard-interactive
/// bridge, so both tab and pane render it with the prompt they already
/// have.
#[derive(Debug, Clone)]
pub struct SecurityKeyPrompts {
    /// Title of the PIN prompt ("Security key PIN").
    pub pin_title: String,
    /// Label of the PIN field ("PIN").
    pub pin_label: String,
    /// Shown above the field after a wrong PIN; `{n}` is the attempts
    /// left, and a template without it is shown as is.
    pub pin_retry: String,
    /// Where touch / verify notices go. `None` still allows the touch
    /// (the OS dialog or the key's own light is the prompt), it just has
    /// no card to write on.
    pub notices: Option<tokio::sync::mpsc::UnboundedSender<SecurityKeyNotice>>,
}
