//! Asking a FIDO2 token for an assertion.
//!
//! USB everywhere; NFC and Bluetooth tokens only through Windows Hello,
//! which reaches them itself. Linux NFC would go through PC/SC (`pcscd`),
//! a service and a C library this crate does not take on.
//!
//! The SSH side (`oryxis-ssh::sk`) knows what an `sk-ssh-ed25519` key file
//! holds and what OpenSSH expects on the wire. This crate knows the other
//! half: how to reach a token on this machine and run
//! `authenticatorGetAssertion` against it, PIN protocol included. Nothing
//! here knows about SSH, which is what keeps the transports testable
//! against a scripted device and reusable by anything else that ever
//! needs a token.
//!
//! - [`ctap`] is CTAPHID framing plus the one CTAP2 command we send, and
//!   the sliver of CBOR it needs. Platform-neutral: it talks to a
//!   [`ctap::HidTransport`].
//! - `hid_windows` / `hid_linux` / `hid_macos` are that transport over the
//!   OS's HID device interface.
//! - `webauthn_windows` is Windows Hello, the only way an ordinary
//!   (non-elevated) Windows process may reach a token at all.
//!
//! Every call blocks: a USB round trip, then a person pressing a button.
//! Callers run it on a blocking thread and stop it with a
//! [`CancelToken`], never by dropping a future around it.

mod authenticator;
mod cancel;
mod cbor;
pub mod ctap;
mod pin;

#[cfg(target_os = "linux")]
mod hid_linux;
#[cfg(target_os = "macos")]
mod hid_macos;
#[cfg(windows)]
mod hid_windows;
#[cfg(windows)]
mod webauthn_windows;

pub use authenticator::{
    Assertion, AssertionRequest, Authenticator, Interaction, PinPrompt, PinSource, TokenEvent,
    platform_authenticator, platform_supported,
};
pub use cancel::CancelToken;

use thiserror::Error;

/// Everything that can go wrong between "ask the token" and "here is its
/// signature". Each variant is a different thing for a person to do, which
/// is why they are kept apart instead of folded into one string.
#[derive(Debug, Error)]
pub enum Error {
    /// This build has no way of reaching a token on this platform.
    #[error("native security-key signing is not available on {0}")]
    Unsupported(&'static str),
    /// No FIDO token is plugged in, or none would open.
    #[error("no security key found: {0}")]
    DeviceNotFound(String),
    /// The token is there but the exchange with it failed.
    #[error("security key communication failed: {0}")]
    Transport(String),
    /// The credential needs a PIN and nobody could be asked for one.
    #[error("the security key requires its PIN")]
    PinRequired,
    /// The token refused the PIN it was given.
    #[error("the security key rejected the PIN ({retries} attempts left)")]
    PinInvalid { retries: u32 },
    /// Too many wrong PINs: the token will not take another until it is
    /// reset (or, for a soft block, re-plugged).
    #[error("the security key's PIN is blocked; {0}")]
    PinBlocked(&'static str),
    /// The token has no PIN set, and this credential requires one.
    #[error("the security key has no PIN set, and this key requires user verification")]
    PinNotSet,
    /// Built-in verification (fingerprint) is locked out.
    #[error("the security key's user verification is blocked")]
    UserVerificationBlocked,
    /// No touch arrived in time.
    #[error("timed out waiting for a touch on the security key")]
    TouchTimeout,
    /// The request was cancelled, by the person or by the dial closing.
    #[error("the security key request was cancelled")]
    Cancelled,
    /// The token does not hold the credential the request named.
    #[error("the security key does not hold this credential")]
    CredentialNotFound,
    /// The token cannot do what this credential asks of it (a U2F-only
    /// token has no user verification).
    #[error("the security key cannot do this: {0}")]
    UnsupportedByToken(&'static str),
    /// Something we sent or received does not parse.
    #[error("malformed security-key exchange: {0}")]
    Malformed(String),
}
