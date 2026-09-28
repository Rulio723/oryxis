//! The token itself, behind a trait.
//!
//! Every implementation is blocking I/O — a USB round trip, then a human
//! pressing a button — so the trait is synchronous and the caller runs it
//! on a blocking task. That split is what keeps "touch your key" from
//! freezing the interface: the UI thread is never the one waiting.

use std::sync::Arc;

use super::SkError;

/// One `authenticatorGetAssertion` request, already reduced to what the
/// token needs (the caller has done the hashing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionRequest {
    /// FIDO2 relying-party id: the SSH application string ("ssh:").
    pub application: String,
    /// The bytes the signature has to cover — OpenSSH's userauth blob,
    /// `session_id || SSH_MSG_USERAUTH_REQUEST ...`.
    ///
    /// The message is carried rather than a hash of it because the two
    /// transports want different things from it. CTAP2 takes
    /// `SHA256(message)` as its "client data hash"; the WebAuthn API hashes
    /// whatever it is handed, so it needs the bytes themselves. Storing the
    /// hash would suit CTAP2 and quietly make WebAuthn sign a hash of a
    /// hash — a signature the server rejects for reasons invisible from
    /// here.
    pub message: Vec<u8>,
    /// The credential handle, or `None` for a discoverable credential
    /// (a resident key, whose handle is empty).
    pub key_handle: Option<Vec<u8>>,
    /// Ask the token to require a touch.
    pub require_user_presence: bool,
    /// Ask the token to require user verification (PIN/biometric).
    pub require_user_verification: bool,
    /// The PIN, when the user's key was made with `-O verify-required`.
    pub pin: Option<String>,
}

/// What the token answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// The raw Ed25519 signature (64 bytes).
    pub signature: Vec<u8>,
    /// The `authenticatorData` flags byte: bit 0 user present, bit 2 user
    /// verified. Goes into the signature blob verbatim — OpenSSH hashes
    /// this same byte into the signed string, so it cannot be rewritten
    /// to something prettier.
    pub flags: u8,
    /// The token's signature counter, echoed into the blob.
    pub counter: u32,
}

/// A FIDO2 authenticator that can produce an assertion for a credential
/// it holds.
pub trait SkAuthenticator: Send + Sync {
    fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, SkError>;
}

/// The authenticator for the running platform.
///
/// A normal Windows process uses Windows Hello because Windows blocks raw
/// access to FIDO HID interfaces without elevation. An elevated process can
/// drive HID directly, avoiding the Windows Security picker and asking only
/// for the token touch. Older Windows falls back to HID as well; every other
/// platform returns an authenticator whose error names the situation.
pub fn platform_authenticator() -> Arc<dyn SkAuthenticator> {
    #[cfg(target_os = "windows")]
    {
        match process_is_elevated() {
            Ok(true) => {
                tracing::debug!("elevated process: using direct USB HID for the security key");
                return Arc::new(super::hid_windows::WindowsHidAuthenticator::default());
            }
            Ok(false) => {}
            Err(error) => {
                // A failed token query must not make an ordinary launch try
                // a transport Windows will deny. WebAuthn is the safe path.
                tracing::warn!(%error, "could not determine process elevation; using Windows Hello");
            }
        }
        if super::webauthn_windows::is_available() {
            return Arc::new(super::webauthn_windows::WindowsWebAuthnAuthenticator::default());
        }
        tracing::debug!("Windows Hello is unavailable; falling back to direct USB HID");
        Arc::new(super::hid_windows::WindowsHidAuthenticator::default())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Arc::new(UnsupportedPlatform)
    }
}

/// Whether the current Windows token is elevated. Kept here rather than in
/// the app so every caller of the SSH crate gets the same transport choice.
#[cfg(target_os = "windows")]
fn process_is_elevated() -> std::io::Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            std::ptr::addr_of_mut!(elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let error = if result == 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        CloseHandle(token);
        match error {
            Some(error) => Err(error),
            None => Ok(elevation.TokenIsElevated != 0),
        }
    }
}

/// Everywhere but Windows. The SSH half of this module is portable; the
/// token transport is not — macOS and Linux would go through `libfido2`
/// (or the platform's own WebAuthn API), which is a dependency Oryxis
/// does not carry today.
#[cfg(not(target_os = "windows"))]
#[derive(Debug, Default)]
struct UnsupportedPlatform;

#[cfg(not(target_os = "windows"))]
impl SkAuthenticator for UnsupportedPlatform {
    fn get_assertion(&self, _request: &AssertionRequest) -> Result<Assertion, SkError> {
        Err(SkError::DeviceNotFound(format!(
            "native security-key signing is implemented for Windows only so far; \
             this build runs on {}",
            std::env::consts::OS
        )))
    }
}
