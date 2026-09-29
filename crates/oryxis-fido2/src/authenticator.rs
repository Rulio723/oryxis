//! The token, behind a trait, and the one choice of how to reach it.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{CancelToken, Error};

/// One `authenticatorGetAssertion`, already reduced to what a token needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionRequest {
    /// FIDO2 relying-party id.
    pub application: String,
    /// The bytes the assertion covers, NOT their hash.
    ///
    /// The two transports want different things from them: CTAP2 takes
    /// `SHA256(message)` as its client data hash, while Windows Hello
    /// hashes whatever it is handed. Carrying the hash would suit CTAP2
    /// and quietly make Windows Hello sign a hash of a hash.
    pub message: Vec<u8>,
    /// The credential to use. `None` asks the token to pick a
    /// discoverable credential for this relying party itself, which is
    /// only right when the caller has no handle at all: with several
    /// resident credentials the token answers with whichever it likes.
    pub allow_credential: Option<Vec<u8>>,
    /// Ask for a touch.
    pub user_presence: bool,
    /// Ask for user verification (PIN or built-in biometric).
    pub user_verification: bool,
}

/// What the token answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// The raw signature: 64 bytes for Ed25519, DER for ECDSA.
    pub signature: Vec<u8>,
    /// The `authenticatorData` flags byte (bit 0 user present, bit 2
    /// user verified), verbatim: a verifier hashes this same byte.
    pub flags: u8,
    /// The token's signature counter.
    pub counter: u32,
}

/// Something the token is waiting on a person for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEvent {
    /// Touch the key.
    TouchNeeded,
    /// Verify on the key itself (fingerprint).
    VerificationNeeded,
}

/// A request for the token's PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinPrompt {
    /// Attempts left before the token blocks its PIN, when it said.
    pub retries: Option<u32>,
    /// The previous PIN was refused; this is a second ask.
    pub retry: bool,
}

/// Answers a [`PinPrompt`] with the PIN, or `None` when the person
/// declined. Called on the transport's blocking thread.
pub type PinSource = Arc<dyn Fn(PinPrompt) -> Option<Zeroizing<String>> + Send + Sync>;

/// Everything a request needs from the person driving it.
#[derive(Clone, Default)]
pub struct Interaction {
    /// Stops the request.
    pub cancel: CancelToken,
    /// Told when the token starts waiting for a person.
    pub events: Option<Arc<dyn Fn(TokenEvent) + Send + Sync>>,
    /// Asked for the PIN when the credential needs one. `None` turns a
    /// PIN-protected credential into [`Error::PinRequired`].
    pub pin: Option<PinSource>,
}

impl std::fmt::Debug for Interaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interaction")
            .field("cancel", &self.cancel)
            .field("events", &self.events.is_some())
            .field("pin", &self.pin.is_some())
            .finish()
    }
}

impl Interaction {
    pub(crate) fn event(&self, event: TokenEvent) {
        match &self.events {
            Some(events) => events(event),
            None => tracing::info!(?event, "security key is waiting"),
        }
    }
}

/// A FIDO2 authenticator that can produce an assertion. Blocking.
pub trait Authenticator: Send + Sync {
    fn get_assertion(
        &self,
        request: &AssertionRequest,
        interaction: &Interaction,
    ) -> Result<Assertion, Error>;
}

/// Whether this build can reach a token on this platform at all.
///
/// The UI reads this to decide whether to offer native signing, so it
/// must be exactly the set [`platform_authenticator`] can serve.
pub const fn platform_supported() -> bool {
    cfg!(any(windows, target_os = "linux"))
}

/// The authenticator for the running platform.
///
/// On Windows an ordinary process goes through Windows Hello, because
/// since Windows 10 1903 only an elevated process may open a FIDO HID
/// interface. An elevated one drives HID directly, which also avoids the
/// Windows Security picker; a Windows without `webauthn.dll` falls back to
/// HID too. Linux reads `/dev/hidraw*`.
pub fn platform_authenticator() -> Arc<dyn Authenticator> {
    #[cfg(windows)]
    {
        match process_is_elevated() {
            Ok(true) => {
                tracing::debug!("elevated process: using direct USB HID for the security key");
                return Arc::new(crate::hid_windows::WindowsHidAuthenticator);
            }
            Ok(false) => {}
            Err(error) => {
                // A failed query must not send an ordinary launch to a
                // transport Windows will refuse. Windows Hello is safe.
                tracing::warn!(%error, "could not determine process elevation; using Windows Hello");
            }
        }
        if crate::webauthn_windows::is_available() {
            return Arc::new(crate::webauthn_windows::WindowsWebAuthnAuthenticator::default());
        }
        tracing::debug!("Windows Hello is unavailable; falling back to direct USB HID");
        Arc::new(crate::hid_windows::WindowsHidAuthenticator)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(crate::hid_linux::LinuxHidAuthenticator)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Arc::new(Unsupported)
    }
}

/// Whether the current Windows token is elevated.
#[cfg(windows)]
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
        let error = (result == 0).then(std::io::Error::last_os_error);
        CloseHandle(token);
        match error {
            Some(error) => Err(error),
            None => Ok(elevation.TokenIsElevated != 0),
        }
    }
}

/// Every platform without a transport (macOS today: IOKit HID is where a
/// third one would go). Names the platform instead of "not found", so the
/// failure reads as a missing feature rather than a missing key.
#[cfg(not(any(windows, target_os = "linux")))]
struct Unsupported;

#[cfg(not(any(windows, target_os = "linux")))]
impl Authenticator for Unsupported {
    fn get_assertion(&self, _: &AssertionRequest, _: &Interaction) -> Result<Assertion, Error> {
        Err(Error::Unsupported(std::env::consts::OS))
    }
}
