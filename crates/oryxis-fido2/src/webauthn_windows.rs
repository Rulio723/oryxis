//! Windows Hello, as the transport for security-key signing.
//!
//! `hid_windows` drives the token over USB HID directly. On Windows that
//! is a dead end for a program the user merely double-clicks: since
//! Windows 10 1903 a non-elevated process cannot open a FIDO device's HID
//! interface at all (`CreateFileW` answers `ERROR_ACCESS_DENIED` before a
//! single CTAP byte is exchanged). Every
//! tool that talks to a security key on Windows therefore either asks to
//! be run as administrator or goes through the WebAuthn API. This module
//! is the second: it is what browsers use, it is what Microsoft's own
//! OpenSSH uses, and it needs no elevation.
//!
//! It is a good fit beyond the permission problem. We hand the API the
//! userauth blob, it hands back `authenticatorData` and a signature, and
//! the two things the SSH blob needs (the flags byte and the signature
//! counter) sit at fixed offsets inside that data, the same two offsets
//! OpenSSH's `sk-usbhid.c` reads.
//!
//! ## The client data has to be the message, not its hash
//!
//! `WebAuthnAuthenticatorGetAssertion` hashes the bytes it is given and
//! passes *that* to the token as `clientDataHash`. OpenSSH's signature
//! covers `SHA256(application) || flags || counter || SHA256(message)`,
//! so what we hand over must be `message` itself. Handing over
//! `SHA256(message)` would sign a hash of a hash: a well-formed signature
//! that no server would ever accept, and one that fails for reasons
//! invisible from this side of the wire.
//!
//! ## What this costs, and what it gives
//!
//! The API always involves a human (it raises the Windows Security dialog
//! and waits for a touch), so a `no-touch-required` credential still gets
//! a prompt. In exchange it owns user verification: a `verify-required`
//! key has its PIN (or Windows Hello biometric) collected by that same
//! dialog, so the app's own PIN prompt never runs on this path.
//!
//! The call is cancelled by id (`WebAuthNGetCancellationId` before it,
//! `WebAuthNCancelCurrentOperation` from another thread), which is what
//! takes the dialog down when the dial that raised it is abandoned.

use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Duration;

use windows_sys::Win32::Foundation::{FARPROC, HWND};
use windows_sys::core::GUID;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

use crate::authenticator::{Assertion, AssertionRequest, Authenticator, Interaction, TokenEvent};
use crate::Error;

/// How long a touch may take. Matches the HID transport's budget.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

// Struct versions and enum values, from the Windows SDK's `webauthn.h`.
//
// The options struct version is the interesting one. Later SDKs define
// higher versions for features this module does not use (large blobs and
// beyond), and older builds of the API reject a version they do not know.
// Version 3 is the oldest that carries `pCancellationId`, the one field
// past version 1 this module needs (`dwUserVerificationRequirement` is in
// version 1 already).
const CLIENT_DATA_VERSION: u32 = 1;
const CREDENTIAL_VERSION: u32 = 1;
const ASSERTION_OPTIONS_VERSION: u32 = 3;
const AUTHENTICATOR_ATTACHMENT_ANY: u32 = 0;
const USER_VERIFICATION_REQUIREMENT_REQUIRED: u32 = 1;
const USER_VERIFICATION_REQUIREMENT_DISCOURAGED: u32 = 3;

/// `WEBAUTHN_HASH_ALGORITHM_SHA_256`, NUL-terminated.
const HASH_ALGORITHM: &[u16] = &[b'S' as u16, b'H' as u16, b'A' as u16, b'-' as u16,
    b'2' as u16, b'5' as u16, b'6' as u16, 0];
/// `WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY`, NUL-terminated.
const PUBLIC_KEY_TYPE: &[u16] = &[b'p' as u16, b'u' as u16, b'b' as u16, b'l' as u16,
    b'i' as u16, b'c' as u16, b'-' as u16, b'k' as u16, b'e' as u16, b'y' as u16, 0];

#[repr(C)]
struct WebAuthnClientData {
    version: u32,
    cb_client_data_json: u32,
    pb_client_data_json: *mut u8,
    hash_alg_id: *const u16,
}

#[repr(C)]
struct WebAuthnCredential {
    version: u32,
    cb_id: u32,
    pb_id: *mut u8,
    credential_type: *const u16,
}

#[repr(C)]
struct WebAuthnCredentials {
    count: u32,
    credentials: *mut WebAuthnCredential,
}

#[repr(C)]
struct WebAuthnExtensions {
    count: u32,
    extensions: *mut c_void,
}

#[repr(C)]
struct WebAuthnAssertionOptions {
    version: u32,
    timeout_ms: u32,
    credential_list: WebAuthnCredentials,
    extensions: WebAuthnExtensions,
    authenticator_attachment: u32,
    user_verification_requirement: u32,
    flags: u32,
    u2f_app_id: *const u16,
    pb_u2f_app_id: *mut i32,
    cancellation_id: *mut GUID,
    allow_credential_list: *mut c_void,
    cred_large_blob_operation: u32,
    cb_cred_large_blob: u32,
    pb_cred_large_blob: *mut u8,
}

#[repr(C)]
struct WebAuthnAssertion {
    version: u32,
    cb_authenticator_data: u32,
    pb_authenticator_data: *mut u8,
    cb_signature: u32,
    pb_signature: *mut u8,
    credential: WebAuthnCredential,
    cb_user_id: u32,
    pb_user_id: *mut u8,
    extensions: WebAuthnExtensions,
    cb_cred_large_blob: u32,
    pb_cred_large_blob: *mut u8,
    cred_large_blob_status: u32,
}

type GetAssertionFn = unsafe extern "system" fn(
    hwnd: HWND,
    rp_id: *const u16,
    client_data: *const WebAuthnClientData,
    options: *const WebAuthnAssertionOptions,
    assertion: *mut *mut WebAuthnAssertion,
) -> i32;

type FreeAssertionFn = unsafe extern "system" fn(assertion: *mut WebAuthnAssertion);

type ErrorNameFn = unsafe extern "system" fn(hr: i32) -> *const u16;

type GetCancellationIdFn = unsafe extern "system" fn(id: *mut GUID) -> i32;

type CancelOperationFn = unsafe extern "system" fn(id: *const GUID) -> i32;

/// The `webauthn.dll` entry points we need, resolved once.
struct WebAuthnApi {
    get_assertion: GetAssertionFn,
    free_assertion: FreeAssertionFn,
    error_name: ErrorNameFn,
    /// Optional: a `webauthn.dll` without them still signs, it just cannot
    /// be interrupted, and the dialog stays until its own timeout.
    cancellation: Option<(GetCancellationIdFn, CancelOperationFn)>,
}

// The function pointers come from a system DLL that is never unloaded, so
// they are good for the life of the process.
unsafe impl Send for WebAuthnApi {}
unsafe impl Sync for WebAuthnApi {}

/// Resolve `webauthn.dll`, or `None` on a machine that has no such thing
/// (pre-1903 Windows). Loaded rather than linked so that absence is a
/// fallback instead of a program that will not start.
fn api() -> Option<&'static WebAuthnApi> {
    static API: OnceLock<Option<WebAuthnApi>> = OnceLock::new();
    API.get_or_init(|| unsafe {
        let name: Vec<u16> = "webauthn.dll\0".encode_utf16().collect();
        let module = LoadLibraryW(name.as_ptr());
        if module.is_null() {
            tracing::debug!("webauthn.dll is not present; Windows Hello is unavailable");
            return None;
        }
        // The module is deliberately never freed: it is a system library
        // and its function pointers have to outlive every caller.
        //
        // `GetProcAddress` hands back an untyped pointer, so only the
        // symbol name says what the type is; the annotations on these
        // bindings are the whole of the safety argument, and they are
        // spelled out rather than inferred for that reason.
        let get_assertion: GetAssertionFn =
            std::mem::transmute(resolve(module, c"WebAuthNAuthenticatorGetAssertion")?);
        let free_assertion: FreeAssertionFn =
            std::mem::transmute(resolve(module, c"WebAuthNFreeAssertion")?);
        let error_name: ErrorNameFn =
            std::mem::transmute(resolve(module, c"WebAuthNGetErrorName")?);
        let cancellation = (|| {
            let get_id: GetCancellationIdFn =
                std::mem::transmute(resolve(module, c"WebAuthNGetCancellationId")?);
            let cancel: CancelOperationFn =
                std::mem::transmute(resolve(module, c"WebAuthNCancelCurrentOperation")?);
            Some((get_id, cancel))
        })();
        Some(WebAuthnApi {
            get_assertion,
            free_assertion,
            error_name,
            cancellation,
        })
    })
    .as_ref()
}

/// Look one symbol up, complaining once if the DLL is older than we need.
unsafe fn resolve(module: *mut c_void, symbol: &std::ffi::CStr) -> FARPROC {
    let found = unsafe { GetProcAddress(module, symbol.as_ptr().cast()) };
    if found.is_none() {
        tracing::debug!(symbol = %symbol.to_string_lossy(), "webauthn.dll is missing a function");
    }
    found
}

/// Whether this machine can sign through Windows Hello at all. Used to
/// choose between transports before a token is ever touched.
pub(crate) fn is_available() -> bool {
    api().is_some()
}

/// Signs with a FIDO2 token through the Windows Hello API, which is
/// reachable without administrator rights.
pub(crate) struct WindowsWebAuthnAuthenticator {
    timeout: Duration,
}

impl Default for WindowsWebAuthnAuthenticator {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl Authenticator for WindowsWebAuthnAuthenticator {
    fn get_assertion(
        &self,
        request: &AssertionRequest,
        interaction: &Interaction,
    ) -> Result<Assertion, Error> {
        let api = api().ok_or_else(|| {
            Error::DeviceNotFound(
                "Windows Hello is not available on this system; \
                 Windows 10 1903 or newer is required"
                    .into(),
            )
        })?;
        if interaction.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let rp_id = wide(&request.application);

        // The bytes, not their hash: the API hashes what it is handed.
        let client_data = WebAuthnClientData {
            version: CLIENT_DATA_VERSION,
            cb_client_data_json: request.message.len() as u32,
            pb_client_data_json: request.message.as_ptr() as *mut u8,
            hash_alg_id: HASH_ALGORITHM.as_ptr(),
        };

        // No handle means "let the token pick a discoverable credential",
        // which the API is told with an empty list.
        let handle = request
            .allow_credential
            .as_deref()
            .filter(|handle| !handle.is_empty());
        let mut credential = WebAuthnCredential {
            version: CREDENTIAL_VERSION,
            cb_id: handle.map_or(0, <[u8]>::len) as u32,
            pb_id: handle.map_or(std::ptr::null_mut(), |handle| handle.as_ptr() as *mut u8),
            credential_type: PUBLIC_KEY_TYPE.as_ptr(),
        };
        let credential_list = WebAuthnCredentials {
            count: u32::from(handle.is_some()),
            credentials: if handle.is_some() {
                &mut credential
            } else {
                std::ptr::null_mut()
            },
        };

        // An id for this one call, and the hook that cancels it from
        // whichever thread gives up on it. The guard unregisters the hook
        // when the call returns, so a late cancel never reaches into an
        // operation that is over.
        let mut cancellation_id: GUID = unsafe { std::mem::zeroed() };
        let cancellable = api
            .cancellation
            .is_some_and(|(get_id, _)| unsafe { get_id(&mut cancellation_id) } >= 0);
        let _cancel_guard = api.cancellation.filter(|_| cancellable).map(|(_, cancel)| {
            let id = cancellation_id;
            interaction.cancel.on_cancel(Box::new(move || unsafe {
                cancel(&id);
            }))
        });
        if interaction.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let options = WebAuthnAssertionOptions {
            version: ASSERTION_OPTIONS_VERSION,
            timeout_ms: self.timeout.as_millis().min(u32::MAX as u128) as u32,
            credential_list,
            extensions: WebAuthnExtensions {
                count: 0,
                extensions: std::ptr::null_mut(),
            },
            authenticator_attachment: AUTHENTICATOR_ATTACHMENT_ANY,
            user_verification_requirement: if request.user_verification {
                USER_VERIFICATION_REQUIREMENT_REQUIRED
            } else {
                USER_VERIFICATION_REQUIREMENT_DISCOURAGED
            },
            flags: 0,
            u2f_app_id: std::ptr::null(),
            pb_u2f_app_id: std::ptr::null_mut(),
            cancellation_id: if cancellable {
                &mut cancellation_id
            } else {
                std::ptr::null_mut()
            },
            allow_credential_list: std::ptr::null_mut(),
            cred_large_blob_operation: 0,
            cb_cred_large_blob: 0,
            pb_cred_large_blob: std::ptr::null_mut(),
        };

        // The dialog IS the touch prompt; say so to whoever is showing the
        // connect card, before the call blocks on it.
        interaction.event(if request.user_verification {
            TokenEvent::VerificationNeeded
        } else {
            TokenEvent::TouchNeeded
        });

        let mut raw: *mut WebAuthnAssertion = std::ptr::null_mut();
        let hr = unsafe {
            (api.get_assertion)(
                // The security dialog is parented to whatever window is in
                // front, which is the best a library with no window of its
                // own can offer.
                GetForegroundWindow(),
                rp_id.as_ptr(),
                &client_data,
                &options,
                &mut raw,
            )
        };
        if hr < 0 {
            if interaction.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            return Err(map_hr(api, hr));
        }
        if raw.is_null() {
            // Success with nothing to show for it. Cannot be mapped through
            // the error name, because there is no error.
            return Err(Error::Malformed(
                "Windows Hello reported success but returned no assertion".into(),
            ));
        }

        let result = read_assertion(raw);
        // Owned by the API, and the only way to release it.
        unsafe { (api.free_assertion)(raw) };
        result
    }
}

/// Pull the flags and counter out of `authenticatorData` and hand back the
/// signature. Split out so the `free` happens on every path.
fn read_assertion(raw: *const WebAuthnAssertion) -> Result<Assertion, Error> {
    if raw.is_null() {
        return Err(Error::Malformed("the token returned no assertion".into()));
    }
    let assertion = unsafe { &*raw };
    let auth_data = copy_bytes(assertion.pb_authenticator_data, assertion.cb_authenticator_data);
    let signature = copy_bytes(assertion.pb_signature, assertion.cb_signature);

    // rpIdHash(32) || flags(1) || signCount(4). Anything shorter cannot be
    // an assertion, and indexing it would panic.
    if auth_data.len() < 37 {
        return Err(Error::Malformed(format!(
            "the token's authenticator data is {} bytes, too short to carry flags and a counter",
            auth_data.len()
        )));
    }
    Ok(Assertion {
        signature,
        flags: auth_data[32],
        counter: u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]),
    })
}

/// Copy out a `(pointer, length)` pair the API owns.
///
/// Through a `Vec` rather than `from_raw_parts`: the API leaves fields it
/// has nothing to say about as a null pointer with a zero length, and
/// `from_raw_parts(null, 0)` is undefined behaviour even though the slice
/// would be empty.
fn copy_bytes(pointer: *const u8, length: u32) -> Vec<u8> {
    if pointer.is_null() || length == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec()
}

/// Turn an `HRESULT` into something a person can act on. The API's own
/// names are the only stable thing here (the raw numbers are shared with
/// the NTE and Win32 ranges), so they are what the message is built from.
fn map_hr(api: &WebAuthnApi, hr: i32) -> Error {
    let name = unsafe {
        let pointer = (api.error_name)(hr);
        if pointer.is_null() {
            String::new()
        } else {
            let mut length = 0;
            while *pointer.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length))
        }
    };
    match name.as_str() {
        // The user closed the dialog, or a touch never came. Both are the
        // user's own doing and worth saying plainly rather than dressing
        // up as a device fault.
        "NotAllowedError" => Error::Cancelled,
        "AbortError" => Error::Cancelled,
        "TimeoutError" => Error::TouchTimeout,
        _ => Error::Transport(format!(
            "Windows Hello refused the request ({name}, hresult 0x{:08x})",
            hr as u32
        )),
    }
}

/// NUL-terminated UTF-16, the shape every `LPCWSTR` argument wants.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
