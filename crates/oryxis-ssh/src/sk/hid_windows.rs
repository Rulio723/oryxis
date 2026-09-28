//! The Windows half of the token transport: CTAP2 over USB HID.
//!
//! No C dependency. `libfido2` would be the obvious building block, but
//! it is a C library that would need a toolchain and a shipping story on
//! every platform Oryxis builds for; the FIDO HID interface is a plain
//! interrupt endpoint pair, and Windows already exposes it through
//! SetupAPI + `hid.dll`, both of which `windows-sys` binds directly.
//!
//! Overlapped I/O rather than a blocking `ReadFile` on a helper thread:
//! the token sends `CTAPHID_KEEPALIVE` while it waits for a touch, and we
//! need to be able to give up on our own clock (and `CancelIoEx` the
//! request) instead of leaving a read outstanding on a device that may
//! already be unplugged.
//!
//! ## Not the Windows transport any more
//!
//! [`super::webauthn_windows`] is what Windows uses. Since Windows 10 1903
//! a non-elevated process cannot open a FIDO device's HID interface at
//! all, so this path only ever runs from an elevated shell — which is why
//! it is now the fallback rather than the front door.
//!
//! ## Multi-packet interoperability
//!
//! Measured against one physical token, before the WebAuthn transport
//! existed:
//!
//! - Single-packet `getAssertion` requests are accepted. Shortening the
//!   request until it fits in one 57-byte initial packet — dropping the
//!   allow-list, or the options map, or both — gets `0x2e`
//!   (`NO_CREDENTIALS`) rather than a complaint, which is the token saying
//!   it read and understood the request and simply found nothing matching.
//! - Requests containing an allow-list originally came back `0x11`
//!   (`CBOR_UNEXPECTED_TYPE`). Those requests also happened to require a
//!   continuation packet because an OpenSSH credential handle is large.
//! - `CTAPHID_PING` sent through the very same `send` is echoed back
//!   byte-for-byte at 70, 100 and 195 bytes — so the framing, the sequence
//!   numbers and the packet count are all right.
//! - Pacing the continuation packets changed nothing.
//!
//! The shared feature was the allow-list, not fragmentation: its nested
//! `PublicKeyCredentialDescriptor` had incorrectly used integer keys instead
//! of the WebAuthn text keys `"type"` and `"id"`. Correcting those keys fixes
//! the direct-HID request without any transport delay. This path is used by
//! elevated processes, while ordinary Windows launches use the WebAuthn API.

use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO, SP_DEVICE_INTERFACE_DATA,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces,
    SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
};
use windows_sys::Win32::Devices::HumanInterfaceDevice::{
    HIDP_CAPS, HidD_FreePreparsedData, HidD_GetHidGuid, HidD_GetPreparsedData, HidP_GetCaps,
    PHIDP_PREPARSED_DATA,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, NTSTATUS, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile,
    WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use super::SkError;
use super::authenticator::{Assertion, AssertionRequest, SkAuthenticator};
use super::ctap::{self, HID_PACKET_LEN, HidTransport, TouchState};

/// The FIDO usage page and usage. This pair is what distinguishes the
/// security-key interface from the keyboard interface the same device
/// also presents, and it is the same discriminator OpenSSH's
/// `sk-usbhid.c` uses.
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE: u16 = 0x01;

/// `HIDP_STATUS_SUCCESS`. The HID parser reports NTSTATUS-style codes,
/// and success is not zero.
const HIDP_STATUS_SUCCESS: NTSTATUS = 0x0011_0000;

/// A `HDEVINFO` is an `isize` handle rather than a pointer, so it has
/// its own sentinel.
const INVALID_HDEVINFO: HDEVINFO = -1;

/// `ERROR_OPERATION_ABORTED`: a `CancelIoEx` we asked for, or a device
/// yanked mid-read. Either way, "nothing arrived".
const ERROR_OPERATION_ABORTED: u32 = 995;

/// How long a touch may take before the attempt is abandoned. OpenSSH
/// waits forever; an SSH client with a connection to keep alive should
/// not, and the user can simply try again.
const DEFAULT_TOUCH_TIMEOUT: Duration = Duration::from_secs(120);

/// Signs with whatever FIDO2 token is plugged in.
pub(crate) struct WindowsHidAuthenticator {
    touch_timeout: Duration,
    /// Told when the token starts waiting for a touch, so a caller can
    /// put "touch your key" on screen without the SSH task blocking.
    progress: Option<Arc<dyn Fn(TouchState) + Send + Sync>>,
}

impl Default for WindowsHidAuthenticator {
    fn default() -> Self {
        Self {
            touch_timeout: DEFAULT_TOUCH_TIMEOUT,
            progress: None,
        }
    }
}

impl WindowsHidAuthenticator {
    #[allow(dead_code)] // Wired up when the UI grows a touch hint.
    pub(crate) fn with_progress(mut self, progress: Arc<dyn Fn(TouchState) + Send + Sync>) -> Self {
        self.progress = Some(progress);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_touch_timeout(mut self, timeout: Duration) -> Self {
        self.touch_timeout = timeout;
        self
    }
}

impl SkAuthenticator for WindowsHidAuthenticator {
    fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, SkError> {
        let progress = self.progress.clone();
        let mut report = move |state| {
            if let Some(progress) = &progress {
                progress(state);
            } else {
                tracing::info!(
                    "security key is waiting for {}",
                    match state {
                        TouchState::WaitingForTouch => "a touch",
                        TouchState::WaitingForVerification => "user verification",
                    }
                );
            }
        };

        let mut device = open_first()?;
        ctap::get_assertion(&mut device, request, self.touch_timeout, &mut report)
    }
}

/// Open the first FIDO interface that will have us. More than one token
/// can be plugged in, and one of them can be busy with another
/// application, so one refusal is not the end of the search — but the
/// reason the last one gave is, because "no key found" is the wrong thing
/// to say when the key was found and would not open.
fn open_first() -> Result<HidDevice, SkError> {
    let mut last_error = None;
    for path in fido_interfaces()? {
        match HidDevice::open(&path) {
            Ok(device) => return Ok(device),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error
        .unwrap_or_else(|| SkError::DeviceNotFound("no FIDO security key is plugged in".into())))
}

/// Every HID interface on the machine that is a FIDO token, as
/// NUL-terminated UTF-16 device paths.
fn fido_interfaces() -> Result<Vec<Vec<u16>>, SkError> {
    let interfaces = hid_interface_paths()?;
    tracing::debug!(count = interfaces.len(), "HID interfaces present");
    let fido: Vec<Vec<u16>> = interfaces
        .into_iter()
        .filter(|path| is_fido_interface(path))
        .collect();
    if fido.is_empty() {
        return Err(SkError::DeviceNotFound(
            "no FIDO security key is plugged in".into(),
        ));
    }
    tracing::debug!(count = fido.len(), "FIDO interfaces found");
    Ok(fido)
}

/// Every HID interface currently present, as NUL-terminated UTF-16 paths.
fn hid_interface_paths() -> Result<Vec<Vec<u16>>, SkError> {
    let mut paths = Vec::new();
    unsafe {
        let mut guid = std::mem::zeroed();
        HidD_GetHidGuid(&mut guid);

        let set = SetupDiGetClassDevsW(
            &guid,
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        if set == INVALID_HDEVINFO {
            return Err(SkError::Transport(format!(
                "SetupDiGetClassDevs failed (win32 {})",
                GetLastError()
            )));
        }
        // The info set is a kernel handle; release it on every path out.
        let _guard = DeviceInfoSet(set);

        let mut index = 0u32;
        loop {
            let mut interface: SP_DEVICE_INTERFACE_DATA = std::mem::zeroed();
            interface.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
            if SetupDiEnumDeviceInterfaces(set, std::ptr::null(), &guid, index, &mut interface) == 0
            {
                // ERROR_NO_MORE_ITEMS is the normal end of the walk.
                break;
            }
            index += 1;

            // First call sizes the detail buffer; the second fills it.
            let mut required = 0u32;
            SetupDiGetDeviceInterfaceDetailW(
                set,
                &interface,
                std::ptr::null_mut(),
                0,
                &mut required,
                std::ptr::null_mut(),
            );
            if required == 0 {
                continue;
            }

            let mut buffer = vec![0u8; required as usize];
            let detail = buffer.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
            (*detail).cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
            if SetupDiGetDeviceInterfaceDetailW(
                set,
                &interface,
                detail,
                required,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                continue;
            }

            // `DevicePath` is the first element of a variable-length
            // array; the string runs to the NUL.
            let start = std::ptr::addr_of!((*detail).DevicePath) as *const u16;
            let mut len = 0usize;
            while *start.add(len) != 0 {
                len += 1;
            }
            let path = std::slice::from_raw_parts(start, len + 1).to_vec();
            paths.push(path);
        }
    }
    Ok(paths)
}

/// Releases a SetupAPI info set, however the walk ends.
struct DeviceInfoSet(HDEVINFO);

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

/// Whether this HID interface is the FIDO one. Probing opens the device,
/// which is why the path is checked before it is used for real.
fn is_fido_interface(path: &[u16]) -> bool {
    let name = String::from_utf16_lossy(&path[..path.len().saturating_sub(1)]);
    unsafe {
        let handle = match open_hid(path) {
            Ok(handle) => handle,
            Err(win32) => {
                tracing::debug!(%name, win32, "HID interface will not open");
                return false;
            }
        };
        let _guard = OwnedHandle(handle);

        let mut preparsed: PHIDP_PREPARSED_DATA = 0;
        if !HidD_GetPreparsedData(handle, &mut preparsed) {
            tracing::debug!(%name, win32 = GetLastError(), "no preparsed HID data");
            return false;
        }
        let mut caps: HIDP_CAPS = std::mem::zeroed();
        let status = HidP_GetCaps(preparsed, &mut caps);
        HidD_FreePreparsedData(preparsed);
        let fido = status == HIDP_STATUS_SUCCESS
            && caps.UsagePage == FIDO_USAGE_PAGE
            && caps.Usage == FIDO_USAGE;
        tracing::debug!(
            %name,
            status = format!("0x{status:08x}"),
            usage_page = format!("0x{:04x}", caps.UsagePage),
            usage = format!("0x{:02x}", caps.Usage),
            fido,
            "HID interface capabilities"
        );
        fido
    }
}

/// Open a HID interface. CTAP needs both directions, so read+write is
/// what is asked for; the Win32 error comes back so a caller can say
/// *why* a token was not usable instead of just "not found".
fn open_hid(path: &[u16]) -> Result<HANDLE, u32> {
    unsafe {
        let handle = CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            Err(GetLastError())
        } else {
            Ok(handle)
        }
    }
}

/// Closes a raw handle, however the scope ends.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// An open CTAPHID channel to one token.
struct HidDevice {
    handle: HANDLE,
    event: HANDLE,
    overlapped: OVERLAPPED,
    buffer: Vec<u8>,
    /// Whether the OS puts a report-id byte in front of every report.
    /// `HIDP_CAPS` answers with the byte length, and 65 vs 64 is the
    /// only reliable way to know.
    report_id_prefix: bool,
}

impl HidDevice {
    fn open(path: &[u16]) -> Result<Self, SkError> {
        unsafe {
            let handle = CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(SkError::DeviceNotFound(format!(
                    "could not open the security key (win32 {})",
                    GetLastError()
                )));
            }
            let handle = OwnedHandle(handle);

            let mut preparsed: PHIDP_PREPARSED_DATA = 0;
            if !HidD_GetPreparsedData(handle.0, &mut preparsed) {
                return Err(SkError::Transport(
                    "the security key exposed no HID capabilities".into(),
                ));
            }
            let mut caps: HIDP_CAPS = std::mem::zeroed();
            let status = HidP_GetCaps(preparsed, &mut caps);
            HidD_FreePreparsedData(preparsed);
            if status != HIDP_STATUS_SUCCESS {
                return Err(SkError::Transport(format!(
                    "HidP_GetCaps failed (status 0x{status:08x})"
                )));
            }
            let input_len = caps.InputReportByteLength as usize;
            if input_len < HID_PACKET_LEN {
                return Err(SkError::Transport(format!(
                    "the security key's HID reports are {input_len} bytes, \
                     too small for CTAPHID"
                )));
            }
            tracing::debug!(
                input = caps.InputReportByteLength,
                output = caps.OutputReportByteLength,
                feature = caps.FeatureReportByteLength,
                prefix = input_len > HID_PACKET_LEN,
                "security key HID report sizes"
            );

            let event = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
            if event.is_null() {
                return Err(SkError::Transport(format!(
                    "could not create an I/O event (win32 {})",
                    GetLastError()
                )));
            }

            // Keep the raw handle alive in the struct; the guard above
            // would close it on the way out, so hand it over explicitly.
            let raw = handle.0;
            std::mem::forget(handle);

            let mut device = Self {
                handle: raw,
                event,
                overlapped: std::mem::zeroed(),
                buffer: vec![0u8; input_len],
                report_id_prefix: input_len > HID_PACKET_LEN,
            };
            device.overlapped.hEvent = event;
            Ok(device)
        }
    }

    /// Run one overlapped operation to completion within `timeout`.
    ///
    /// Returns `Ok(true)` when the operation finished, `Ok(false)` when
    /// it was cancelled on timeout (and drained), `Err` for a real
    /// failure. Draining matters: leaving a cancelled I/O pending would
    /// make the *next* operation on this handle fail with
    /// `ERROR_OPERATION_ABORTED`.
    unsafe fn complete(
        &mut self,
        started: bool,
        timeout: Duration,
        transferred: &mut u32,
    ) -> Result<bool, SkError> {
        if started {
            // Completed synchronously.
            return Ok(true);
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            return Err(SkError::Transport(format!(
                "the security key rejected an I/O request (win32 {error})"
            )));
        }
        let millis = timeout.as_millis().min(u32::MAX as u128) as u32;
        match unsafe { WaitForSingleObject(self.event, millis) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                unsafe {
                    CancelIoEx(self.handle, &self.overlapped);
                    // Reap the cancellation so the channel is usable again.
                    GetOverlappedResult(self.handle, &self.overlapped, transferred, 1);
                }
                return Ok(false);
            }
            other => {
                return Err(SkError::Transport(format!(
                    "waiting on the security key failed (wait status 0x{other:08x})"
                )));
            }
        }
        if unsafe { GetOverlappedResult(self.handle, &self.overlapped, transferred, 0) } == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_OPERATION_ABORTED {
                return Ok(false);
            }
            return Err(SkError::Transport(format!(
                "the security key's I/O did not complete (win32 {error})"
            )));
        }
        Ok(true)
    }
}

impl Drop for HidDevice {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
            CloseHandle(self.event);
        }
    }
}

impl HidTransport for HidDevice {
    fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), SkError> {
        // A device that numbers its reports wants the report id first.
        let mut out = Vec::with_capacity(HID_PACKET_LEN + 1);
        if self.report_id_prefix {
            out.push(0);
        }
        out.extend_from_slice(packet);
        tracing::debug!(
            len = out.len(),
            prefix = self.report_id_prefix,
            head = ?&out[..out.len().min(16)],
            "HID write"
        );

        let mut written = 0u32;
        let started = unsafe {
            WriteFile(
                self.handle,
                out.as_ptr(),
                out.len() as u32,
                &mut written,
                &mut self.overlapped,
            )
        } != 0;
        // A HID write is expected to complete promptly; a token that has
        // gone away fails here rather than hanging.
        match unsafe { self.complete(started, Duration::from_secs(2), &mut written)? } {
            true => Ok(()),
            false => Err(SkError::Transport(
                "the security key did not accept a write; it may have been removed".into(),
            )),
        }
    }

    fn read_packet(&mut self, timeout: Duration) -> Result<Option<[u8; HID_PACKET_LEN]>, SkError> {
        let mut read = 0u32;
        let started = unsafe {
            ReadFile(
                self.handle,
                self.buffer.as_mut_ptr(),
                self.buffer.len() as u32,
                &mut read,
                &mut self.overlapped,
            )
        } != 0;
        if !unsafe { self.complete(started, timeout, &mut read)? } {
            return Ok(None);
        }

        let read = read as usize;
        tracing::debug!(
            read,
            head = ?&self.buffer[..read.min(16)],
            "HID read"
        );
        if read == 0 {
            return Ok(None);
        }
        let source = if self.report_id_prefix {
            &self.buffer[1..]
        } else {
            &self.buffer[..]
        };
        if source.len() < HID_PACKET_LEN {
            return Err(SkError::Transport(format!(
                "the security key returned a short report ({read} bytes)"
            )));
        }
        let mut packet = [0u8; HID_PACKET_LEN];
        packet.copy_from_slice(&source[..HID_PACKET_LEN]);
        Ok(Some(packet))
    }
}
