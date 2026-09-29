//! CTAP2 over USB HID on macOS, through IOKit.
//!
//! The same shape `libfido2`'s `hid_osx.c` has, which is what OpenSSH on
//! a Mac signs with: an `IOHIDManager` matched on the FIDO usage page
//! (`0xF1D0`, usage `0x01`), output reports written with
//! `IOHIDDeviceSetReport`, and input reports delivered to a callback that
//! only runs while this thread spins its run loop. The loop runs in a
//! mode of our own, so nothing else scheduled on the thread fires inside
//! a read, and each spin is bounded so the CTAP loop can notice a cancel.
//!
//! No entitlement is involved: the app is not sandboxed, and a FIDO
//! interface is not a keyboard, so the Input Monitoring consent that
//! guards keyboards does not apply to it.

use std::collections::VecDeque;
use std::ffi::{CStr, c_void};
use std::time::Duration;

use core_foundation_sys::base::{CFIndex, CFRelease, CFRetain, CFTypeRef, kCFAllocatorDefault};
use core_foundation_sys::dictionary::{
    CFDictionaryCreateMutable, CFDictionarySetValue, kCFTypeDictionaryKeyCallBacks,
    kCFTypeDictionaryValueCallBacks,
};
use core_foundation_sys::number::{CFNumberCreate, kCFNumberSInt32Type};
use core_foundation_sys::runloop::{CFRunLoopGetCurrent, CFRunLoopRunInMode};
use core_foundation_sys::set::{CFSetGetCount, CFSetGetValues};
use core_foundation_sys::string::{
    CFStringCreateWithCString, CFStringRef, kCFStringEncodingUTF8,
};
use io_kit_sys::hid::base::IOHIDDeviceRef;
use io_kit_sys::hid::device::{
    IOHIDDeviceClose, IOHIDDeviceOpen, IOHIDDeviceRegisterInputReportCallback,
    IOHIDDeviceScheduleWithRunLoop, IOHIDDeviceSetReport, IOHIDDeviceUnscheduleFromRunLoop,
};
use io_kit_sys::hid::keys::{
    IOHIDReportType, kIOHIDOptionsTypeNone, kIOHIDPrimaryUsageKey, kIOHIDPrimaryUsagePageKey,
    kIOHIDReportTypeOutput,
};
use io_kit_sys::hid::manager::{
    IOHIDManagerCopyDevices, IOHIDManagerCreate, IOHIDManagerRef, IOHIDManagerSetDeviceMatching,
};
use io_kit_sys::ret::{IOReturn, kIOReturnSuccess};

use crate::authenticator::{Assertion, AssertionRequest, Authenticator, Interaction};
use crate::ctap::{self, HID_PACKET_LEN, HidTransport};
use crate::Error;

const FIDO_USAGE_PAGE: i32 = 0xf1d0;
const FIDO_USAGE: i32 = 0x01;

/// Same budget as the other transports.
const DEFAULT_TOUCH_TIMEOUT: Duration = Duration::from_secs(120);

/// The run-loop mode our input callback is scheduled in.
const RUN_LOOP_MODE: &CStr = c"com.oryxis.fido2";

/// `kCFRunLoopRunFinished`: the mode has no sources left to run.
const RUN_FINISHED: i32 = 1;

/// Signs with whatever FIDO2 token is plugged in.
pub(crate) struct MacHidAuthenticator;

impl Authenticator for MacHidAuthenticator {
    fn get_assertion(
        &self,
        request: &AssertionRequest,
        interaction: &Interaction,
    ) -> Result<Assertion, Error> {
        let manager = Manager::matching_fido()?;
        let mut devices = manager.open_all()?;
        ctap::get_assertion_from(&mut devices, request, interaction, DEFAULT_TOUCH_TIMEOUT)
    }
}

/// An owned CoreFoundation reference, released on drop.
struct Owned(CFTypeRef);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

fn cf_string(text: &CStr) -> Owned {
    Owned(unsafe {
        CFStringCreateWithCString(kCFAllocatorDefault, text.as_ptr(), kCFStringEncodingUTF8)
    } as CFTypeRef)
}

fn cf_i32(value: i32) -> Owned {
    Owned(unsafe {
        CFNumberCreate(
            kCFAllocatorDefault,
            kCFNumberSInt32Type,
            (&value as *const i32).cast(),
        )
    } as CFTypeRef)
}

/// An `IOHIDManager` that sees only FIDO interfaces.
struct Manager(Owned);

impl Manager {
    fn matching_fido() -> Result<Self, Error> {
        unsafe {
            let manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
            if manager.is_null() {
                return Err(Error::DeviceNotFound("IOHIDManagerCreate failed".into()));
            }
            let manager = Owned(manager as CFTypeRef);

            let matching = Owned(CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                2,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            ) as CFTypeRef);
            let page_key = cf_string(CStr::from_ptr(kIOHIDPrimaryUsagePageKey));
            let usage_key = cf_string(CStr::from_ptr(kIOHIDPrimaryUsageKey));
            let page = cf_i32(FIDO_USAGE_PAGE);
            let usage = cf_i32(FIDO_USAGE);
            if matching.0.is_null()
                || page_key.0.is_null()
                || usage_key.0.is_null()
                || page.0.is_null()
                || usage.0.is_null()
            {
                return Err(Error::DeviceNotFound(
                    "could not build the FIDO HID matching dictionary".into(),
                ));
            }
            CFDictionarySetValue(matching.0 as _, page_key.0, page.0);
            CFDictionarySetValue(matching.0 as _, usage_key.0, usage.0);
            IOHIDManagerSetDeviceMatching(manager.0 as IOHIDManagerRef, matching.0 as _);
            Ok(Self(manager))
        }
    }

    /// Every FIDO device that will have us (the CTAP layer picks the one
    /// holding the credential), reporting the last refusal rather than "no
    /// key" when one was there and would not open.
    fn open_all(&self) -> Result<Vec<Box<dyn HidTransport>>, Error> {
        let devices = unsafe { IOHIDManagerCopyDevices(self.0.0 as IOHIDManagerRef) };
        if devices.is_null() {
            return Err(Error::DeviceNotFound(
                "no FIDO security key is plugged in".into(),
            ));
        }
        let devices = Owned(devices as CFTypeRef);
        let count = unsafe { CFSetGetCount(devices.0 as _) };
        if count <= 0 {
            return Err(Error::DeviceNotFound(
                "no FIDO security key is plugged in".into(),
            ));
        }
        let mut refs: Vec<*const c_void> = vec![std::ptr::null(); count as usize];
        unsafe { CFSetGetValues(devices.0 as _, refs.as_mut_ptr()) };
        let mut devices: Vec<Box<dyn HidTransport>> = Vec::new();
        let mut last_error = None;
        for device in refs {
            match MacHidDevice::open(device as IOHIDDeviceRef) {
                Ok(device) => devices.push(Box::new(device)),
                Err(e) => last_error = Some(e),
            }
        }
        if devices.is_empty() {
            return Err(last_error.expect("the set was not empty"));
        }
        Ok(devices)
    }
}

/// Where the input callback leaves reports until `read_packet` takes them.
/// Boxed so its address is stable for the callback's context pointer.
struct Inbox {
    /// The buffer IOKit writes each input report into before the callback.
    buffer: [u8; HID_PACKET_LEN],
    packets: VecDeque<[u8; HID_PACKET_LEN]>,
}

unsafe extern "C" fn on_input_report(
    context: *mut c_void,
    result: IOReturn,
    _sender: *mut c_void,
    _type: IOHIDReportType,
    _report_id: u32,
    report: *mut u8,
    length: CFIndex,
) {
    if result != kIOReturnSuccess || context.is_null() || report.is_null() {
        return;
    }
    // Copy out of IOKit's buffer BEFORE a reference to the inbox exists:
    // `report` points into `Inbox::buffer`, and reading through it after
    // forming `&mut Inbox` would alias that borrow.
    let length = (length.max(0) as usize).min(HID_PACKET_LEN);
    let mut packet = [0u8; HID_PACKET_LEN];
    unsafe { std::ptr::copy_nonoverlapping(report, packet.as_mut_ptr(), length) };
    // Runs on this same thread, inside `CFRunLoopRunInMode`, and only the
    // queue is touched, never the buffer.
    let packets = unsafe { &mut (*(context as *mut Inbox)).packets };
    packets.push_back(packet);
}

/// An open FIDO interface, scheduled on this thread's run loop.
struct MacHidDevice {
    device: IOHIDDeviceRef,
    mode: Owned,
    /// Owned through a raw pointer (from `Box::into_raw`, freed in `Drop`)
    /// because IOKit holds it as the callback's context: no `Box` or
    /// `&mut` may claim it exclusively while the callback can run.
    inbox: *mut Inbox,
}

impl MacHidDevice {
    fn open(device: IOHIDDeviceRef) -> Result<Self, Error> {
        unsafe {
            let status = IOHIDDeviceOpen(device, kIOHIDOptionsTypeNone);
            if status != kIOReturnSuccess {
                return Err(Error::DeviceNotFound(format!(
                    "could not open the security key (IOReturn 0x{status:08x})"
                )));
            }
            // The manager's set owns the device; hold a reference of our
            // own for as long as it is open.
            CFRetain(device as CFTypeRef);
            let mode = cf_string(RUN_LOOP_MODE);
            let inbox = Box::into_raw(Box::new(Inbox {
                buffer: [0u8; HID_PACKET_LEN],
                packets: VecDeque::new(),
            }));
            IOHIDDeviceRegisterInputReportCallback(
                device,
                std::ptr::addr_of_mut!((*inbox).buffer).cast(),
                HID_PACKET_LEN as CFIndex,
                on_input_report,
                inbox.cast(),
            );
            IOHIDDeviceScheduleWithRunLoop(device, CFRunLoopGetCurrent(), mode.0 as CFStringRef);
            Ok(Self {
                device,
                mode,
                inbox,
            })
        }
    }
}

impl Drop for MacHidDevice {
    fn drop(&mut self) {
        unsafe {
            // Unscheduled first, so the callback can never run against an
            // inbox that is about to be freed.
            IOHIDDeviceUnscheduleFromRunLoop(
                self.device,
                CFRunLoopGetCurrent(),
                self.mode.0 as CFStringRef,
            );
            IOHIDDeviceClose(self.device, kIOHIDOptionsTypeNone);
            CFRelease(self.device as CFTypeRef);
            drop(Box::from_raw(self.inbox));
        }
    }
}

impl HidTransport for MacHidDevice {
    fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), Error> {
        // FIDO interfaces do not number their reports: report id 0, and
        // the 64 bytes as they are.
        let status = unsafe {
            IOHIDDeviceSetReport(
                self.device,
                kIOHIDReportTypeOutput,
                0,
                packet.as_ptr(),
                HID_PACKET_LEN as CFIndex,
            )
        };
        if status != kIOReturnSuccess {
            return Err(Error::Transport(format!(
                "the security key did not accept a write (IOReturn 0x{status:08x}); \
                 it may have been removed"
            )));
        }
        Ok(())
    }

    fn read_packet(&mut self, timeout: Duration) -> Result<Option<[u8; HID_PACKET_LEN]>, Error> {
        let pop = |inbox: *mut Inbox| unsafe { (*inbox).packets.pop_front() };
        if let Some(packet) = pop(self.inbox) {
            return Ok(Some(packet));
        }
        // One bounded spin of our own mode: returns as soon as a report
        // was handled, or when the timeout passes with nothing.
        let result = unsafe {
            CFRunLoopRunInMode(self.mode.0 as CFStringRef, timeout.as_secs_f64(), 1)
        };
        if let Some(packet) = pop(self.inbox) {
            return Ok(Some(packet));
        }
        // No source left in our mode: the device went away (IOKit drops
        // it from the run loop), and spinning again would return at once
        // until the deadline.
        if result == RUN_FINISHED {
            return Err(Error::Transport("the security key was removed".into()));
        }
        Ok(None)
    }
}
