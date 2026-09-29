//! CTAP2 over USB HID on Linux: `/dev/hidraw*`.
//!
//! The kernel exposes every HID interface as a character device and its
//! report descriptor under `/sys/class/hidraw/<node>/device/`. A FIDO
//! interface is the one whose descriptor declares usage page `0xF1D0`,
//! usage `0x01`, the same test `libfido2` and OpenSSH's `sk-usbhid.c`
//! apply. Reads are bounded with `poll(2)`, so the CTAP loop can notice a
//! cancel or its deadline between packets.
//!
//! Access is a matter of udev: systemd tags FIDO tokens for the seated
//! user (`uaccess`) since v244, and older systems need the `70-u2f.rules`
//! file `libfido2` ships. A token that is present but not openable is
//! reported as exactly that, never as "no key found".

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::authenticator::{Assertion, AssertionRequest, Authenticator, Interaction};
use crate::ctap::{self, HID_PACKET_LEN, HidTransport};
use crate::Error;

const FIDO_USAGE_PAGE: u32 = 0xf1d0;
const FIDO_USAGE: u32 = 0x01;

/// Same budget as the Windows transports.
const DEFAULT_TOUCH_TIMEOUT: Duration = Duration::from_secs(120);

/// Signs with whatever FIDO2 token is plugged in.
#[derive(Default)]
pub(crate) struct LinuxHidAuthenticator;

impl Authenticator for LinuxHidAuthenticator {
    fn get_assertion(
        &self,
        request: &AssertionRequest,
        interaction: &Interaction,
    ) -> Result<Assertion, Error> {
        let mut device = open_first()?;
        ctap::get_assertion(&mut device, request, interaction, DEFAULT_TOUCH_TIMEOUT)
    }
}

/// Open the first FIDO interface that will have us. One refusal does not
/// end the search (a second token may be free), but the last reason is
/// what gets reported when none opens.
fn open_first() -> Result<HidrawDevice, Error> {
    let nodes = fido_nodes(Path::new("/sys/class/hidraw"));
    if nodes.is_empty() {
        return Err(Error::DeviceNotFound(
            "no FIDO security key is plugged in".into(),
        ));
    }
    let mut last_error = None;
    for node in nodes {
        match HidrawDevice::open(&node) {
            Ok(device) => return Ok(device),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.expect("at least one node was tried"))
}

/// `/dev/<node>` for every hidraw node whose report descriptor is FIDO.
fn fido_nodes(sysfs: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(sysfs) else {
        return Vec::new();
    };
    let mut nodes: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| {
            std::fs::read(entry.path().join("device/report_descriptor"))
                .is_ok_and(|descriptor| is_fido_descriptor(&descriptor))
        })
        .map(|entry| Path::new("/dev").join(entry.file_name()))
        .collect();
    // Stable order, so "the first token" means the same one every time.
    nodes.sort();
    nodes
}

/// Whether a HID report descriptor declares the FIDO usage page and usage
/// for its top-level collection.
///
/// A walk over SHORT items (HID 1.11 section 6.2.2.2): a prefix byte with
/// size (0, 1, 2 or 4 bytes), type and tag, then that many data bytes
/// little-endian. Long items (prefix `0xFE`) carry their own length and
/// are skipped. Usage Page is global item tag 0 (`0x04`), Usage is local
/// item tag 0 (`0x08`); the first Usage after the FIDO page decides.
fn is_fido_descriptor(descriptor: &[u8]) -> bool {
    let mut page: Option<u32> = None;
    let mut i = 0;
    while i < descriptor.len() {
        let prefix = descriptor[i];
        if prefix == 0xfe {
            // Long item: size byte, tag byte, then data.
            let Some(&size) = descriptor.get(i + 1) else {
                return false;
            };
            i += 3 + size as usize;
            continue;
        }
        let size = match prefix & 0x03 {
            3 => 4,
            n => n as usize,
        };
        let Some(data) = descriptor.get(i + 1..i + 1 + size) else {
            return false;
        };
        let value = data
            .iter()
            .rev()
            .fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte));
        match prefix & 0xfc {
            0x04 => page = Some(value),
            0x08 => return page == Some(FIDO_USAGE_PAGE) && value == FIDO_USAGE,
            _ => {}
        }
        i += 1 + size;
    }
    false
}

/// An open hidraw node.
struct HidrawDevice {
    fd: OwnedFd,
}

impl HidrawDevice {
    fn open(path: &Path) -> Result<Self, Error> {
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| Error::DeviceNotFound("a hidraw path held a NUL byte".into()))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::EACCES) | Some(libc::EPERM) => Error::DeviceNotFound(format!(
                    "a security key is plugged in but {} is not accessible to this user; \
                     install the FIDO udev rules (systemd 244+ tags tokens for the \
                     seated user, older systems need libfido2's 70-u2f.rules)",
                    path.display()
                )),
                _ => Error::DeviceNotFound(format!("could not open {}: {error}", path.display())),
            });
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }
}

impl HidTransport for HidrawDevice {
    fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), Error> {
        // The first byte is the report number; FIDO interfaces do not
        // number their reports, which hidraw spells as a leading zero.
        let mut out = [0u8; HID_PACKET_LEN + 1];
        out[1..].copy_from_slice(packet);
        let written = unsafe { libc::write(self.fd.as_raw_fd(), out.as_ptr().cast(), out.len()) };
        if written != out.len() as isize {
            return Err(Error::Transport(format!(
                "the security key did not accept a write ({}); it may have been removed",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn read_packet(&mut self, timeout: Duration) -> Result<Option<[u8; HID_PACKET_LEN]>, Error> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(Error::Transport(format!("waiting on the security key failed: {error}")));
        }
        if ready == 0 {
            return Ok(None);
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::Transport("the security key was removed".into()));
        }
        let mut packet = [0u8; HID_PACKET_LEN];
        let read = unsafe {
            libc::read(self.fd.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len())
        };
        if read < 0 {
            return Err(Error::Transport(format!(
                "reading from the security key failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if (read as usize) < HID_PACKET_LEN {
            return Err(Error::Transport(format!(
                "the security key returned a short report ({read} bytes)"
            )));
        }
        Ok(Some(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor a YubiKey 5's FIDO interface reports: Usage Page
    /// (FIDO Alliance), Usage (U2F Authenticator Device), Collection
    /// (Application), then the two 64-byte reports.
    const YUBIKEY_FIDO: &[u8] = &[
        0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00,
        0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75,
        0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
    ];

    /// A boot keyboard: Generic Desktop, Keyboard. The same YubiKey
    /// presents one of these too, and it must never be picked.
    const KEYBOARD: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0xc0,
    ];

    #[test]
    fn the_fido_interface_is_recognised_by_its_usage_page() {
        assert!(is_fido_descriptor(YUBIKEY_FIDO));
    }

    #[test]
    fn a_keyboard_on_the_same_device_is_not() {
        assert!(!is_fido_descriptor(KEYBOARD));
    }

    #[test]
    fn a_fido_page_with_another_usage_is_not_the_authenticator() {
        assert!(!is_fido_descriptor(&[0x06, 0xd0, 0xf1, 0x09, 0x02, 0xa1, 0x01, 0xc0]));
    }

    #[test]
    fn a_truncated_descriptor_is_refused_rather_than_read_past() {
        assert!(!is_fido_descriptor(&[0x06, 0xd0]));
        assert!(!is_fido_descriptor(&[0xfe]));
    }

    #[test]
    fn long_items_are_skipped() {
        let mut descriptor = vec![0xfe, 0x02, 0x10, 0xaa, 0xbb];
        descriptor.extend_from_slice(YUBIKEY_FIDO);
        assert!(is_fido_descriptor(&descriptor));
    }

    #[test]
    fn nodes_are_found_through_sysfs() {
        let root = std::env::temp_dir().join(format!("oryxis-fido2-sysfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (node, descriptor) in [("hidraw3", KEYBOARD), ("hidraw1", YUBIKEY_FIDO)] {
            let dir = root.join(node).join("device");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("report_descriptor"), descriptor).unwrap();
        }
        assert_eq!(fido_nodes(&root), vec![PathBuf::from("/dev/hidraw1")]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
