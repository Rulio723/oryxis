//! CTAP2 over the USB HID transport, and the little CBOR it needs.
//!
//! This is deliberately a hand-rolled slice of the spec rather than a
//! dependency: Oryxis already avoids `libfido2` (a C library that would
//! need a toolchain on every platform we ship), and the only command we
//! need is `authenticatorGetAssertion` with a PIN-less, handle-addressed
//! credential. Everything else the spec defines is left out on purpose —
//! see [`super::SkError::UnsupportedAlgorithm`] and
//! [`super::SkError::PinRequired`] for the two places that shows.
//!
//! The transport is behind [`HidTransport`] so the framing and the CBOR
//! can be tested against a scripted device.

use std::time::Duration;

use super::SkError;
use super::authenticator::{Assertion, AssertionRequest};

/// One CTAPHID report, without the leading report-id byte the OS adds.
pub(crate) const HID_PACKET_LEN: usize = 64;

const BROADCAST_CID: u32 = 0xffff_ffff;

/// The top bit of a command byte means "this packet starts a message". A
/// continuation packet reuses the same byte for its sequence number, and
/// a sequence number never has the top bit set — that is the only thing
/// separating the two cases.
///
/// The flag is about packet *position*, not direction: a request and its
/// response carry the same byte, so `CTAPHID_INIT` is `0x86` on the wire
/// rather than `0x06`. Sending the bare base code is not a near miss — a
/// token reads it as "continuation, sequence 6" on a channel that has no
/// transaction open and answers `CTAPHID_ERROR` / `ERR_INVALID_CHANNEL`.
const INIT_PACKET_FLAG: u8 = 0x80;

const CMD_MSG: u8 = 0x03 | INIT_PACKET_FLAG;
const CMD_INIT: u8 = 0x06 | INIT_PACKET_FLAG;
const CMD_CBOR: u8 = 0x10 | INIT_PACKET_FLAG;
const CMD_CANCEL: u8 = 0x11 | INIT_PACKET_FLAG;
const CMD_KEEPALIVE: u8 = 0x3b | INIT_PACKET_FLAG;
const CMD_ERROR: u8 = 0x3f | INIT_PACKET_FLAG;

/// `CTAPHID_KEEPALIVE` status: the token wants a touch.
const KEEPALIVE_UP_NEEDED: u8 = 1;
/// `CTAPHID_KEEPALIVE` status: the token wants user verification.
const KEEPALIVE_UV_NEEDED: u8 = 2;

// CTAP status codes, exactly as the spec numbers them. The CTAP1 codes
// occupy 0x01-0x0b and the CTAP2 ones 0x11-0x40 — a two-range layout that
// is easy to get wrong by writing a plausible-looking run of consecutive
// values instead of looking them up. These were wrong in exactly that way
// (0x1c for KEEPALIVE_CANCEL, 0x1d for NO_CREDENTIALS, ...), which is
// invisible in tests and only shows up as a mislabelled failure against a
// real token. Source: the spec's "Status Codes" table, cross-checked
// against Yubico's python-fido2 (`CtapError.ERR`).
const CTAP2_OK: u8 = 0x00;
const CTAP1_ERR_TIMEOUT: u8 = 0x05;
const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
const CTAP2_ERR_INVALID_OPTION: u8 = 0x2c;
const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2d;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2f;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
/// Named `PIN_REQUIRED` in CTAP 2.0 and `PUAT_REQUIRED` from 2.1 on; the
/// number did not move.
const CTAP2_ERR_PIN_REQUIRED: u8 = 0x36;
const CTAP2_ERR_REQUEST_TOO_LARGE: u8 = 0x39;
const CTAP2_ERR_ACTION_TIMEOUT: u8 = 0x3a;
const CTAP2_ERR_UP_REQUIRED: u8 = 0x3b;
const CTAP2_ERR_UV_BLOCKED: u8 = 0x3c;

/// `authenticatorGetAssertion`.
const CTAP2_GET_ASSERTION: u8 = 0x02;

/// How long one `read_packet` waits before reporting "nothing yet". Short
/// enough that a cancelled or timed-out request is noticed promptly, long
/// enough not to spin.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// What the token is waiting for while a request is in flight. The engine
/// surfaces this as "touch your key" without the SSH task blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TouchState {
    WaitingForTouch,
    WaitingForVerification,
}

/// A CTAPHID channel: one packet in, one packet out.
pub(crate) trait HidTransport {
    /// Send one 64-byte report.
    fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), SkError>;
    /// Read one 64-byte report, or `None` if nothing arrived in time.
    fn read_packet(&mut self, timeout: Duration) -> Result<Option<[u8; HID_PACKET_LEN]>, SkError>;
}

/// Run `authenticatorGetAssertion` over `transport`.
///
/// `touch_timeout` bounds the whole human wait, not one read: the token
/// sends keepalives while it waits, and each one resets nothing — the
/// budget is the user's, so a token that is present but untouched fails
/// with [`SkError::TouchTimeout`] rather than hanging.
pub(crate) fn get_assertion(
    transport: &mut dyn HidTransport,
    request: &AssertionRequest,
    touch_timeout: Duration,
    progress: &mut dyn FnMut(TouchState),
) -> Result<Assertion, SkError> {
    // Encode first: a request we cannot express (a PIN we cannot turn into
    // the token's HMAC) must be refused before the device is even opened
    // for a channel, so a half-built request never reaches the token.
    let payload = encode_get_assertion(request)?;
    let response = exchange(transport, &payload, touch_timeout, progress)?;
    parse_get_assertion(&response)
}

/// Send one CTAP2 message and read the token's raw reply, status byte
/// first. Split out of [`get_assertion`] so the transport can be exercised
/// against a token with a request that was not built by
/// [`encode_get_assertion`] — which is the only way to tell a request the
/// token dislikes from a framing bug, since both look identical from the
/// outside.
pub(crate) fn exchange(
    transport: &mut dyn HidTransport,
    payload: &[u8],
    touch_timeout: Duration,
    progress: &mut dyn FnMut(TouchState),
) -> Result<Vec<u8>, SkError> {
    let channel = init_channel(transport)?;
    send(transport, channel, CMD_CBOR, payload)?;

    let mut assembled: Vec<u8> = Vec::new();
    let mut expected: Option<usize> = None;
    let mut next_seq: u8 = 0;
    let mut waited = Duration::ZERO;
    let mut announced_touch = false;

    loop {
        let packet = match transport.read_packet(POLL_INTERVAL)? {
            Some(packet) => packet,
            None => {
                waited += POLL_INTERVAL;
                if waited >= touch_timeout {
                    // Best effort: tell the token to stop waiting too, so
                    // the next attempt does not find a channel busy with a
                    // request nobody is looking at.
                    let _ = send(transport, channel, CMD_CANCEL, &[]);
                    return Err(SkError::TouchTimeout);
                }
                continue;
            }
        };

        if u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) != channel {
            // Another application's channel on the same device, or a
            // stale reply from the INIT broadcast. Not ours.
            continue;
        }

        match packet[4] {
            CMD_KEEPALIVE => {
                // The status is the packet's one payload byte, i.e. the
                // first byte after the command and the length field — not
                // the length field itself.
                let status = packet[7];
                if !announced_touch {
                    announced_touch = true;
                    progress(match status {
                        KEEPALIVE_UP_NEEDED => TouchState::WaitingForTouch,
                        KEEPALIVE_UV_NEEDED => TouchState::WaitingForVerification,
                        // The spec leaves other statuses undefined; either
                        // way the token is waiting on a human.
                        _ => TouchState::WaitingForTouch,
                    });
                }
                continue;
            }
            CMD_ERROR => {
                return Err(map_hid_error(packet[7]));
            }
            _ => {}
        }

        // Continuation of a message already in flight. A continuation
        // packet puts its sequence number in the very byte an initial
        // packet uses for its command, so this has to be decided *before*
        // any command dispatch: a fragmented response would otherwise
        // look like an unknown command. `INIT_PACKET_FLAG` is what keeps
        // the two apart — every command carries it, no sequence number
        // does. (Keepalives and errors are handled above, because a token
        // may send them mid-message.)
        if expected.is_some() {
            if packet[4] != next_seq {
                return Err(SkError::Transport(format!(
                    "the security key sent sequence {} where {} was expected",
                    packet[4], next_seq
                )));
            }
            next_seq = next_seq.wrapping_add(1);
            let want = expected.unwrap_or(0);
            let remaining = want.saturating_sub(assembled.len());
            let take = remaining.min(HID_PACKET_LEN - 5);
            assembled.extend_from_slice(&packet[5..5 + take]);
            if assembled.len() >= want {
                return Ok(assembled);
            }
            continue;
        }

        // Initial packet: a command, a two-byte *total* length, payload.
        match packet[4] {
            CMD_CBOR | CMD_MSG => {}
            other => {
                return Err(SkError::Transport(format!(
                    "unexpected CTAPHID command 0x{other:02x} from the security key"
                )));
            }
        }
        let len = u16::from_be_bytes([packet[5], packet[6]]) as usize;
        let take = len.min(HID_PACKET_LEN - 7);
        assembled.extend_from_slice(&packet[7..7 + take]);
        if assembled.len() >= len {
            return Ok(assembled);
        }
        expected = Some(len);
        next_seq = 0;
    }
}

/// Open a CTAPHID channel with `CTAPHID_INIT`.
fn init_channel(transport: &mut dyn HidTransport) -> Result<u32, SkError> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|e| SkError::Transport(format!("no randomness for CTAPHID_INIT: {e}")))?;

    let mut packet = [0u8; HID_PACKET_LEN];
    packet[..4].copy_from_slice(&BROADCAST_CID.to_be_bytes());
    packet[4] = CMD_INIT;
    packet[5..7].copy_from_slice(&8u16.to_be_bytes());
    packet[7..15].copy_from_slice(&nonce);
    transport.write_packet(&packet)?;

    let deadline = Duration::from_secs(2);
    let mut waited = Duration::ZERO;
    loop {
        let reply = match transport.read_packet(POLL_INTERVAL)? {
            Some(reply) => reply,
            None => {
                waited += POLL_INTERVAL;
                if waited >= deadline {
                    return Err(SkError::DeviceNotFound(
                        "the security key did not answer CTAPHID_INIT".into(),
                    ));
                }
                continue;
            }
        };
        if reply[4] == CMD_ERROR {
            // As with keepalives, the code is the payload byte.
            return Err(map_hid_error(reply[7]));
        }
        if reply[4] != CMD_INIT {
            continue;
        }
        // Broadcast replies carry the fresh channel in the body.
        if reply[7..15] != nonce {
            continue;
        }
        let channel = u32::from_be_bytes([reply[15], reply[16], reply[17], reply[18]]);
        if channel == BROADCAST_CID || channel == 0 {
            return Err(SkError::Transport(
                "the security key handed back an unusable channel id".into(),
            ));
        }
        return Ok(channel);
    }
}

/// Frame `payload` into a message and write it.
fn send(
    transport: &mut dyn HidTransport,
    channel: u32,
    command: u8,
    payload: &[u8],
) -> Result<(), SkError> {
    if payload.len() > u16::MAX as usize {
        return Err(SkError::Malformed("CTAPHID message too long".into()));
    }
    let mut packet = [0u8; HID_PACKET_LEN];
    packet[..4].copy_from_slice(&channel.to_be_bytes());
    packet[4] = command;
    packet[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first = payload.len().min(HID_PACKET_LEN - 7);
    packet[7..7 + first].copy_from_slice(&payload[..first]);
    transport.write_packet(&packet)?;

    let mut sent = first;
    let mut seq: u8 = 0;
    while sent < payload.len() {
        let mut packet = [0u8; HID_PACKET_LEN];
        packet[..4].copy_from_slice(&channel.to_be_bytes());
        packet[4] = seq;
        let take = (payload.len() - sent).min(HID_PACKET_LEN - 5);
        packet[5..5 + take].copy_from_slice(&payload[sent..sent + take]);
        transport.write_packet(&packet)?;
        sent += take;
        seq = seq.wrapping_add(1);
    }
    Ok(())
}

/// `CTAPHID_ERROR` payloads, by the spec's own codes. `0x0b` is the one a
/// token sends when the channel id in a request is not one it has open —
/// which is also what a *malformed* request looks like, so it is worth
/// reading as "the token did not recognise what we sent" rather than as a
/// statement about the channel alone.
fn map_hid_error(code: u8) -> SkError {
    match code {
        0x05 => SkError::TouchTimeout,
        0x06 => SkError::Transport("the security key is busy".into()),
        0x0b => SkError::Transport(
            "the security key did not recognise the channel; it may have been \
             reset or claimed by another program"
                .into(),
        ),
        other => SkError::Transport(format!("CTAPHID error 0x{other:02x}")),
    }
}

fn map_ctap_error(code: u8) -> SkError {
    match code {
        CTAP2_ERR_NO_CREDENTIALS => SkError::CredentialNotFound,
        CTAP2_ERR_KEEPALIVE_CANCEL => SkError::Cancelled,
        CTAP1_ERR_TIMEOUT | CTAP2_ERR_USER_ACTION_TIMEOUT | CTAP2_ERR_ACTION_TIMEOUT => {
            SkError::TouchTimeout
        }
        CTAP2_ERR_PIN_REQUIRED | CTAP2_ERR_PIN_NOT_SET => SkError::PinRequired,
        CTAP2_ERR_PIN_INVALID | CTAP2_ERR_PIN_AUTH_INVALID => {
            SkError::Transport("the security key rejected the PIN".into())
        }
        CTAP2_ERR_PIN_BLOCKED => SkError::Transport(
            "the security key's PIN is blocked; reset it with a FIDO2 tool".into(),
        ),
        CTAP2_ERR_UV_BLOCKED => SkError::UserVerificationUnavailable,
        CTAP2_ERR_UP_REQUIRED => {
            SkError::Transport("the security key requires a touch but none was requested".into())
        }
        // The three the token sends when it cannot make sense of the
        // request itself. Worth naming apart from a generic status: they
        // mean *we* built something the token would not parse, so the
        // useful next step is on our side of the wire, not the user's.
        CTAP2_ERR_CBOR_UNEXPECTED_TYPE => {
            SkError::Malformed("the security key rejected the request's CBOR".into())
        }
        CTAP2_ERR_INVALID_CBOR => {
            SkError::Malformed("the security key could not decode the request's CBOR".into())
        }
        CTAP2_ERR_MISSING_PARAMETER => {
            SkError::Malformed("the security key wanted a parameter the request left out".into())
        }
        CTAP2_ERR_UNSUPPORTED_OPTION | CTAP2_ERR_INVALID_OPTION => SkError::Malformed(
            "the security key does not accept one of the options the request asked for".into(),
        ),
        CTAP2_ERR_UNSUPPORTED_ALGORITHM => {
            SkError::Malformed("the security key cannot sign with Ed25519".into())
        }
        CTAP2_ERR_REQUEST_TOO_LARGE => {
            SkError::Malformed("the request was larger than the security key accepts".into())
        }
        other => SkError::Transport(format!(
            "the security key returned CTAP2 status 0x{other:02x}"
        )),
    }
}

// ---------------------------------------------------------------------------
// The one CBOR message we build, and the one we read.
// ---------------------------------------------------------------------------

fn encode_get_assertion(request: &AssertionRequest) -> Result<Vec<u8>, SkError> {
    if request.pin.is_some() {
        // Building the PIN's HMAC requires the token's key agreement and
        // HKDF/AES on top; phase 1 does not carry that, and silently
        // dropping the PIN would produce a confusing server-side failure
        // instead of a local one.
        return Err(SkError::PinRequired);
    }

    let mut cbor = Cbor::new();
    // rpId, clientDataHash, and the options map — plus the allow-list when
    // the credential is addressed by handle rather than searched for.
    let entries = 2 + usize::from(request.key_handle.is_some()) + 1;
    cbor.map(entries);
    cbor.uint(0x01);
    cbor.text(&request.application);
    cbor.uint(0x02);
    cbor.bytes(&super::signature::sha256(&request.message));
    if let Some(handle) = &request.key_handle {
        cbor.uint(0x03);
        // A resident credential has an empty handle and is searched for
        // rather than named, so the list is present but empty.
        cbor.array(usize::from(!handle.is_empty()));
        if !handle.is_empty() {
            cbor.map(2);
            // PublicKeyCredentialDescriptor is a WebAuthn dictionary, so
            // its member names are TEXT keys. The surrounding CTAP request
            // uses numeric keys, but carrying that convention into this
            // nested map makes a real token answer CBOR_UNEXPECTED_TYPE.
            cbor.text("type");
            cbor.text("public-key");
            cbor.text("id");
            cbor.bytes(handle);
        }
    }
    cbor.uint(0x05);
    cbor.map(if request.require_user_verification {
        2
    } else {
        1
    });
    cbor.text("up");
    cbor.bool(request.require_user_presence);
    if request.require_user_verification {
        cbor.text("uv");
        cbor.bool(true);
    }

    // A `CTAPHID_CBOR` message body is not bare CBOR: it is the one-byte
    // CTAP command identifier followed by the CBOR-encoded parameters.
    // Sending the map on its own is the kind of mistake that only shows
    // up against a real token, so it is asserted in the tests below.
    let parameters = cbor.finish();
    let mut payload = Vec::with_capacity(parameters.len() + 1);
    payload.push(CTAP2_GET_ASSERTION);
    payload.extend_from_slice(&parameters);
    Ok(payload)
}

fn parse_get_assertion(bytes: &[u8]) -> Result<Assertion, SkError> {
    if bytes.is_empty() {
        return Err(SkError::Malformed("empty CTAP2 response".into()));
    }
    if bytes[0] != CTAP2_OK {
        return Err(map_ctap_error(bytes[0]));
    }
    let (value, _) = cbor_decode(&bytes[1..])?;
    let entries = match value {
        Value::Map(entries) => entries,
        other => {
            return Err(SkError::Malformed(format!(
                "expected a CBOR map, got {}",
                other.kind()
            )));
        }
    };

    let mut auth_data: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    for (key, value) in entries {
        match (key.as_uint(), value) {
            (Some(0x02), Value::Bytes(data)) => auth_data = Some(data),
            (Some(0x03), Value::Bytes(sig)) => signature = Some(sig),
            _ => {}
        }
    }

    // rpIdHash(32) || flags(1) || signCount(4) -- the five bytes after the
    // hash are echoed into the SSH signature blob verbatim.
    let auth_data = auth_data.ok_or_else(|| SkError::Malformed("no authData".into()))?;
    if auth_data.len() < 37 {
        return Err(SkError::Malformed(format!(
            "authData is {} bytes, too short to carry flags and a counter",
            auth_data.len()
        )));
    }
    let signature = signature.ok_or_else(|| SkError::Malformed("no signature".into()))?;

    Ok(Assertion {
        signature,
        flags: auth_data[32],
        counter: u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]),
    })
}

/// The smallest CBOR writer that covers `authenticatorGetAssertion`.
struct Cbor(Vec<u8>);

impl Cbor {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }

    fn map(&mut self, entries: usize) -> &mut Self {
        self.head(5, entries as u64)
    }

    fn array(&mut self, items: usize) -> &mut Self {
        self.head(4, items as u64)
    }

    fn uint(&mut self, value: u64) -> &mut Self {
        self.head(0, value)
    }

    fn text(&mut self, value: &str) -> &mut Self {
        self.head(3, value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
        self
    }

    fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.head(2, value.len() as u64);
        self.0.extend_from_slice(value);
        self
    }

    fn bool(&mut self, value: bool) -> &mut Self {
        self.0.push(if value { 0xf5 } else { 0xf4 });
        self
    }

    /// Major type plus argument, in the shortest form CBOR allows.
    fn head(&mut self, major: u8, value: u64) -> &mut Self {
        let tag = major << 5;
        match value {
            0..=23 => self.0.push(tag | value as u8),
            24..=0xff => {
                self.0.push(tag | 24);
                self.0.push(value as u8);
            }
            0x100..=0xffff => {
                self.0.push(tag | 25);
                self.0.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(tag | 26);
                self.0.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(tag | 27);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
        self
    }
}

/// The slice of CBOR a CTAP2 assertion response can contain.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Uint(u64),
    Neg(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(value) => Some(*value),
            _ => None,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Uint(_) => "an unsigned integer",
            Self::Neg(_) => "a negative integer",
            Self::Bytes(_) => "a byte string",
            Self::Text(_) => "a text string",
            Self::Array(_) => "an array",
            Self::Map(_) => "a map",
            Self::Bool(_) => "a boolean",
            Self::Null => "null",
        }
    }
}

fn cbor_decode(bytes: &[u8]) -> Result<(Value, usize), SkError> {
    let mut reader = Reader { bytes, pos: 0 };
    let value = reader.value()?;
    Ok((value, reader.pos))
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, SkError> {
        let byte = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| SkError::Malformed("truncated CBOR".into()))?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SkError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| SkError::Malformed("truncated CBOR".into()))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn argument(&mut self, info: u8) -> Result<u64, SkError> {
        Ok(match info {
            0..=23 => info as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(SkError::Malformed("indefinite-length CBOR".into())),
        })
    }

    fn value(&mut self) -> Result<Value, SkError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        Ok(match major {
            0 => Value::Uint(self.argument(info)?),
            1 => Value::Neg(-1 - self.argument(info)? as i64),
            2 => {
                let len = self.argument(info)? as usize;
                Value::Bytes(self.take(len)?.to_vec())
            }
            3 => {
                let len = self.argument(info)? as usize;
                let raw = self.take(len)?;
                Value::Text(
                    std::str::from_utf8(raw)
                        .map_err(|_| SkError::Malformed("invalid UTF-8 in CBOR".into()))?
                        .to_string(),
                )
            }
            4 => {
                let len = self.argument(info)? as usize;
                let mut items = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    items.push(self.value()?);
                }
                Value::Array(items)
            }
            5 => {
                let len = self.argument(info)? as usize;
                let mut entries = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    let key = self.value()?;
                    let value = self.value()?;
                    entries.push((key, value));
                }
                Value::Map(entries)
            }
            7 => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => return Err(SkError::Malformed("unsupported CBOR simple value".into())),
            },
            other => {
                return Err(SkError::Malformed(format!(
                    "unsupported CBOR major type {other}"
                )));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A scripted token. It answers `CTAPHID_INIT` for real — echoing the
    /// nonce it was sent, which is the one field a test cannot know in
    /// advance — and replays a canned packet stream for everything else.
    struct ScriptedDevice {
        channel: u32,
        replies: VecDeque<[u8; HID_PACKET_LEN]>,
        written: Vec<[u8; HID_PACKET_LEN]>,
    }

    impl ScriptedDevice {
        fn new(channel: u32, replies: Vec<[u8; HID_PACKET_LEN]>) -> Self {
            Self {
                channel,
                replies: replies.into(),
                written: Vec::new(),
            }
        }

        /// An initial packet: command, two-byte length, payload.
        fn initial(channel: u32, command: u8, payload: &[u8]) -> [u8; HID_PACKET_LEN] {
            Self::initial_with_total(channel, command, payload.len(), payload)
        }

        /// An initial packet whose length field describes the *whole*
        /// message, which is what the spec says it is: the two-byte field
        /// is the total length, and the remainder arrives in continuation
        /// packets. Getting this wrong is invisible for a one-packet
        /// message and fatal for a fragmented one, so the two cases are
        /// spelled out separately here.
        fn initial_with_total(
            channel: u32,
            command: u8,
            total_len: usize,
            payload: &[u8],
        ) -> [u8; HID_PACKET_LEN] {
            assert!(
                payload.len() <= HID_PACKET_LEN - 7,
                "{} bytes do not fit in an initial packet; use packets()",
                payload.len()
            );
            let mut packet = [0u8; HID_PACKET_LEN];
            packet[..4].copy_from_slice(&channel.to_be_bytes());
            packet[4] = command;
            packet[5..7].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[7..7 + payload.len()].copy_from_slice(payload);
            packet
        }

        /// Fragment one `CTAPHID_CBOR` message the way a token does:
        /// an initial packet, then continuation packets carrying the rest.
        fn packets(channel: u32, command: u8, message: &[u8]) -> Vec<[u8; HID_PACKET_LEN]> {
            let first = message.len().min(HID_PACKET_LEN - 7);
            let mut packets = vec![Self::initial_with_total(
                channel,
                command,
                message.len(),
                &message[..first],
            )];
            let mut sent = first;
            let mut seq: u8 = 0;
            while sent < message.len() {
                let take = (message.len() - sent).min(HID_PACKET_LEN - 5);
                packets.push(Self::continuation(
                    channel,
                    seq,
                    &message[sent..sent + take],
                ));
                sent += take;
                seq = seq.wrapping_add(1);
            }
            packets
        }

        /// A continuation packet: sequence number, then payload.
        fn continuation(channel: u32, seq: u8, payload: &[u8]) -> [u8; HID_PACKET_LEN] {
            let mut packet = [0u8; HID_PACKET_LEN];
            packet[..4].copy_from_slice(&channel.to_be_bytes());
            packet[4] = seq;
            packet[5..5 + payload.len()].copy_from_slice(payload);
            packet
        }

        /// The 17-byte `CTAPHID_INIT` reply: nonce, channel, version,
        /// device version, capabilities.
        fn init_reply(nonce: &[u8], channel: u32) -> [u8; HID_PACKET_LEN] {
            let mut body = Vec::with_capacity(17);
            body.extend_from_slice(nonce);
            body.extend_from_slice(&channel.to_be_bytes());
            body.extend_from_slice(&[2, 0, 0, 0, 0]);
            Self::initial(BROADCAST_CID, CMD_INIT, &body)
        }
    }

    impl HidTransport for ScriptedDevice {
        fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), SkError> {
            self.written.push(*packet);
            if packet[4] == CMD_INIT
                && u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) == BROADCAST_CID
            {
                let reply = ScriptedDevice::init_reply(&packet[7..15], self.channel);
                self.replies.push_front(reply);
            }
            Ok(())
        }

        fn read_packet(
            &mut self,
            _timeout: Duration,
        ) -> Result<Option<[u8; HID_PACKET_LEN]>, SkError> {
            Ok(self.replies.pop_front())
        }
    }

    fn request() -> AssertionRequest {
        AssertionRequest {
            application: "ssh:".into(),
            // The encoder hashes this, so what lands in the CBOR is
            // `SHA256` of these 32 bytes, not the bytes themselves.
            message: vec![0x42; 32],
            key_handle: Some(vec![1, 2, 3, 4]),
            require_user_presence: true,
            require_user_verification: false,
            pin: None,
        }
    }

    /// `CTAP2_OK || map(2) { 0x02: authData, 0x03: signature }`.
    fn assertion_message(flags: u8, counter: u32, signature: &[u8]) -> Vec<u8> {
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = flags;
        auth_data[33..37].copy_from_slice(&counter.to_be_bytes());
        let mut message = vec![CTAP2_OK, 0xa2];
        message.push(0x02);
        message.extend_from_slice(&[0x58, auth_data.len() as u8]);
        message.extend_from_slice(&auth_data);
        message.push(0x03);
        message.extend_from_slice(&[0x58, signature.len() as u8]);
        message.extend_from_slice(signature);
        message
    }

    /// The shape a real token produces: a keepalive while the user
    /// reaches for it, then a response that does not fit in one packet.
    #[test]
    fn assembles_a_multi_packet_assertion_after_a_keepalive() {
        let signature = vec![0x7au8; 64];
        let message = assertion_message(0x05, 9, &signature);
        assert!(message.len() > 57, "the test must actually split packets");

        let mut replies = vec![ScriptedDevice::initial(
            7,
            CMD_KEEPALIVE,
            &[KEEPALIVE_UP_NEEDED],
        )];
        replies.extend(ScriptedDevice::packets(7, CMD_CBOR, &message));
        let mut device = ScriptedDevice::new(7, replies);

        let mut states = Vec::new();
        let assertion = get_assertion(
            &mut device,
            &request(),
            Duration::from_secs(5),
            &mut |state| states.push(state),
        )
        .unwrap();

        assert_eq!(assertion.flags, 0x05);
        assert_eq!(assertion.counter, 9);
        assert_eq!(assertion.signature, signature);
        assert_eq!(states, vec![TouchState::WaitingForTouch]);

        // INIT went to the broadcast channel; the request went to the
        // channel INIT handed back.
        assert_eq!(&device.written[0][..4], &BROADCAST_CID.to_be_bytes());
        assert_eq!(device.written[0][4], CMD_INIT);
        assert_eq!(&device.written[1][..4], &7u32.to_be_bytes());
        assert_eq!(device.written[1][4], CMD_CBOR);
    }

    /// A token that wants user verification says so through the
    /// keepalive, and the caller can surface that instead of a blank wait.
    #[test]
    fn a_uv_keepalive_is_reported_as_verification() {
        let message = assertion_message(0x05, 0, &[0u8; 64]);
        let mut replies = vec![ScriptedDevice::initial(
            3,
            CMD_KEEPALIVE,
            &[KEEPALIVE_UV_NEEDED],
        )];
        replies.extend(ScriptedDevice::packets(3, CMD_CBOR, &message));
        let mut device = ScriptedDevice::new(3, replies);
        let mut states = Vec::new();
        get_assertion(
            &mut device,
            &request(),
            Duration::from_secs(5),
            &mut |state| states.push(state),
        )
        .unwrap();
        assert_eq!(states, vec![TouchState::WaitingForVerification]);
    }

    /// A token that never answers must fail with the named timeout and
    /// tell the token to stop, not hang until the connection gives up.
    #[test]
    fn an_unanswered_touch_times_out_and_cancels() {
        let mut device = ScriptedDevice::new(1, vec![]);
        let err = get_assertion(
            &mut device,
            &request(),
            Duration::from_millis(1),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(matches!(err, SkError::TouchTimeout), "got {err:?}");
        assert_eq!(device.written.last().unwrap()[4], CMD_CANCEL);
    }

    /// A token that knows nothing about the handle is a distinct,
    /// actionable error, not a generic transport failure.
    #[test]
    fn no_credentials_maps_to_a_named_error() {
        let mut device = ScriptedDevice::new(
            1,
            vec![ScriptedDevice::initial(
                1,
                CMD_CBOR,
                &[CTAP2_ERR_NO_CREDENTIALS],
            )],
        );
        let err = get_assertion(&mut device, &request(), Duration::from_secs(1), &mut |_| {})
            .unwrap_err();
        assert!(matches!(err, SkError::CredentialNotFound), "got {err:?}");
    }

    /// A CTAPHID-level error carries its code in the payload byte, not in
    /// the length field. Reading the wrong byte turns every error into a
    /// timeout, which is the kind of bug that only ever shows up on a real
    /// token — so the offset is pinned here.
    #[test]
    fn a_hid_error_is_read_from_the_payload() {
        let mut device =
            ScriptedDevice::new(1, vec![ScriptedDevice::initial(1, CMD_ERROR, &[0x0b])]);
        let err = get_assertion(&mut device, &request(), Duration::from_secs(1), &mut |_| {})
            .unwrap_err();
        match err {
            SkError::Transport(message) => {
                assert!(
                    message.contains("did not recognise the channel"),
                    "got {message}"
                );
            }
            other => panic!("expected a transport error, got {other:?}"),
        }
    }

    /// A token that wants a PIN must say so locally: the request must
    /// never leave without the HMAC the PIN would have produced, because
    /// a token that got half a request is worse than one that got none.
    #[test]
    fn a_pin_key_is_refused_before_the_device_is_touched() {
        let mut device = ScriptedDevice::new(1, vec![]);
        let mut request = request();
        request.pin = Some("123456".into());
        let err =
            get_assertion(&mut device, &request, Duration::from_secs(1), &mut |_| {}).unwrap_err();
        assert!(matches!(err, SkError::PinRequired), "got {err:?}");
        assert!(device.written.is_empty(), "nothing may reach the token");
    }

    /// The encoded request is the exact CBOR a token expects: the CTAP
    /// command byte in front, WebAuthn text keys inside the credential
    /// descriptor, and text keys for the options map.
    #[test]
    fn encodes_the_documented_request_shape() {
        let bytes = encode_get_assertion(&request()).unwrap();
        assert_eq!(
            bytes[0], CTAP2_GET_ASSERTION,
            "a CTAPHID_CBOR body must start with the CTAP command identifier"
        );
        let (value, used) = cbor_decode(&bytes[1..]).unwrap();
        assert_eq!(used, bytes.len() - 1, "no padding after the CBOR");
        let Value::Map(entries) = value else {
            panic!("expected a map");
        };
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].0, Value::Uint(0x01));
        assert_eq!(entries[0].1, Value::Text("ssh:".into()));
        assert_eq!(entries[1].0, Value::Uint(0x02));
        // The token is given a *hash* of the message. Putting the message
        // there instead would still be well-formed CBOR and would still
        // produce a signature — one the server would reject, for reasons
        // that never point back here. Pin the hash.
        assert_eq!(
            entries[1].1,
            Value::Bytes(crate::sk::signature::sha256(&request().message).to_vec())
        );

        let Value::Array(descriptors) = &entries[2].1 else {
            panic!("expected an allow-list array");
        };
        let Value::Map(descriptor) = &descriptors[0] else {
            panic!("expected a descriptor map");
        };
        assert_eq!(descriptor[0].0, Value::Text("type".into()));
        assert_eq!(descriptor[0].1, Value::Text("public-key".into()));
        assert_eq!(descriptor[1].0, Value::Text("id".into()));
        assert_eq!(descriptor[1].1, Value::Bytes(vec![1, 2, 3, 4]));

        let Value::Map(options) = &entries[3].1 else {
            panic!("expected an options map");
        };
        assert_eq!(options[0].0, Value::Text("up".into()));
        assert_eq!(options[0].1, Value::Bool(true));
    }

    /// A resident credential is asked for with no allow-list at all: the
    /// token searches its own store instead of being handed a handle.
    #[test]
    fn a_discoverable_credential_omits_the_allow_list() {
        let mut request = request();
        request.key_handle = None;
        let bytes = encode_get_assertion(&request).unwrap();
        assert_eq!(bytes[0], CTAP2_GET_ASSERTION);
        let Value::Map(entries) = cbor_decode(&bytes[1..]).unwrap().0 else {
            panic!("expected a map");
        };
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|(key, _)| key.as_uint() != Some(0x03)));
    }

    /// The decoder has to survive a real assertion response, which
    /// carries fields we ignore (credential, user, numberOfCredentials).
    #[test]
    fn ignores_response_fields_we_do_not_use() {
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01;
        let mut message = vec![CTAP2_OK, 0xa4];
        // 0x01: credential (a map) -- ignored.
        message.extend_from_slice(&[0x01, 0xa2, 0x64]);
        message.extend_from_slice(b"type");
        message.push(0x6a);
        message.extend_from_slice(b"public-key");
        message.push(0x62);
        message.extend_from_slice(b"id");
        message.extend_from_slice(&[0x44, 1, 2, 3, 4]);
        // 0x02: authData.
        message.push(0x02);
        message.extend_from_slice(&[0x58, auth_data.len() as u8]);
        message.extend_from_slice(&auth_data);
        // 0x03: signature.
        message.push(0x03);
        message.extend_from_slice(&[0x58, 64]);
        message.extend_from_slice(&[0x11u8; 64]);
        // 0x05: numberOfCredentials.
        message.extend_from_slice(&[0x05, 0x01]);

        let mut device = ScriptedDevice::new(2, ScriptedDevice::packets(2, CMD_CBOR, &message));
        let assertion =
            get_assertion(&mut device, &request(), Duration::from_secs(1), &mut |_| {}).unwrap();
        assert_eq!(assertion.flags, 0x01);
        assert_eq!(assertion.signature, vec![0x11u8; 64]);
    }

    /// The command byte is `base | 0x80`, and the literals are pinned on
    /// purpose: every other test here builds its packets from these same
    /// constants, so a wrong constant is invisible to all of them. Only a
    /// real token can tell you that `0x06` is not `CTAPHID_INIT`.
    #[test]
    fn every_command_byte_carries_the_initial_packet_flag() {
        assert_eq!(CMD_MSG, 0x83, "CTAPHID_MSG");
        assert_eq!(CMD_INIT, 0x86, "CTAPHID_INIT");
        assert_eq!(CMD_CBOR, 0x90, "CTAPHID_CBOR");
        assert_eq!(CMD_CANCEL, 0x91, "CTAPHID_CANCEL");
        assert_eq!(CMD_KEEPALIVE, 0xbb, "CTAPHID_KEEPALIVE");
        assert_eq!(CMD_ERROR, 0xbf, "CTAPHID_ERROR");

        // The flag is the only thing separating an initial packet from a
        // continuation, so no command may ever go out without it.
        for command in [
            CMD_MSG,
            CMD_INIT,
            CMD_CBOR,
            CMD_CANCEL,
            CMD_KEEPALIVE,
            CMD_ERROR,
        ] {
            assert_ne!(
                command & INIT_PACKET_FLAG,
                0,
                "0x{command:02x} lost the initial-packet flag"
            );
        }
    }

    /// And the flag has to reach the wire, not just live in the constant:
    /// pin the bytes of the INIT the client actually writes.
    #[test]
    fn the_init_request_goes_out_with_the_flag_set() {
        let mut device = ScriptedDevice::new(0x1234_5678, vec![]);
        let channel = init_channel(&mut device).unwrap();
        assert_eq!(channel, 0x1234_5678);

        let init = device.written[0];
        assert_eq!(&init[..4], &BROADCAST_CID.to_be_bytes(), "broadcast");
        assert_eq!(init[4], 0x86, "CTAPHID_INIT is 0x86 on the wire");
        assert_eq!(&init[5..7], &8u16.to_be_bytes(), "an 8-byte nonce");
    }

    /// The status codes, pinned as literals for the same reason the
    /// command bytes are: every test above builds its reply from these
    /// very constants, so a wrong value is invisible here and only ever
    /// surfaces as a mislabelled error against real hardware. The two
    /// ranges are the trap — CTAP1 lives in 0x01-0x0b and CTAP2 in
    /// 0x11-0x40, so writing "the next number along" produces something
    /// that looks right and means nothing.
    #[test]
    fn the_ctap_status_codes_are_the_spec_numbers() {
        assert_eq!(CTAP2_OK, 0x00);
        assert_eq!(CTAP1_ERR_TIMEOUT, 0x05);
        assert_eq!(CTAP2_ERR_CBOR_UNEXPECTED_TYPE, 0x11, "CBOR_UNEXPECTED_TYPE");
        assert_eq!(CTAP2_ERR_INVALID_CBOR, 0x12, "INVALID_CBOR");
        assert_eq!(CTAP2_ERR_MISSING_PARAMETER, 0x14, "MISSING_PARAMETER");
        assert_eq!(
            CTAP2_ERR_UNSUPPORTED_ALGORITHM, 0x26,
            "UNSUPPORTED_ALGORITHM"
        );
        assert_eq!(CTAP2_ERR_UNSUPPORTED_OPTION, 0x2b, "UNSUPPORTED_OPTION");
        assert_eq!(CTAP2_ERR_INVALID_OPTION, 0x2c, "INVALID_OPTION");
        assert_eq!(CTAP2_ERR_KEEPALIVE_CANCEL, 0x2d, "KEEPALIVE_CANCEL");
        assert_eq!(CTAP2_ERR_NO_CREDENTIALS, 0x2e, "NO_CREDENTIALS");
        assert_eq!(CTAP2_ERR_USER_ACTION_TIMEOUT, 0x2f, "USER_ACTION_TIMEOUT");
        assert_eq!(CTAP2_ERR_PIN_INVALID, 0x31, "PIN_INVALID");
        assert_eq!(CTAP2_ERR_PIN_BLOCKED, 0x32, "PIN_BLOCKED");
        assert_eq!(CTAP2_ERR_PIN_AUTH_INVALID, 0x33, "PIN_AUTH_INVALID");
        assert_eq!(CTAP2_ERR_PIN_NOT_SET, 0x35, "PIN_NOT_SET");
        assert_eq!(CTAP2_ERR_PIN_REQUIRED, 0x36, "PUAT_REQUIRED");
        assert_eq!(CTAP2_ERR_REQUEST_TOO_LARGE, 0x39, "REQUEST_TOO_LARGE");
        assert_eq!(CTAP2_ERR_ACTION_TIMEOUT, 0x3a, "ACTION_TIMEOUT");
        assert_eq!(CTAP2_ERR_UP_REQUIRED, 0x3b, "UP_REQUIRED");
        assert_eq!(CTAP2_ERR_UV_BLOCKED, 0x3c, "UV_BLOCKED");
    }

    /// A token that rejects the request's own encoding must not be
    /// reported as a device or transport problem — the fault is ours, and
    /// saying so is the difference between "plug it in again" and
    /// "there is a bug in the encoder".
    #[test]
    fn a_cbor_complaint_is_our_fault_not_the_users() {
        for code in [
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            CTAP2_ERR_INVALID_CBOR,
            CTAP2_ERR_MISSING_PARAMETER,
            CTAP2_ERR_UNSUPPORTED_OPTION,
            CTAP2_ERR_INVALID_OPTION,
        ] {
            let mut device =
                ScriptedDevice::new(1, vec![ScriptedDevice::initial(1, CMD_CBOR, &[code])]);
            let err = get_assertion(&mut device, &request(), Duration::from_secs(1), &mut |_| {})
                .unwrap_err();
            assert!(
                matches!(err, SkError::Malformed(_)),
                "status 0x{code:02x} should read as a malformed request, got {err:?}"
            );
        }
    }
}
