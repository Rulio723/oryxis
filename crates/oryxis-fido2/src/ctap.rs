//! CTAP2 over CTAPHID: the framing, `authenticatorGetAssertion`, and the
//! `authenticatorGetInfo` / `authenticatorClientPIN` calls a PIN needs.
//!
//! A hand-rolled slice of the spec rather than `libfido2`, a C library
//! that would need a toolchain and a shipping story on every platform.
//! The transport is behind [`HidTransport`], so the whole exchange runs
//! against a scripted token in the tests below.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::authenticator::{Assertion, AssertionRequest, Interaction, PinPrompt, TokenEvent};
use crate::cbor::{self, Cbor, Value};
use crate::pin::{self, Protocol};
use crate::Error;

/// One CTAPHID report, without the leading report-id byte the OS adds.
pub const HID_PACKET_LEN: usize = 64;

const BROADCAST_CID: u32 = 0xffff_ffff;

/// The top bit of a command byte means "this packet starts a message". A
/// continuation packet reuses the same byte for its sequence number, and a
/// sequence number never has the top bit set, which is the only thing
/// separating the two cases. The flag is about packet POSITION, not
/// direction: `CTAPHID_INIT` is `0x86` on the wire in both directions, and
/// a bare `0x06` reads to a token as "continuation, sequence 6".
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

// CTAP status codes, exactly as the spec numbers them. CTAP1 occupies
// 0x01-0x0b and CTAP2 0x11-0x40, a two-range layout that is easy to get
// wrong by writing a plausible run of consecutive values. Source: the
// spec's "Status Codes" table, cross-checked against Yubico's
// python-fido2 (`CtapError.ERR`).
const CTAP2_OK: u8 = 0x00;
const CTAP1_ERR_TIMEOUT: u8 = 0x05;
const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
const CTAP2_ERR_INVALID_OPTION: u8 = 0x2c;
const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2d;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2f;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
/// Named `PIN_REQUIRED` in CTAP 2.0 and `PUAT_REQUIRED` from 2.1 on; the
/// number did not move.
const CTAP2_ERR_PUAT_REQUIRED: u8 = 0x36;
const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
const CTAP2_ERR_REQUEST_TOO_LARGE: u8 = 0x39;
const CTAP2_ERR_ACTION_TIMEOUT: u8 = 0x3a;
const CTAP2_ERR_UP_REQUIRED: u8 = 0x3b;
const CTAP2_ERR_UV_BLOCKED: u8 = 0x3c;

const CTAP2_GET_ASSERTION: u8 = 0x02;
const CTAP2_GET_INFO: u8 = 0x04;
const CTAP2_CLIENT_PIN: u8 = 0x06;

const PIN_GET_RETRIES: u64 = 0x01;
const PIN_GET_KEY_AGREEMENT: u64 = 0x02;
const PIN_GET_PIN_TOKEN: u64 = 0x05;
const PIN_GET_TOKEN_WITH_PERMISSIONS: u64 = 0x09;
/// The `ga` permission: the token may be used for getAssertion.
const PERMISSION_GET_ASSERTION: u64 = 0x02;

/// How long one `read_packet` waits before reporting "nothing yet". Short
/// enough that a cancel is noticed promptly, long enough not to spin.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Budget for an exchange no person takes part in (INIT, getInfo, the
/// PIN protocol's key agreement).
const MACHINE_TIMEOUT: Duration = Duration::from_secs(5);

/// How many times a wrong PIN is asked for again inside one request. The
/// token itself blocks after three in a row (then needs a re-plug), so
/// asking a fourth time here would only ever meet `PIN_AUTH_BLOCKED`.
const MAX_PIN_ATTEMPTS: u32 = 3;

/// A CTAPHID channel: one packet in, one packet out.
pub trait HidTransport {
    /// Send one 64-byte report.
    fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), Error>;
    /// Read one 64-byte report, or `None` if nothing arrived in `timeout`.
    fn read_packet(&mut self, timeout: Duration) -> Result<Option<[u8; HID_PACKET_LEN]>, Error>;
}

/// Run `authenticatorGetAssertion` over `transport`, asking for the PIN
/// through `interaction` when the credential or the token needs one.
///
/// `touch_timeout` bounds the human wait as a whole: keepalives do not
/// extend it, so a token that is present and never touched fails with
/// [`Error::TouchTimeout`] instead of hanging on its own clock.
pub fn get_assertion(
    transport: &mut dyn HidTransport,
    request: &AssertionRequest,
    interaction: &Interaction,
    touch_timeout: Duration,
) -> Result<Assertion, Error> {
    let client_data_hash: [u8; 32] = Sha256::digest(&request.message).into();
    let mut channel = Channel::open(transport, interaction)?;

    // User verification is decided up front when the credential demands
    // it; otherwise only if the token turns out to demand it anyway
    // (`PUAT_REQUIRED`, an `alwaysUv` token).
    let mut verification = if request.user_verification {
        let info = channel.get_info(interaction)?;
        Some(Verification::choose(&mut channel, &info, request, interaction)?)
    } else {
        None
    };

    loop {
        let payload = encode_get_assertion(request, &client_data_hash, verification.as_ref())?;
        let response =
            channel.call(&payload, Instant::now() + touch_timeout, interaction, true)?;
        match response.first().copied() {
            Some(CTAP2_OK) => return parse_get_assertion(&response),
            Some(CTAP2_ERR_PUAT_REQUIRED) if verification.is_none() => {
                let info = channel.get_info(interaction)?;
                verification = Some(Verification::choose(
                    &mut channel,
                    &info,
                    request,
                    interaction,
                )?);
            }
            Some(code) => return Err(map_ctap_error(code)),
            None => return Err(Error::Malformed("empty CTAP2 response".into())),
        }
    }
}

/// How a request proves the user was verified.
enum Verification {
    /// The token verifies on its own (fingerprint): send `"uv": true`.
    BuiltIn,
    /// A PIN-derived pinUvAuthToken signs the client data hash.
    Pin {
        protocol: Protocol,
        token: Zeroizing<Vec<u8>>,
    },
}

impl Verification {
    /// Built-in verification when the token has it configured, else the
    /// PIN. OpenSSH makes the same choice (`sk-usbhid.c`: internal UV when
    /// no PIN was given and the token reports `uv`).
    fn choose(
        channel: &mut Channel<'_>,
        info: &Info,
        request: &AssertionRequest,
        interaction: &Interaction,
    ) -> Result<Self, Error> {
        if info.option("uv") == Some(true) {
            return Ok(Self::BuiltIn);
        }
        match info.option("clientPin") {
            Some(true) => {}
            Some(false) => return Err(Error::PinNotSet),
            None => return Err(Error::UserVerificationBlocked),
        }
        let protocol = Protocol::negotiate(&info.pin_protocols).ok_or_else(|| {
            Error::Malformed("the security key speaks no PIN protocol this build knows".into())
        })?;
        let token = channel.pin_token(protocol, info, &request.application, interaction)?;
        Ok(Self::Pin { protocol, token })
    }
}

/// What `authenticatorGetInfo` said, reduced to what we read.
#[derive(Debug, Default)]
struct Info {
    options: Vec<(String, bool)>,
    pin_protocols: Vec<u64>,
}

impl Info {
    fn option(&self, name: &str) -> Option<bool> {
        self.options
            .iter()
            .find_map(|(key, value)| (key == name).then_some(*value))
    }
}

/// An open CTAPHID channel.
struct Channel<'a> {
    transport: &'a mut dyn HidTransport,
    cid: u32,
}

impl<'a> Channel<'a> {
    /// Allocate a channel with `CTAPHID_INIT`.
    fn open(
        transport: &'a mut dyn HidTransport,
        interaction: &Interaction,
    ) -> Result<Self, Error> {
        let cid = init_channel(transport, interaction)?;
        Ok(Self { transport, cid })
    }

    /// Send one CTAP2 message and read the reply, status byte first.
    ///
    /// `human` says whether a person is expected to act before the reply
    /// (a touch): keepalives are reported through `interaction` only then.
    fn call(
        &mut self,
        payload: &[u8],
        deadline: Instant,
        interaction: &Interaction,
        human: bool,
    ) -> Result<Vec<u8>, Error> {
        send(self.transport, self.cid, CMD_CBOR, payload)?;

        let mut assembled: Vec<u8> = Vec::new();
        let mut expected: Option<usize> = None;
        let mut next_seq: u8 = 0;
        let mut announced: Option<TokenEvent> = None;

        loop {
            if interaction.cancel.is_cancelled() {
                // Tell the token to stop waiting as well, so the next
                // attempt does not find it busy with an abandoned request.
                let _ = send(self.transport, self.cid, CMD_CANCEL, &[]);
                return Err(Error::Cancelled);
            }
            if Instant::now() >= deadline {
                let _ = send(self.transport, self.cid, CMD_CANCEL, &[]);
                return Err(if human {
                    Error::TouchTimeout
                } else {
                    Error::Transport("the security key did not answer in time".into())
                });
            }
            let Some(packet) = self.transport.read_packet(POLL_INTERVAL)? else {
                continue;
            };

            if u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) != self.cid {
                // Another application's channel on the same device.
                continue;
            }

            match packet[4] {
                CMD_KEEPALIVE => {
                    // The status is the one payload byte after the command
                    // and the two-byte length, not the length itself.
                    let event = match packet[7] {
                        KEEPALIVE_UV_NEEDED => TokenEvent::VerificationNeeded,
                        KEEPALIVE_UP_NEEDED => TokenEvent::TouchNeeded,
                        // PROCESSING, or a status the spec leaves undefined:
                        // nobody is being asked for anything yet.
                        _ => continue,
                    };
                    if human && announced != Some(event) {
                        announced = Some(event);
                        interaction.event(event);
                    }
                    continue;
                }
                CMD_ERROR => return Err(map_hid_error(packet[7])),
                _ => {}
            }

            // A continuation packet puts its sequence number in the byte an
            // initial packet uses for its command, so a message in flight
            // is decided BEFORE command dispatch. Keepalives and errors are
            // handled above because a token may send them mid-message.
            if let Some(want) = expected {
                if packet[4] != next_seq {
                    return Err(Error::Transport(format!(
                        "the security key sent sequence {} where {} was expected",
                        packet[4], next_seq
                    )));
                }
                next_seq = next_seq.wrapping_add(1);
                let take = want.saturating_sub(assembled.len()).min(HID_PACKET_LEN - 5);
                assembled.extend_from_slice(&packet[5..5 + take]);
                if assembled.len() >= want {
                    return Ok(assembled);
                }
                continue;
            }

            // Initial packet: a command, a two-byte TOTAL length, payload.
            match packet[4] {
                CMD_CBOR | CMD_MSG => {}
                other => {
                    return Err(Error::Transport(format!(
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

    /// A machine-only CTAP2 call whose reply must be `CTAP2_OK` + a map.
    fn call_map(
        &mut self,
        command: u8,
        parameters: Option<Vec<u8>>,
        interaction: &Interaction,
    ) -> Result<Result<Vec<(Value, Value)>, u8>, Error> {
        let mut payload = vec![command];
        if let Some(parameters) = parameters {
            payload.extend_from_slice(&parameters);
        }
        let response = self.call(&payload, Instant::now() + MACHINE_TIMEOUT, interaction, false)?;
        match response.first().copied() {
            Some(CTAP2_OK) if response.len() == 1 => Ok(Ok(Vec::new())),
            Some(CTAP2_OK) => Ok(Ok(cbor::decode(&response[1..])?.0.into_map()?)),
            Some(code) => Ok(Err(code)),
            None => Err(Error::Malformed("empty CTAP2 response".into())),
        }
    }

    fn get_info(&mut self, interaction: &Interaction) -> Result<Info, Error> {
        let entries = self
            .call_map(CTAP2_GET_INFO, None, interaction)?
            .map_err(map_ctap_error)?;
        let mut info = Info::default();
        for (key, value) in entries {
            match (key.as_uint(), value) {
                (Some(0x04), Value::Map(options)) => {
                    for (name, flag) in options {
                        if let (Value::Text(name), Value::Bool(flag)) = (name, flag) {
                            info.options.push((name, flag));
                        }
                    }
                }
                (Some(0x06), Value::Array(protocols)) => {
                    info.pin_protocols = protocols.iter().filter_map(Value::as_uint).collect();
                }
                _ => {}
            }
        }
        Ok(info)
    }

    fn pin_retries(&mut self, protocol: Protocol, interaction: &Interaction) -> Option<u32> {
        let mut cbor = Cbor::new();
        cbor.map(2).uint(0x01).uint(protocol.id()).uint(0x02).uint(PIN_GET_RETRIES);
        let entries = self
            .call_map(CTAP2_CLIENT_PIN, Some(cbor.finish()), interaction)
            .ok()?
            .ok()?;
        entries.into_iter().find_map(|(key, value)| {
            (key.as_uint() == Some(0x03))
                .then(|| value.as_uint().and_then(|n| u32::try_from(n).ok()))
                .flatten()
        })
    }

    /// The token's key-agreement public key, as COSE x / y.
    fn key_agreement(
        &mut self,
        protocol: Protocol,
        interaction: &Interaction,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut cbor = Cbor::new();
        cbor.map(2)
            .uint(0x01)
            .uint(protocol.id())
            .uint(0x02)
            .uint(PIN_GET_KEY_AGREEMENT);
        let entries = self
            .call_map(CTAP2_CLIENT_PIN, Some(cbor.finish()), interaction)?
            .map_err(map_ctap_error)?;
        let key = entries
            .into_iter()
            .find_map(|(key, value)| (key.as_uint() == Some(0x01)).then_some(value))
            .ok_or_else(|| Error::Malformed("no keyAgreement in the PIN response".into()))?
            .into_map()?;
        let coordinate = |label: i64| {
            key.iter()
                .find_map(|(k, v)| (k.as_int() == Some(label)).then(|| v.as_bytes()).flatten())
                .map(<[u8]>::to_vec)
                .ok_or_else(|| Error::Malformed("the keyAgreement key lacks a coordinate".into()))
        };
        Ok((coordinate(-2)?, coordinate(-3)?))
    }

    /// Ask for the PIN and trade it for a pinUvAuthToken, re-asking on a
    /// wrong PIN until the token's own retry policy stops it.
    fn pin_token(
        &mut self,
        protocol: Protocol,
        info: &Info,
        rp_id: &str,
        interaction: &Interaction,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let source = interaction.pin.clone().ok_or(Error::PinRequired)?;
        // CTAP 2.1 tokens scope the token to getAssertion on this rp;
        // CTAP 2.0 tokens only know the unscoped `getPinToken`.
        let scoped = info.option("pinUvAuthToken") == Some(true);
        let mut retries = self.pin_retries(protocol, interaction);
        let mut retry = false;

        for _ in 0..MAX_PIN_ATTEMPTS {
            if retries == Some(0) {
                return Err(Error::PinBlocked("reset the key with a FIDO2 tool"));
            }
            let pin = source(PinPrompt { retries, retry }).ok_or(Error::Cancelled)?;
            if interaction.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }

            let (x, y) = self.key_agreement(protocol, interaction)?;
            let agreement = pin::agree(protocol, &x, &y)?;
            let pin_hash_enc = agreement.secret.encrypt(pin::pin_hash(&pin).as_ref())?;
            drop(pin);

            let mut cbor = Cbor::new();
            cbor.map(if scoped { 6 } else { 4 })
                .uint(0x01)
                .uint(protocol.id())
                .uint(0x02)
                .uint(if scoped {
                    PIN_GET_TOKEN_WITH_PERMISSIONS
                } else {
                    PIN_GET_PIN_TOKEN
                })
                .uint(0x03);
            cose_key(&mut cbor, &agreement.x, &agreement.y);
            cbor.uint(0x06).bytes(&pin_hash_enc);
            if scoped {
                cbor.uint(0x09).uint(PERMISSION_GET_ASSERTION);
                cbor.uint(0x0a).text(rp_id);
            }

            match self.call_map(CTAP2_CLIENT_PIN, Some(cbor.finish()), interaction)? {
                Ok(entries) => {
                    let encrypted = entries
                        .into_iter()
                        .find_map(|(key, value)| {
                            (key.as_uint() == Some(0x02))
                                .then(|| value.as_bytes().map(<[u8]>::to_vec))
                                .flatten()
                        })
                        .ok_or_else(|| {
                            Error::Malformed("no pinUvAuthToken in the PIN response".into())
                        })?;
                    let token = agreement.secret.decrypt(&encrypted)?;
                    debug_assert_eq!(agreement.secret.protocol(), protocol);
                    return Ok(token);
                }
                Err(CTAP2_ERR_PIN_INVALID) => {
                    retries = self.pin_retries(protocol, interaction);
                    retry = true;
                }
                Err(CTAP2_ERR_PIN_POLICY_VIOLATION) => {
                    // Too short or too long for the token: the same answer
                    // as a wrong PIN from the person's side.
                    retry = true;
                }
                Err(code) => return Err(map_ctap_error(code)),
            }
        }
        Err(Error::PinInvalid {
            retries: retries.unwrap_or(0),
        })
    }
}

/// The platform key-agreement key as a COSE_Key, keys in canonical order
/// (1, 3, -1, -2, -3).
fn cose_key(cbor: &mut Cbor, x: &[u8; 32], y: &[u8; 32]) {
    cbor.map(5);
    cbor.uint(1).uint(2); // kty: EC2
    cbor.uint(3).int(-25); // alg: ECDH-ES + HKDF-256
    cbor.int(-1).uint(1); // crv: P-256
    cbor.int(-2).bytes(x);
    cbor.int(-3).bytes(y);
}

/// Open a CTAPHID channel with `CTAPHID_INIT`.
fn init_channel(transport: &mut dyn HidTransport, interaction: &Interaction) -> Result<u32, Error> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|e| Error::Transport(format!("no randomness for CTAPHID_INIT: {e}")))?;

    let mut packet = [0u8; HID_PACKET_LEN];
    packet[..4].copy_from_slice(&BROADCAST_CID.to_be_bytes());
    packet[4] = CMD_INIT;
    packet[5..7].copy_from_slice(&8u16.to_be_bytes());
    packet[7..15].copy_from_slice(&nonce);
    transport.write_packet(&packet)?;

    let deadline = Instant::now() + MACHINE_TIMEOUT;
    loop {
        if interaction.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(Error::DeviceNotFound(
                "the security key did not answer CTAPHID_INIT".into(),
            ));
        }
        let Some(reply) = transport.read_packet(POLL_INTERVAL)? else {
            continue;
        };
        if reply[4] == CMD_ERROR {
            return Err(map_hid_error(reply[7]));
        }
        // Only the broadcast reply carrying OUR nonce is ours.
        if reply[4] != CMD_INIT || reply[7..15] != nonce {
            continue;
        }
        let channel = u32::from_be_bytes([reply[15], reply[16], reply[17], reply[18]]);
        if channel == BROADCAST_CID || channel == 0 {
            return Err(Error::Transport(
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
) -> Result<(), Error> {
    // 128 continuation packets is the most a sequence byte can number.
    if payload.len() > (HID_PACKET_LEN - 7) + 128 * (HID_PACKET_LEN - 5) {
        return Err(Error::Malformed("CTAPHID message too long".into()));
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
        seq += 1;
    }
    Ok(())
}

/// `CTAPHID_ERROR` payloads. `0x0b` is what a token sends for a channel it
/// does not have open, which is also what a malformed request looks like.
fn map_hid_error(code: u8) -> Error {
    match code {
        0x05 => Error::TouchTimeout,
        0x06 => Error::Transport("the security key is busy".into()),
        0x0b => Error::Transport(
            "the security key did not recognise the channel; it may have been \
             reset or claimed by another program"
                .into(),
        ),
        other => Error::Transport(format!("CTAPHID error 0x{other:02x}")),
    }
}

fn map_ctap_error(code: u8) -> Error {
    match code {
        CTAP2_ERR_NO_CREDENTIALS => Error::CredentialNotFound,
        CTAP2_ERR_KEEPALIVE_CANCEL | CTAP2_ERR_OPERATION_DENIED => Error::Cancelled,
        CTAP1_ERR_TIMEOUT | CTAP2_ERR_USER_ACTION_TIMEOUT | CTAP2_ERR_ACTION_TIMEOUT => {
            Error::TouchTimeout
        }
        CTAP2_ERR_PUAT_REQUIRED => Error::PinRequired,
        CTAP2_ERR_PIN_NOT_SET => Error::PinNotSet,
        CTAP2_ERR_PIN_INVALID | CTAP2_ERR_PIN_AUTH_INVALID => Error::PinInvalid { retries: 0 },
        CTAP2_ERR_PIN_BLOCKED => Error::PinBlocked("reset the key with a FIDO2 tool"),
        CTAP2_ERR_PIN_AUTH_BLOCKED => Error::PinBlocked("unplug the key and plug it back in"),
        CTAP2_ERR_UV_BLOCKED => Error::UserVerificationBlocked,
        CTAP2_ERR_UP_REQUIRED => {
            Error::Transport("the security key requires a touch but none was requested".into())
        }
        // The token could not make sense of the request itself: the fault
        // is on our side of the wire, not the person's.
        CTAP2_ERR_CBOR_UNEXPECTED_TYPE => {
            Error::Malformed("the security key rejected the request's CBOR".into())
        }
        CTAP2_ERR_INVALID_CBOR => {
            Error::Malformed("the security key could not decode the request's CBOR".into())
        }
        CTAP2_ERR_MISSING_PARAMETER => {
            Error::Malformed("the security key wanted a parameter the request left out".into())
        }
        CTAP2_ERR_UNSUPPORTED_OPTION | CTAP2_ERR_INVALID_OPTION => Error::Malformed(
            "the security key does not accept one of the options the request asked for".into(),
        ),
        CTAP2_ERR_UNSUPPORTED_ALGORITHM => {
            Error::Malformed("the security key does not support this key's algorithm".into())
        }
        CTAP2_ERR_REQUEST_TOO_LARGE => {
            Error::Malformed("the request was larger than the security key accepts".into())
        }
        other => Error::Transport(format!(
            "the security key returned CTAP2 status 0x{other:02x}"
        )),
    }
}

/// `authenticatorGetAssertion`, command byte first.
fn encode_get_assertion(
    request: &AssertionRequest,
    client_data_hash: &[u8; 32],
    verification: Option<&Verification>,
) -> Result<Vec<u8>, Error> {
    let allow = request
        .allow_credential
        .as_deref()
        .filter(|handle| !handle.is_empty());
    let pin = match verification {
        Some(Verification::Pin { protocol, token }) => {
            Some((*protocol, protocol.authenticate(token, client_data_hash)))
        }
        _ => None,
    };
    let built_in_uv = matches!(verification, Some(Verification::BuiltIn));

    let mut cbor = Cbor::new();
    cbor.map(3 + usize::from(allow.is_some()) + 2 * usize::from(pin.is_some()));
    cbor.uint(0x01).text(&request.application);
    cbor.uint(0x02).bytes(client_data_hash);
    if let Some(handle) = allow {
        cbor.uint(0x03).array(1);
        // A WebAuthn dictionary, so TEXT keys, in canonical order: "id"
        // (2 bytes) before "type" (4 bytes).
        cbor.map(2);
        cbor.text("id").bytes(handle);
        cbor.text("type").text("public-key");
    }
    cbor.uint(0x05).map(1 + usize::from(built_in_uv));
    cbor.text("up").bool(request.user_presence);
    if built_in_uv {
        cbor.text("uv").bool(true);
    }
    if let Some((protocol, param)) = pin {
        cbor.uint(0x06).bytes(&param);
        cbor.uint(0x07).uint(protocol.id());
    }

    // A CTAPHID_CBOR body is the one-byte CTAP command, then the map.
    let parameters = cbor.finish();
    let mut payload = Vec::with_capacity(parameters.len() + 1);
    payload.push(CTAP2_GET_ASSERTION);
    payload.extend_from_slice(&parameters);
    Ok(payload)
}

fn parse_get_assertion(bytes: &[u8]) -> Result<Assertion, Error> {
    let entries = cbor::decode(&bytes[1..])?.0.into_map()?;

    let mut auth_data: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    for (key, value) in entries {
        match (key.as_uint(), value) {
            (Some(0x02), Value::Bytes(data)) => auth_data = Some(data),
            (Some(0x03), Value::Bytes(sig)) => signature = Some(sig),
            _ => {}
        }
    }

    // rpIdHash(32) || flags(1) || signCount(4): the five bytes after the
    // hash are echoed into the SSH signature blob verbatim.
    let auth_data = auth_data.ok_or_else(|| Error::Malformed("no authData".into()))?;
    if auth_data.len() < 37 {
        return Err(Error::Malformed(format!(
            "authData is {} bytes, too short to carry flags and a counter",
            auth_data.len()
        )));
    }
    let signature = signature.ok_or_else(|| Error::Malformed("no signature".into()))?;

    Ok(Assertion {
        signature,
        flags: auth_data[32],
        counter: u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]),
    })
}

#[cfg(test)]
mod tests;
