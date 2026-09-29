use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use p256::elliptic_curve::sec1::ToSec1Point;

use super::*;
use crate::CancelToken;
use crate::pin::SharedSecret;

/// A scripted token. It answers `CTAPHID_INIT` for real (echoing the
/// nonce, the one field a test cannot know in advance) and replays a
/// canned packet stream for everything else.
struct ScriptedDevice {
    channel: u32,
    capabilities: u8,
    replies: VecDeque<[u8; HID_PACKET_LEN]>,
    written: Vec<[u8; HID_PACKET_LEN]>,
}

impl ScriptedDevice {
    fn new(channel: u32, replies: Vec<[u8; HID_PACKET_LEN]>) -> Self {
        Self {
            channel,
            capabilities: CAPFLAG_CBOR,
            replies: replies.into(),
            written: Vec::new(),
        }
    }

    /// A token that answers INIT without `CAPFLAG_CBOR`: U2F only.
    fn u2f_only(channel: u32, replies: Vec<[u8; HID_PACKET_LEN]>) -> Self {
        Self {
            capabilities: 0,
            ..Self::new(channel, replies)
        }
    }
}

/// An initial packet whose length field is the TOTAL message length, as
/// the spec says: the remainder arrives in continuation packets.
fn initial_with_total(
    channel: u32,
    command: u8,
    total_len: usize,
    payload: &[u8],
) -> [u8; HID_PACKET_LEN] {
    assert!(payload.len() <= HID_PACKET_LEN - 7);
    let mut packet = [0u8; HID_PACKET_LEN];
    packet[..4].copy_from_slice(&channel.to_be_bytes());
    packet[4] = command;
    packet[5..7].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[7..7 + payload.len()].copy_from_slice(payload);
    packet
}

fn initial(channel: u32, command: u8, payload: &[u8]) -> [u8; HID_PACKET_LEN] {
    initial_with_total(channel, command, payload.len(), payload)
}

fn continuation(channel: u32, seq: u8, payload: &[u8]) -> [u8; HID_PACKET_LEN] {
    let mut packet = [0u8; HID_PACKET_LEN];
    packet[..4].copy_from_slice(&channel.to_be_bytes());
    packet[4] = seq;
    packet[5..5 + payload.len()].copy_from_slice(payload);
    packet
}

/// Fragment one message the way a token does.
fn packets(channel: u32, command: u8, message: &[u8]) -> Vec<[u8; HID_PACKET_LEN]> {
    let first = message.len().min(HID_PACKET_LEN - 7);
    let mut out = vec![initial_with_total(channel, command, message.len(), &message[..first])];
    let mut sent = first;
    let mut seq: u8 = 0;
    while sent < message.len() {
        let take = (message.len() - sent).min(HID_PACKET_LEN - 5);
        out.push(continuation(channel, seq, &message[sent..sent + take]));
        sent += take;
        seq += 1;
    }
    out
}

/// The 17-byte `CTAPHID_INIT` reply: nonce, channel, versions, caps.
fn init_reply(nonce: &[u8], channel: u32, capabilities: u8) -> [u8; HID_PACKET_LEN] {
    let mut body = Vec::with_capacity(17);
    body.extend_from_slice(nonce);
    body.extend_from_slice(&channel.to_be_bytes());
    body.extend_from_slice(&[2, 0, 0, 0, capabilities]);
    initial(BROADCAST_CID, CMD_INIT, &body)
}

/// Reassemble the message whose initial packet is `written[index]`: its
/// command byte and payload, continuation packets included.
fn sent_message(written: &[[u8; HID_PACKET_LEN]], index: usize) -> (u8, Vec<u8>) {
    let first = &written[index];
    let len = u16::from_be_bytes([first[5], first[6]]) as usize;
    let mut payload = first[7..].to_vec();
    let mut next = index + 1;
    while payload.len() < len {
        payload.extend_from_slice(&written[next][5..]);
        next += 1;
    }
    payload.truncate(len);
    (first[4], payload)
}

fn is_broadcast_init(packet: &[u8; HID_PACKET_LEN]) -> bool {
    packet[4] == CMD_INIT
        && u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) == BROADCAST_CID
}

impl HidTransport for ScriptedDevice {
    fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), Error> {
        self.written.push(*packet);
        if is_broadcast_init(packet) {
            self.replies
                .push_front(init_reply(&packet[7..15], self.channel, self.capabilities));
        }
        Ok(())
    }

    fn read_packet(&mut self, _timeout: Duration) -> Result<Option<[u8; HID_PACKET_LEN]>, Error> {
        Ok(self.replies.pop_front())
    }
}

fn request() -> AssertionRequest {
    AssertionRequest {
        application: "ssh:".into(),
        message: vec![0x42; 32],
        allow_credential: Some(vec![1, 2, 3, 4]),
        user_presence: true,
        user_verification: false,
    }
}

/// `authData` with the given flags and counter.
fn auth_data(flags: u8, counter: u32) -> Vec<u8> {
    let mut data = vec![0u8; 37];
    data[32] = flags;
    data[33..37].copy_from_slice(&counter.to_be_bytes());
    data
}

/// `CTAP2_OK || { 0x02: authData, 0x03: signature }`.
fn assertion_message(flags: u8, counter: u32, signature: &[u8]) -> Vec<u8> {
    let mut cbor = Cbor::new();
    cbor.map(2);
    cbor.uint(0x02).bytes(&auth_data(flags, counter));
    cbor.uint(0x03).bytes(signature);
    let mut message = vec![CTAP2_OK];
    message.extend(cbor.finish());
    message
}

fn run(device: &mut dyn HidTransport, request: &AssertionRequest) -> Result<Assertion, Error> {
    get_assertion(device, request, &Interaction::default(), Duration::from_secs(5))
}

/// The shape a real token produces: a keepalive while the user reaches
/// for it, then a response that does not fit in one packet.
#[test]
fn assembles_a_multi_packet_assertion_after_a_keepalive() {
    let signature = vec![0x7au8; 64];
    let message = assertion_message(0x05, 9, &signature);
    assert!(message.len() > 57, "the test must actually split packets");

    let mut replies = vec![initial(7, CMD_KEEPALIVE, &[KEEPALIVE_UP_NEEDED])];
    replies.extend(packets(7, CMD_CBOR, &message));
    let mut device = ScriptedDevice::new(7, replies);

    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let interaction = Interaction {
        events: Some(Arc::new(move |event| seen.lock().unwrap().push(event))),
        ..Interaction::default()
    };
    let assertion =
        get_assertion(&mut device, &request(), &interaction, Duration::from_secs(5)).unwrap();

    assert_eq!(assertion.flags, 0x05);
    assert_eq!(assertion.counter, 9);
    assert_eq!(assertion.signature, signature);
    assert_eq!(*events.lock().unwrap(), vec![TokenEvent::TouchNeeded]);

    // INIT went to the broadcast channel; the request to the one INIT
    // handed back.
    assert_eq!(&device.written[0][..4], &BROADCAST_CID.to_be_bytes());
    assert_eq!(device.written[0][4], CMD_INIT);
    assert_eq!(&device.written[1][..4], &7u32.to_be_bytes());
    assert_eq!(device.written[1][4], CMD_CBOR);
}

/// A token waiting on a person sends a keepalive every ~100 ms. The event
/// is reported once per kind, not once per keepalive.
#[test]
fn repeated_keepalives_announce_the_wait_once() {
    let message = assertion_message(0x01, 0, &[0u8; 64]);
    let mut replies = vec![initial(3, CMD_KEEPALIVE, &[KEEPALIVE_UP_NEEDED]); 5];
    replies.extend(packets(3, CMD_CBOR, &message));
    let mut device = ScriptedDevice::new(3, replies);
    let count = Arc::new(Mutex::new(0));
    let seen = Arc::clone(&count);
    let interaction = Interaction {
        events: Some(Arc::new(move |_| *seen.lock().unwrap() += 1)),
        ..Interaction::default()
    };
    get_assertion(&mut device, &request(), &interaction, Duration::from_secs(5)).unwrap();
    assert_eq!(*count.lock().unwrap(), 1);
}

#[test]
fn a_uv_keepalive_is_reported_as_verification() {
    let message = assertion_message(0x05, 0, &[0u8; 64]);
    let mut replies = vec![initial(3, CMD_KEEPALIVE, &[KEEPALIVE_UV_NEEDED])];
    replies.extend(packets(3, CMD_CBOR, &message));
    let mut device = ScriptedDevice::new(3, replies);
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let interaction = Interaction {
        events: Some(Arc::new(move |event| seen.lock().unwrap().push(event))),
        ..Interaction::default()
    };
    get_assertion(&mut device, &request(), &interaction, Duration::from_secs(5)).unwrap();
    assert_eq!(*events.lock().unwrap(), vec![TokenEvent::VerificationNeeded]);
}

/// A token that never answers fails with the named timeout and is told to
/// stop, instead of hanging until the connection gives up.
#[test]
fn an_unanswered_touch_times_out_and_cancels() {
    let mut device = ScriptedDevice::new(1, vec![]);
    let err = get_assertion(
        &mut device,
        &request(),
        &Interaction::default(),
        Duration::from_millis(1),
    )
    .unwrap_err();
    assert!(matches!(err, Error::TouchTimeout), "got {err:?}");
    assert_eq!(device.written.last().unwrap()[4], CMD_CANCEL);
}

/// Keepalives must not extend the touch budget. A token that is present
/// and untouched sends one every ~100 ms forever (well, until its own
/// clock), and counting only EMPTY reads never reached the deadline.
#[test]
fn keepalives_do_not_extend_the_touch_budget() {
    struct Nagging(ScriptedDevice);
    impl HidTransport for Nagging {
        fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), Error> {
            self.0.write_packet(packet)
        }
        fn read_packet(&mut self, t: Duration) -> Result<Option<[u8; HID_PACKET_LEN]>, Error> {
            if let Some(packet) = self.0.read_packet(t)? {
                return Ok(Some(packet));
            }
            std::thread::sleep(Duration::from_millis(1));
            Ok(Some(initial(self.0.channel, CMD_KEEPALIVE, &[KEEPALIVE_UP_NEEDED])))
        }
    }
    let mut device = Nagging(ScriptedDevice::new(1, vec![]));
    let started = Instant::now();
    let err = get_assertion(
        &mut device,
        &request(),
        &Interaction::default(),
        Duration::from_millis(50),
    )
    .unwrap_err();
    assert!(matches!(err, Error::TouchTimeout), "got {err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// A cancel from another thread ends the wait and tells the token.
#[test]
fn a_cancel_ends_the_wait_and_tells_the_token() {
    let mut device = ScriptedDevice::new(1, vec![]);
    let interaction = Interaction::default();
    let cancel = interaction.cancel.clone();
    let waiter = std::thread::spawn(move || {
        let result = get_assertion(&mut device, &request(), &interaction, Duration::from_secs(60));
        (result, device)
    });
    std::thread::sleep(Duration::from_millis(20));
    cancel.cancel();
    let (result, device) = waiter.join().unwrap();
    assert!(matches!(result, Err(Error::Cancelled)), "got {result:?}");
    assert_eq!(device.written.last().unwrap()[4], CMD_CANCEL);
}

#[test]
fn no_credentials_maps_to_a_named_error() {
    let mut device =
        ScriptedDevice::new(1, vec![initial(1, CMD_CBOR, &[CTAP2_ERR_NO_CREDENTIALS])]);
    let err = run(&mut device, &request()).unwrap_err();
    assert!(matches!(err, Error::CredentialNotFound), "got {err:?}");
}

/// A CTAPHID error carries its code in the payload byte, not the length
/// field. Reading the wrong byte turns every error into a timeout.
#[test]
fn a_hid_error_is_read_from_the_payload() {
    let mut device = ScriptedDevice::new(1, vec![initial(1, CMD_ERROR, &[0x0b])]);
    match run(&mut device, &request()).unwrap_err() {
        Error::Transport(message) => {
            assert!(message.contains("did not recognise the channel"), "got {message}")
        }
        other => panic!("expected a transport error, got {other:?}"),
    }
}

/// The encoded request is the exact CBOR a token expects, in canonical
/// key order at every level.
#[test]
fn encodes_the_documented_request_shape() {
    let hash: [u8; 32] = Sha256::digest(request().message).into();
    let bytes = encode_get_assertion(&request(), &hash, None).unwrap();
    assert_eq!(bytes[0], CTAP2_GET_ASSERTION, "the CTAP command byte leads");
    let (value, used) = cbor::decode(&bytes[1..]).unwrap();
    assert_eq!(used, bytes.len() - 1, "no padding after the CBOR");
    let entries = value.into_map().unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0], (Value::Uint(0x01), Value::Text("ssh:".into())));
    // The token is given a HASH of the message; the message itself would
    // still be well-formed and would produce a signature no server takes.
    assert_eq!(entries[1], (Value::Uint(0x02), Value::Bytes(hash.to_vec())));

    let Value::Array(descriptors) = &entries[2].1 else {
        panic!("expected an allow-list array");
    };
    let Value::Map(descriptor) = &descriptors[0] else {
        panic!("expected a descriptor map");
    };
    assert_eq!(
        descriptor,
        &vec![
            (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3, 4])),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ],
        "canonical CBOR puts the shorter key first"
    );

    let Value::Map(options) = &entries[3].1 else {
        panic!("expected an options map");
    };
    assert_eq!(options, &vec![(Value::Text("up".into()), Value::Bool(true))]);
}

#[test]
fn a_request_without_a_handle_omits_the_allow_list() {
    for allow in [None, Some(Vec::new())] {
        let mut request = request();
        request.allow_credential = allow;
        let bytes = encode_get_assertion(&request, &[0; 32], None).unwrap();
        let entries = cbor::decode(&bytes[1..]).unwrap().0.into_map().unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|(key, _)| key.as_uint() != Some(0x03)));
    }
}

/// The decoder survives a real response, which carries fields we ignore.
#[test]
fn ignores_response_fields_we_do_not_use() {
    let mut cbor = Cbor::new();
    cbor.map(4);
    cbor.uint(0x01).map(2);
    cbor.text("id").bytes(&[1, 2, 3, 4]);
    cbor.text("type").text("public-key");
    cbor.uint(0x02).bytes(&auth_data(0x01, 0));
    cbor.uint(0x03).bytes(&[0x11u8; 64]);
    cbor.uint(0x05).uint(1);
    let mut message = vec![CTAP2_OK];
    message.extend(cbor.finish());

    let mut device = ScriptedDevice::new(2, packets(2, CMD_CBOR, &message));
    let assertion = run(&mut device, &request()).unwrap();
    assert_eq!(assertion.flags, 0x01);
    assert_eq!(assertion.signature, vec![0x11u8; 64]);
}

/// The literals are pinned on purpose: every other test builds its packets
/// from these same constants, so a wrong constant is invisible to them.
#[test]
fn every_command_byte_carries_the_initial_packet_flag() {
    assert_eq!(CMD_MSG, 0x83, "CTAPHID_MSG");
    assert_eq!(CMD_INIT, 0x86, "CTAPHID_INIT");
    assert_eq!(CMD_CBOR, 0x90, "CTAPHID_CBOR");
    assert_eq!(CMD_CANCEL, 0x91, "CTAPHID_CANCEL");
    assert_eq!(CMD_KEEPALIVE, 0xbb, "CTAPHID_KEEPALIVE");
    assert_eq!(CMD_ERROR, 0xbf, "CTAPHID_ERROR");
}

#[test]
fn the_init_request_goes_out_with_the_flag_set() {
    let mut device = ScriptedDevice::new(0x1234_5678, vec![]);
    let (channel, capabilities) = init_channel(&mut device, &Interaction::default()).unwrap();
    assert_eq!(channel, 0x1234_5678);
    assert_eq!(capabilities, CAPFLAG_CBOR);
    let init = device.written[0];
    assert_eq!(&init[..4], &BROADCAST_CID.to_be_bytes(), "broadcast");
    assert_eq!(init[4], 0x86, "CTAPHID_INIT is 0x86 on the wire");
    assert_eq!(&init[5..7], &8u16.to_be_bytes(), "an 8-byte nonce");
}

/// Pinned as literals for the same reason as the command bytes.
#[test]
fn the_ctap_status_codes_are_the_spec_numbers() {
    assert_eq!(CTAP2_OK, 0x00);
    assert_eq!(CTAP1_ERR_TIMEOUT, 0x05);
    assert_eq!(CTAP2_ERR_CBOR_UNEXPECTED_TYPE, 0x11);
    assert_eq!(CTAP2_ERR_INVALID_CBOR, 0x12);
    assert_eq!(CTAP2_ERR_MISSING_PARAMETER, 0x14);
    assert_eq!(CTAP2_ERR_UNSUPPORTED_ALGORITHM, 0x26);
    assert_eq!(CTAP2_ERR_OPERATION_DENIED, 0x27);
    assert_eq!(CTAP2_ERR_UNSUPPORTED_OPTION, 0x2b);
    assert_eq!(CTAP2_ERR_INVALID_OPTION, 0x2c);
    assert_eq!(CTAP2_ERR_KEEPALIVE_CANCEL, 0x2d);
    assert_eq!(CTAP2_ERR_NO_CREDENTIALS, 0x2e);
    assert_eq!(CTAP2_ERR_USER_ACTION_TIMEOUT, 0x2f);
    assert_eq!(CTAP2_ERR_PIN_INVALID, 0x31);
    assert_eq!(CTAP2_ERR_PIN_BLOCKED, 0x32);
    assert_eq!(CTAP2_ERR_PIN_AUTH_INVALID, 0x33);
    assert_eq!(CTAP2_ERR_PIN_AUTH_BLOCKED, 0x34);
    assert_eq!(CTAP2_ERR_PIN_NOT_SET, 0x35);
    assert_eq!(CTAP2_ERR_PUAT_REQUIRED, 0x36);
    assert_eq!(CTAP2_ERR_PIN_POLICY_VIOLATION, 0x37);
    assert_eq!(CTAP2_ERR_REQUEST_TOO_LARGE, 0x39);
    assert_eq!(CTAP2_ERR_ACTION_TIMEOUT, 0x3a);
    assert_eq!(CTAP2_ERR_UP_REQUIRED, 0x3b);
    assert_eq!(CTAP2_ERR_UV_BLOCKED, 0x3c);
    assert_eq!(CTAP2_GET_ASSERTION, 0x02);
    assert_eq!(CTAP2_GET_INFO, 0x04);
    assert_eq!(CTAP2_CLIENT_PIN, 0x06);
}

#[test]
fn a_cbor_complaint_is_our_fault_not_the_users() {
    for code in [
        CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
        CTAP2_ERR_INVALID_CBOR,
        CTAP2_ERR_MISSING_PARAMETER,
        CTAP2_ERR_UNSUPPORTED_OPTION,
        CTAP2_ERR_INVALID_OPTION,
    ] {
        let mut device = ScriptedDevice::new(1, vec![initial(1, CMD_CBOR, &[code])]);
        let err = run(&mut device, &request()).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)), "0x{code:02x}: {err:?}");
    }
}

// ---------------------------------------------------------------------------
// A simulated token that speaks the PIN protocol for real.
// ---------------------------------------------------------------------------

/// What the simulated token is configured with.
#[derive(Clone)]
struct TokenConfig {
    pin: Option<&'static str>,
    built_in_uv: bool,
    pin_protocols: Vec<u64>,
    /// CTAP 2.1: supports getPinUvAuthTokenUsingPinWithPermissions.
    scoped_tokens: bool,
    /// Refuses getAssertion without user verification.
    always_uv: bool,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            pin: Some("1234"),
            built_in_uv: false,
            pin_protocols: vec![2, 1],
            scoped_tokens: true,
            always_uv: false,
        }
    }
}

/// A CTAP2 authenticator in software: reassembles CTAPHID messages,
/// answers getInfo / clientPIN / getAssertion, and checks pinUvAuthParam
/// with keys it derives on its own side of the ECDH.
struct FakeToken {
    config: TokenConfig,
    channel: u32,
    retries: u32,
    key: p256::SecretKey,
    shared: Option<SharedSecret>,
    pin_token: [u8; 32],
    incoming: Vec<u8>,
    incoming_len: usize,
    replies: VecDeque<[u8; HID_PACKET_LEN]>,
    /// Every CTAP2 command byte received, in order.
    commands: Vec<u8>,
    /// The subcommand of every clientPIN call.
    pin_calls: Vec<u64>,
    /// Whether the last getAssertion arrived verified, and how.
    last_uv: Option<&'static str>,
}

impl FakeToken {
    fn new(config: TokenConfig) -> Self {
        Self {
            config,
            channel: 0x0bad_cafe,
            retries: 8,
            key: crate::pin::ephemeral_key().unwrap(),
            shared: None,
            pin_token: [0x5a; 32],
            incoming: Vec::new(),
            incoming_len: 0,
            replies: VecDeque::new(),
            commands: Vec::new(),
            pin_calls: Vec::new(),
            last_uv: None,
        }
    }

    fn respond(&mut self, status: u8, body: Option<Vec<u8>>) {
        let mut message = vec![status];
        if let Some(body) = body {
            message.extend(body);
        }
        self.replies.extend(packets(self.channel, CMD_CBOR, &message));
    }

    fn handle(&mut self, message: Vec<u8>) {
        let command = message[0];
        self.commands.push(command);
        let params = if message.len() > 1 {
            cbor::decode(&message[1..]).unwrap().0.into_map().unwrap()
        } else {
            Vec::new()
        };
        let get = |label: u64| {
            params
                .iter()
                .find_map(|(k, v)| (k.as_uint() == Some(label)).then(|| v.clone()))
        };
        match command {
            CTAP2_GET_INFO => {
                let mut options = vec![("rk", true), ("up", true)];
                options.push(("clientPin", self.config.pin.is_some()));
                if self.config.built_in_uv {
                    options.push(("uv", true));
                }
                if self.config.scoped_tokens {
                    options.push(("pinUvAuthToken", true));
                }
                let mut cbor = Cbor::new();
                cbor.map(2);
                cbor.uint(0x04).map(options.len());
                for (name, value) in &options {
                    cbor.text(name).bool(*value);
                }
                cbor.uint(0x06).array(self.config.pin_protocols.len());
                for id in &self.config.pin_protocols {
                    cbor.uint(*id);
                }
                self.respond(CTAP2_OK, Some(cbor.finish()));
            }
            CTAP2_CLIENT_PIN => {
                let protocol = match get(0x01).and_then(|v| v.as_uint()) {
                    Some(1) => Protocol::One,
                    _ => Protocol::Two,
                };
                let sub = get(0x02).and_then(|v| v.as_uint()).unwrap();
                self.pin_calls.push(sub);
                match sub {
                    PIN_GET_RETRIES => {
                        let mut cbor = Cbor::new();
                        cbor.map(1).uint(0x03).uint(self.retries as u64);
                        self.respond(CTAP2_OK, Some(cbor.finish()));
                    }
                    PIN_GET_KEY_AGREEMENT => {
                        let point = self.key.public_key().to_sec1_point(false);
                        let bytes = point.as_bytes();
                        let mut cbor = Cbor::new();
                        cbor.map(1).uint(0x01);
                        let x: [u8; 32] = bytes[1..33].try_into().unwrap();
                        let y: [u8; 32] = bytes[33..65].try_into().unwrap();
                        cose_key(&mut cbor, &x, &y);
                        self.respond(CTAP2_OK, Some(cbor.finish()));
                    }
                    PIN_GET_PIN_TOKEN | PIN_GET_TOKEN_WITH_PERMISSIONS => {
                        if sub == PIN_GET_TOKEN_WITH_PERMISSIONS {
                            assert!(self.config.scoped_tokens, "2.0 token got a 2.1 call");
                            assert_eq!(get(0x09).and_then(|v| v.as_uint()), Some(0x02));
                            assert_eq!(get(0x0a), Some(Value::Text("ssh:".into())));
                        }
                        let platform = get(0x03).unwrap().into_map().unwrap();
                        let coord = |label: i64| {
                            platform
                                .iter()
                                .find_map(|(k, v)| {
                                    (k.as_int() == Some(label)).then(|| v.as_bytes().unwrap().to_vec())
                                })
                                .unwrap()
                        };
                        let mut encoded = vec![0x04];
                        encoded.extend(coord(-2));
                        encoded.extend(coord(-3));
                        let peer = p256::PublicKey::from_sec1_bytes(&encoded).unwrap();
                        let z = <[u8; 32]>::from(*self.key.diffie_hellman(&peer).raw_secret_bytes());
                        let shared = SharedSecret::derive(protocol, &z);
                        let pin_hash = shared
                            .decrypt(get(0x06).unwrap().as_bytes().unwrap())
                            .unwrap();
                        let expected = crate::pin::pin_hash(self.config.pin.unwrap());
                        if pin_hash.as_slice() != expected.as_ref() {
                            self.retries -= 1;
                            self.respond(CTAP2_ERR_PIN_INVALID, None);
                            return;
                        }
                        let encrypted = shared.encrypt(&self.pin_token).unwrap();
                        self.shared = Some(shared);
                        let mut cbor = Cbor::new();
                        cbor.map(1).uint(0x02).bytes(&encrypted);
                        self.respond(CTAP2_OK, Some(cbor.finish()));
                    }
                    other => panic!("unexpected clientPIN subcommand {other}"),
                }
            }
            CTAP2_GET_ASSERTION => {
                let hash = get(0x02).unwrap().as_bytes().unwrap().to_vec();
                let options = get(0x05).unwrap().into_map().unwrap();
                let uv_option = options
                    .iter()
                    .any(|(k, v)| *k == Value::Text("uv".into()) && *v == Value::Bool(true));
                let mut flags = 0x01;
                self.last_uv = None;
                if let Some(param) = get(0x06) {
                    let protocol = match get(0x07).and_then(|v| v.as_uint()) {
                        Some(1) => Protocol::One,
                        _ => Protocol::Two,
                    };
                    let expected = protocol.authenticate(&self.pin_token, &hash);
                    if param.as_bytes().unwrap() != expected.as_slice() {
                        self.respond(CTAP2_ERR_PIN_AUTH_INVALID, None);
                        return;
                    }
                    flags |= 0x04;
                    self.last_uv = Some("pin");
                } else if uv_option {
                    assert!(self.config.built_in_uv, "uv option on a token without uv");
                    flags |= 0x04;
                    self.last_uv = Some("built-in");
                } else if self.config.always_uv {
                    self.respond(CTAP2_ERR_PUAT_REQUIRED, None);
                    return;
                }
                let mut cbor = Cbor::new();
                cbor.map(2);
                cbor.uint(0x02).bytes(&auth_data(flags, 1));
                cbor.uint(0x03).bytes(&[0x33; 64]);
                self.respond(CTAP2_OK, Some(cbor.finish()));
            }
            other => panic!("unexpected CTAP2 command 0x{other:02x}"),
        }
    }
}

impl HidTransport for FakeToken {
    fn write_packet(&mut self, packet: &[u8; HID_PACKET_LEN]) -> Result<(), Error> {
        if is_broadcast_init(packet) {
            self.replies
                .push_back(init_reply(&packet[7..15], self.channel, CAPFLAG_CBOR));
            return Ok(());
        }
        if packet[4] == CMD_CANCEL {
            return Ok(());
        }
        if packet[4] & INIT_PACKET_FLAG != 0 {
            assert_eq!(packet[4], CMD_CBOR);
            self.incoming_len = u16::from_be_bytes([packet[5], packet[6]]) as usize;
            let take = self.incoming_len.min(HID_PACKET_LEN - 7);
            self.incoming = packet[7..7 + take].to_vec();
        } else {
            let take = (self.incoming_len - self.incoming.len()).min(HID_PACKET_LEN - 5);
            self.incoming.extend_from_slice(&packet[5..5 + take]);
        }
        if self.incoming.len() == self.incoming_len {
            let message = std::mem::take(&mut self.incoming);
            self.handle(message);
        }
        Ok(())
    }

    fn read_packet(&mut self, _timeout: Duration) -> Result<Option<[u8; HID_PACKET_LEN]>, Error> {
        Ok(self.replies.pop_front())
    }
}

/// An interaction whose PIN prompt answers from a list and records what
/// it was asked.
fn pin_interaction(answers: Vec<Option<&'static str>>) -> (Interaction, Arc<Mutex<Vec<PinPrompt>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&asked);
    let answers = Arc::new(Mutex::new(VecDeque::from(answers)));
    let interaction = Interaction {
        cancel: CancelToken::new(),
        events: None,
        pin: Some(Arc::new(move |prompt| {
            log.lock().unwrap().push(prompt);
            answers
                .lock()
                .unwrap()
                .pop_front()
                .flatten()
                .map(|pin| Zeroizing::new(pin.to_string()))
        })),
    };
    (interaction, asked)
}

fn uv_request() -> AssertionRequest {
    AssertionRequest {
        user_verification: true,
        ..request()
    }
}

#[test]
fn a_verify_required_key_trades_the_pin_for_a_token_under_both_protocols() {
    for (protocols, scoped) in [(vec![2, 1], true), (vec![1], false)] {
        let mut token = FakeToken::new(TokenConfig {
            pin_protocols: protocols,
            scoped_tokens: scoped,
            ..TokenConfig::default()
        });
        let (interaction, asked) = pin_interaction(vec![Some("1234")]);
        let assertion =
            get_assertion(&mut token, &uv_request(), &interaction, Duration::from_secs(5)).unwrap();
        assert_eq!(assertion.flags & 0x04, 0x04, "the assertion is user-verified");
        assert_eq!(token.last_uv, Some("pin"));
        assert_eq!(
            *asked.lock().unwrap(),
            vec![PinPrompt { retries: Some(8), retry: false }]
        );
        let expected_sub = if scoped {
            PIN_GET_TOKEN_WITH_PERMISSIONS
        } else {
            PIN_GET_PIN_TOKEN
        };
        assert_eq!(
            token.pin_calls,
            vec![PIN_GET_RETRIES, PIN_GET_KEY_AGREEMENT, expected_sub]
        );
    }
}

#[test]
fn a_wrong_pin_is_asked_again_with_the_retries_left() {
    let mut token = FakeToken::new(TokenConfig::default());
    let (interaction, asked) = pin_interaction(vec![Some("0000"), Some("1234")]);
    get_assertion(&mut token, &uv_request(), &interaction, Duration::from_secs(5)).unwrap();
    assert_eq!(
        *asked.lock().unwrap(),
        vec![
            PinPrompt { retries: Some(8), retry: false },
            PinPrompt { retries: Some(7), retry: true },
        ]
    );
}

#[test]
fn three_wrong_pins_stop_before_the_token_soft_blocks() {
    let mut token = FakeToken::new(TokenConfig::default());
    let (interaction, asked) = pin_interaction(vec![Some("0"), Some("1"), Some("2"), Some("1234")]);
    let err = get_assertion(&mut token, &uv_request(), &interaction, Duration::from_secs(5))
        .unwrap_err();
    assert!(matches!(err, Error::PinInvalid { retries: 5 }), "got {err:?}");
    assert_eq!(asked.lock().unwrap().len(), 3);
}

#[test]
fn declining_the_pin_prompt_cancels_without_touching_the_assertion() {
    let mut token = FakeToken::new(TokenConfig::default());
    let (interaction, _) = pin_interaction(vec![None]);
    let err = get_assertion(&mut token, &uv_request(), &interaction, Duration::from_secs(5))
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled), "got {err:?}");
    assert!(!token.commands.contains(&CTAP2_GET_ASSERTION));
}

#[test]
fn no_pin_source_is_a_named_error_not_a_hang() {
    let mut token = FakeToken::new(TokenConfig::default());
    let err = get_assertion(
        &mut token,
        &uv_request(),
        &Interaction::default(),
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(matches!(err, Error::PinRequired), "got {err:?}");
}

#[test]
fn built_in_verification_is_preferred_over_asking_for_the_pin() {
    let mut token = FakeToken::new(TokenConfig {
        built_in_uv: true,
        ..TokenConfig::default()
    });
    let (interaction, asked) = pin_interaction(vec![Some("1234")]);
    let assertion =
        get_assertion(&mut token, &uv_request(), &interaction, Duration::from_secs(5)).unwrap();
    assert_eq!(assertion.flags & 0x04, 0x04);
    assert_eq!(token.last_uv, Some("built-in"));
    assert!(asked.lock().unwrap().is_empty(), "no PIN prompt");
    assert!(token.pin_calls.is_empty());
}

#[test]
fn a_verify_required_key_on_a_token_without_a_pin_says_so() {
    let mut token = FakeToken::new(TokenConfig {
        pin: None,
        ..TokenConfig::default()
    });
    let (interaction, _) = pin_interaction(vec![Some("1234")]);
    let err = get_assertion(&mut token, &uv_request(), &interaction, Duration::from_secs(5))
        .unwrap_err();
    assert!(matches!(err, Error::PinNotSet), "got {err:?}");
}

#[test]
fn a_touch_only_request_never_asks_for_a_pin() {
    let mut token = FakeToken::new(TokenConfig::default());
    let (interaction, asked) = pin_interaction(vec![Some("1234")]);
    let assertion =
        get_assertion(&mut token, &request(), &interaction, Duration::from_secs(5)).unwrap();
    assert_eq!(assertion.flags & 0x04, 0);
    assert!(asked.lock().unwrap().is_empty());
    assert_eq!(token.commands, vec![CTAP2_GET_ASSERTION]);
}

/// An `alwaysUv` token refuses a touch-only request with PUAT_REQUIRED;
/// the request is then verified and sent again, once.
#[test]
fn a_token_that_always_wants_verification_gets_it_on_the_second_try() {
    let mut token = FakeToken::new(TokenConfig {
        always_uv: true,
        ..TokenConfig::default()
    });
    let (interaction, asked) = pin_interaction(vec![Some("1234")]);
    let assertion =
        get_assertion(&mut token, &request(), &interaction, Duration::from_secs(5)).unwrap();
    assert_eq!(assertion.flags & 0x04, 0x04);
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert_eq!(
        token.commands,
        vec![
            CTAP2_GET_ASSERTION,
            CTAP2_GET_INFO,
            CTAP2_CLIENT_PIN,
            CTAP2_CLIENT_PIN,
            CTAP2_CLIENT_PIN,
            CTAP2_GET_ASSERTION,
        ]
    );
}

#[test]
fn the_platform_key_goes_out_as_a_canonical_cose_key() {
    let mut cbor = Cbor::new();
    cose_key(&mut cbor, &[1; 32], &[2; 32]);
    let entries = cbor::decode(&cbor.finish()).unwrap().0.into_map().unwrap();
    let keys: Vec<Vec<u8>> = entries
        .iter()
        .map(|(key, _)| {
            let mut cbor = Cbor::new();
            cbor.int(key.as_int().unwrap());
            cbor.finish()
        })
        .collect();
    assert!(cbor::is_canonical_order(&keys));
    assert_eq!(entries[1].1, Value::Neg(-25), "ECDH-ES + HKDF-256");
    assert_eq!(entries[2].1, Value::Uint(1), "P-256");
}

/// The response side of the PIN token has no business in the clear: pin
/// the protocol helpers against an independent derivation.
#[test]
fn the_simulated_token_really_derives_its_own_secret() {
    let token_key = crate::pin::ephemeral_key().unwrap();
    let point = token_key.public_key().to_sec1_point(false);
    let agreement =
        crate::pin::agree(Protocol::Two, &point.as_bytes()[1..33], &point.as_bytes()[33..65])
            .unwrap();
    let mut encoded = vec![0x04];
    encoded.extend_from_slice(&agreement.x);
    encoded.extend_from_slice(&agreement.y);
    let platform = p256::PublicKey::from_sec1_bytes(&encoded).unwrap();
    let z = <[u8; 32]>::from(*token_key.diffie_hellman(&platform).raw_secret_bytes());
    let theirs = SharedSecret::derive(Protocol::Two, &z);
    let sent = agreement.secret.encrypt(&[9u8; 16]).unwrap();
    assert_eq!(theirs.decrypt(&sent).unwrap().as_slice(), &[9u8; 16]);
}

// ---------------------------------------------------------------------------
// Several tokens, and U2F-only tokens.
// ---------------------------------------------------------------------------

/// Two tokens plugged in, the credential on the second: the first is
/// probed silently and skipped, and only the second is asked to sign.
#[test]
fn the_token_that_holds_the_credential_is_the_one_asked() {
    let first = ScriptedDevice::new(1, vec![initial(1, CMD_CBOR, &[CTAP2_ERR_NO_CREDENTIALS])]);
    let signature = vec![0x44u8; 64];
    let mut replies = vec![initial(2, CMD_CBOR, &[CTAP2_OK, 0xa0])];
    replies.extend(packets(2, CMD_CBOR, &assertion_message(0x01, 3, &signature)));
    let second = ScriptedDevice::new(2, replies);

    let mut devices: Vec<Box<dyn HidTransport>> = vec![Box::new(first), Box::new(second)];
    let assertion = get_assertion_from(
        &mut devices,
        &request(),
        &Interaction::default(),
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(assertion.signature, signature);
}

/// The probe is silent: `up: false`, whatever the credential asks.
#[test]
fn the_probe_never_asks_for_a_touch() {
    let mut device = ScriptedDevice::new(1, vec![initial(1, CMD_CBOR, &[CTAP2_OK, 0xa0])]);
    assert!(holds_credential(&mut device, &request(), &[1, 2, 3, 4], &Interaction::default()).unwrap());
    let (command, payload) = sent_message(&device.written, 1);
    assert_eq!(command, CMD_CBOR);
    assert_eq!(payload[0], CTAP2_GET_ASSERTION);
    let entries = cbor::decode(&payload[1..]).unwrap().0.into_map().unwrap();
    let options = entries
        .into_iter()
        .find_map(|(k, v)| (k.as_uint() == Some(0x05)).then_some(v))
        .unwrap()
        .into_map()
        .unwrap();
    assert_eq!(options, vec![(Value::Text("up".into()), Value::Bool(false))]);
}

#[test]
fn no_token_holding_the_credential_is_a_named_error() {
    let mut devices: Vec<Box<dyn HidTransport>> = vec![
        Box::new(ScriptedDevice::new(1, vec![initial(1, CMD_CBOR, &[CTAP2_ERR_NO_CREDENTIALS])])),
        Box::new(ScriptedDevice::new(2, vec![initial(2, CMD_CBOR, &[CTAP2_ERR_NO_CREDENTIALS])])),
    ];
    let err = get_assertion_from(&mut devices, &request(), &Interaction::default(), Duration::from_secs(5))
        .unwrap_err();
    assert!(matches!(err, Error::CredentialNotFound), "got {err:?}");
}

/// A U2F-only token (no `CAPFLAG_CBOR`) signs through a U2F APDU: it
/// answers "waiting for presence" until touched, then the signature.
#[test]
fn a_u2f_only_token_signs_through_ctap1() {
    let mut success = vec![0x01];
    success.extend_from_slice(&7u32.to_be_bytes());
    success.extend_from_slice(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    success.extend_from_slice(&[0x90, 0x00]);
    let mut device = ScriptedDevice::u2f_only(
        5,
        vec![initial(5, CMD_MSG, &[0x69, 0x85]), initial(5, CMD_MSG, &success)],
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let interaction = Interaction {
        events: Some(Arc::new(move |event| seen.lock().unwrap().push(event))),
        ..Interaction::default()
    };
    let assertion =
        get_assertion(&mut device, &request(), &interaction, Duration::from_secs(5)).unwrap();
    assert_eq!(assertion.flags, 0x01);
    assert_eq!(assertion.counter, 7);
    assert_eq!(assertion.signature, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    assert_eq!(*events.lock().unwrap(), vec![TokenEvent::TouchNeeded]);

    // The APDU: AUTHENTICATE with presence enforced, extended length,
    // challenge = SHA-256(message), application = SHA-256("ssh:").
    let (command, apdu) = sent_message(&device.written, 1);
    assert_eq!(command, CMD_MSG);
    assert_eq!(apdu.len(), 7 + 69 + 2);
    assert_eq!(&apdu[..4], &[0x00, U2F_INS_AUTHENTICATE, U2F_ENFORCE_PRESENCE, 0x00]);
    assert_eq!(&apdu[4..7], &[0x00, 0x00, 69]);
    let hash: [u8; 32] = Sha256::digest(request().message).into();
    assert_eq!(&apdu[7..39], &hash);
    let app: [u8; 32] = Sha256::digest(b"ssh:").into();
    assert_eq!(&apdu[39..71], &app);
    assert_eq!(apdu[71], 4);
    assert_eq!(&apdu[72..76], &[1, 2, 3, 4]);
    assert_eq!(&apdu[76..], &[0x00, 0x00], "Le");
}

#[test]
fn a_u2f_only_token_cannot_verify_the_user() {
    let mut device = ScriptedDevice::u2f_only(5, vec![]);
    let err = get_assertion(&mut device, &uv_request(), &Interaction::default(), Duration::from_secs(5))
        .unwrap_err();
    assert!(matches!(err, Error::UnsupportedByToken(_)), "got {err:?}");
}

#[test]
fn a_u2f_token_that_did_not_issue_the_handle_says_so() {
    let mut device = ScriptedDevice::u2f_only(5, vec![initial(5, CMD_MSG, &[0x6a, 0x80])]);
    let err = run(&mut device, &request()).unwrap_err();
    assert!(matches!(err, Error::CredentialNotFound), "got {err:?}");
}
