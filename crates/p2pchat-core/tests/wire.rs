//! M2 gate.
//!
//! 1. every wire type round-trips through a frame;
//! 2. the same value serializes to identical bytes 1000 times — the transcript
//!    hash in `architecture.md` §6 is only meaningful if this holds;
//! 3. an over-size frame is rejected rather than allocated.
//!
//! Plus the bounds on variable-length fields, which are what stops a peer from
//! choosing our allocation sizes.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use p2pchat_core::frame::{decode, encode, read_frame, LENGTH_PREFIX, MAX_FRAME_SIZE};
use p2pchat_core::id::{ConversationId, MessageId, MsgSeq, UserId};
use p2pchat_core::wire::*;
use p2pchat_core::CoreError;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn bytes16() -> impl Strategy<Value = [u8; 16]> {
    prop::array::uniform16(any::<u8>())
}

fn bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn user_id() -> impl Strategy<Value = UserId> {
    bytes32().prop_map(UserId::from_bytes)
}

fn conversation_id() -> impl Strategy<Value = ConversationId> {
    bytes32().prop_map(ConversationId::from_bytes)
}

fn message_id() -> impl Strategy<Value = MessageId> {
    bytes16().prop_map(MessageId::from_bytes)
}

fn signature() -> impl Strategy<Value = Signature> {
    prop::collection::vec(any::<u8>(), 64).prop_map(|bytes| {
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Signature::from_bytes(out)
    })
}

fn addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<u32>(), any::<u16>())
            .prop_map(|(ip, port)| SocketAddr::from((Ipv4Addr::from(ip), port))),
        (bytes16(), any::<u16>())
            .prop_map(|(ip, port)| SocketAddr::from((Ipv6Addr::from(ip), port))),
    ]
}

fn addrs() -> impl Strategy<Value = Vec<SocketAddr>> {
    prop::collection::vec(addr(), 0..=MAX_ADDRS)
}

/// Any name within the bound, including the empty one and multi-byte
/// characters — `display_name` is bounded in bytes, not in characters.
fn display_name() -> impl Strategy<Value = String> {
    "[a-z é]{0,10}"
}

fn msg_type() -> impl Strategy<Value = MsgType> {
    prop_oneof![
        Just(MsgType::Text),
        Just(MsgType::Ack),
        Just(MsgType::Resync)
    ]
}

/// Only the two states a peer is allowed to send — `architecture.md` §11.
fn ack_status() -> impl Strategy<Value = DeliveryStatus> {
    prop_oneof![Just(DeliveryStatus::Delivered), Just(DeliveryStatus::Read)]
}

prop_compose! {
    fn hello_init()(
        version in any::<u8>(),
        user_id_i in user_id(),
        identity_pk_i in bytes32(),
        eph_pk_i in bytes32(),
        nonce_i in bytes32(),
    ) -> HelloInit {
        HelloInit { version, user_id_i, identity_pk_i, eph_pk_i, nonce_i }
    }
}

prop_compose! {
    fn hello_resp_unsigned()(
        version in any::<u8>(),
        user_id_r in user_id(),
        identity_pk_r in bytes32(),
        eph_pk_r in bytes32(),
        nonce_r in bytes32(),
    ) -> HelloRespUnsigned {
        HelloRespUnsigned { version, user_id_r, identity_pk_r, eph_pk_r, nonce_r }
    }
}

prop_compose! {
    fn hello_resp()(unsigned in hello_resp_unsigned(), sig_r in signature()) -> HelloResp {
        HelloResp { unsigned, sig_r }
    }
}

prop_compose! {
    fn hello_confirm()(sig_i in signature()) -> HelloConfirm {
        HelloConfirm { sig_i }
    }
}

prop_compose! {
    fn message_header()(
        version in any::<u8>(),
        msg_type in msg_type(),
        message_id in message_id(),
        conversation_id in conversation_id(),
        sender_id in user_id(),
        msg_seq in any::<u64>(),
        created_at in any::<u64>(),
    ) -> MessageHeader {
        MessageHeader {
            version,
            msg_type,
            message_id,
            conversation_id,
            sender_id,
            msg_seq: MsgSeq::new(msg_seq),
            created_at,
        }
    }
}

prop_compose! {
    fn message_frame()(
        header in message_header(),
        ciphertext in prop::collection::vec(any::<u8>(), 0..=256),
    ) -> MessageFrame {
        MessageFrame { header, ciphertext }
    }
}

prop_compose! {
    fn ack()(
        conversation_id in conversation_id(),
        message_id in message_id(),
        status in ack_status(),
    ) -> Ack {
        Ack { conversation_id, message_id, status }
    }
}

prop_compose! {
    fn resync()(conversation_id in conversation_id(), have_through in any::<u64>()) -> Resync {
        Resync { conversation_id, have_through: MsgSeq::new(have_through) }
    }
}

prop_compose! {
    fn invite_body()(
        version in any::<u8>(),
        user_id in user_id(),
        identity_pk in bytes32(),
        display_name in display_name(),
        addrs in addrs(),
        created_at in any::<u64>(),
        expires_at in any::<Option<u64>>(),
    ) -> InviteBody {
        InviteBody { version, user_id, identity_pk, display_name, addrs, created_at, expires_at }
    }
}

prop_compose! {
    fn invite()(body in invite_body(), sig in signature()) -> Invite {
        Invite { body, sig }
    }
}

prop_compose! {
    fn profile_request()(version in any::<u8>(), user_id in user_id()) -> ProfileRequest {
        ProfileRequest { version, user_id }
    }
}

prop_compose! {
    fn connection_request()(
        version in any::<u8>(),
        from_user_id in user_id(),
        from_identity_pk in bytes32(),
        display_name in display_name(),
        addrs in addrs(),
        created_at in any::<u64>(),
    ) -> ConnectionRequest {
        ConnectionRequest {
            version,
            from_user_id,
            from_identity_pk,
            display_name,
            addrs,
            created_at,
        }
    }
}

prop_compose! {
    fn connection_status()(version in any::<u8>(), from_user_id in user_id()) -> ConnectionStatus {
        ConnectionStatus { version, from_user_id }
    }
}

fn public_request() -> impl Strategy<Value = PublicRequest> {
    prop_oneof![
        profile_request().prop_map(PublicRequest::Profile),
        connection_request().prop_map(PublicRequest::Connection),
        connection_status().prop_map(PublicRequest::Status),
    ]
}

fn request_state() -> impl Strategy<Value = RequestState> {
    prop_oneof![
        Just(RequestState::Pending),
        Just(RequestState::Accepted),
        Just(RequestState::Rejected),
        Just(RequestState::Unknown),
    ]
}

fn public_response() -> impl Strategy<Value = PublicResponse> {
    prop_oneof![
        invite().prop_map(|invite| PublicResponse::Profile(Box::new(invite))),
        request_state().prop_map(PublicResponse::State),
    ]
}

// ---------------------------------------------------------------------------
// Gate 1 and gate 2, for every wire type
// ---------------------------------------------------------------------------

/// Gate 2 says 1000 serializations of *the same value*. Running that for every
/// generated case would be 256 000 per type for no extra coverage, so the
/// determinism property gets its own smaller case count.
const DETERMINISM_CASES: u32 = 16;

macro_rules! wire_type {
    ($name:ident, $ty:ty, $strategy:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #[test]
                fn round_trips_through_a_frame(value in $strategy) {
                    let mut framed = Vec::new();
                    encode(&value, &mut framed).unwrap();

                    let mut body = Vec::new();
                    let used = read_frame(&framed, &mut body).unwrap();
                    prop_assert_eq!(used, Some(framed.len()));
                    prop_assert_eq!(body.len(), framed.len() - LENGTH_PREFIX);

                    let decoded: $ty = decode(&body).unwrap();
                    prop_assert_eq!(decoded, value);
                }
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(DETERMINISM_CASES))]
                #[test]
                fn serializes_identically_a_thousand_times(value in $strategy) {
                    let mut first = Vec::new();
                    encode(&value, &mut first).unwrap();
                    for round in 0..1000 {
                        let mut again = Vec::new();
                        encode(&value, &mut again).unwrap();
                        prop_assert_eq!(&again, &first, "round {} differed", round);
                    }
                }
            }
        }
    };
}

wire_type!(t_hello_init, HelloInit, hello_init());
wire_type!(
    t_hello_resp_unsigned,
    HelloRespUnsigned,
    hello_resp_unsigned()
);
wire_type!(t_hello_resp, HelloResp, hello_resp());
wire_type!(t_hello_confirm, HelloConfirm, hello_confirm());
wire_type!(t_message_header, MessageHeader, message_header());
wire_type!(t_message_frame, MessageFrame, message_frame());
wire_type!(t_ack, Ack, ack());
wire_type!(t_resync, Resync, resync());
wire_type!(t_invite_body, InviteBody, invite_body());
wire_type!(t_invite, Invite, invite());
wire_type!(t_profile_request, ProfileRequest, profile_request());
wire_type!(
    t_connection_request,
    ConnectionRequest,
    connection_request()
);
wire_type!(t_connection_status, ConnectionStatus, connection_status());
wire_type!(t_public_request, PublicRequest, public_request());
wire_type!(t_public_response, PublicResponse, public_response());

// ---------------------------------------------------------------------------
// Gate 2, the part that matters most
// ---------------------------------------------------------------------------

/// `HELLO_RESP` is hashed into the transcript without its signature. If the
/// nested form ever stopped being a prefix of the whole message, both sides
/// would still agree with themselves and disagree with each other.
#[test]
fn the_unsigned_hello_resp_is_a_prefix_of_the_signed_one() {
    let unsigned = HelloRespUnsigned {
        version: PROTOCOL_VERSION,
        user_id_r: UserId::from_bytes([1; 32]),
        identity_pk_r: [2; 32],
        eph_pk_r: [3; 32],
        nonce_r: [4; 32],
    };
    let resp = HelloResp {
        unsigned,
        sig_r: Signature::from_bytes([5; 64]),
    };

    let mut unsigned_bytes = Vec::new();
    encode(&unsigned, &mut unsigned_bytes).unwrap();
    let mut resp_bytes = Vec::new();
    encode(&resp, &mut resp_bytes).unwrap();

    assert_eq!(
        resp_bytes[LENGTH_PREFIX..LENGTH_PREFIX + unsigned_bytes.len() - LENGTH_PREFIX],
        unsigned_bytes[LENGTH_PREFIX..]
    );
    assert_eq!(
        resp_bytes.len() - unsigned_bytes.len(),
        64,
        "the signature is the only difference"
    );
}

/// Same argument for the invite: the signature covers `body` and nothing else.
#[test]
fn the_invite_body_is_a_prefix_of_the_invite() {
    let body = InviteBody {
        version: PROTOCOL_VERSION,
        user_id: UserId::from_bytes([1; 32]),
        identity_pk: [2; 32],
        display_name: "ada".into(),
        addrs: vec![SocketAddr::from(([203, 0, 113, 7], 47100))],
        created_at: 1_700_000_000,
        expires_at: Some(1_700_086_400),
    };
    let invite = Invite {
        body: body.clone(),
        sig: Signature::from_bytes([9; 64]),
    };

    let mut body_bytes = Vec::new();
    encode(&body, &mut body_bytes).unwrap();
    let mut invite_bytes = Vec::new();
    encode(&invite, &mut invite_bytes).unwrap();

    assert!(invite_bytes[LENGTH_PREFIX..].starts_with(&body_bytes[LENGTH_PREFIX..]));
    assert_eq!(invite_bytes.len() - body_bytes.len(), 64);
}

/// The AAD is the header's own encoding, in the field order §7 gives.
#[test]
fn the_aad_is_the_encoded_header() {
    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        msg_type: MsgType::Text,
        message_id: MessageId::from_bytes([1; 16]),
        conversation_id: ConversationId::from_bytes([2; 32]),
        sender_id: UserId::from_bytes([3; 32]),
        msg_seq: MsgSeq::new(9),
        created_at: 1_700_000_000,
    };

    let aad = header.aad().unwrap();
    let mut framed = Vec::new();
    encode(&header, &mut framed).unwrap();
    assert_eq!(aad, framed[LENGTH_PREFIX..]);

    // version, msg_type, then the 16-byte message id.
    assert_eq!(aad[0], PROTOCOL_VERSION);
    assert_eq!(aad[1], 0, "MsgType::Text is variant 0");
    assert_eq!(&aad[2..18], &[1u8; 16]);

    for _ in 0..1000 {
        assert_eq!(header.aad().unwrap(), aad);
    }
}

// ---------------------------------------------------------------------------
// Gate 3
// ---------------------------------------------------------------------------

/// The gate: a header claiming more than 64 KiB is rejected, and the claimed
/// size never reaches the allocator. `capacity` is the observable proof — if
/// the length were used before it were checked, the destination buffer would
/// be holding four gigabytes.
#[test]
fn a_frame_header_claiming_four_gibibytes_allocates_nothing() {
    let mut body = Vec::new();
    let claimed = u32::MAX;
    let header = claimed.to_be_bytes();

    let err = read_frame(&header, &mut body).unwrap_err();

    assert!(
        matches!(err, CoreError::FrameTooLarge { size } if size == claimed as usize),
        "expected FrameTooLarge, got {err}"
    );
    assert_eq!(
        body.capacity(),
        0,
        "the claimed length reached the allocator"
    );
    assert!(body.is_empty());
}

/// Same, with a plausible-looking body behind the lie.
#[test]
fn an_over_size_header_is_rejected_before_the_body_is_waited_for() {
    let mut src = ((MAX_FRAME_SIZE + 1) as u32).to_be_bytes().to_vec();
    src.extend_from_slice(b"whatever follows does not matter");

    let mut body = Vec::with_capacity(0);
    let err = read_frame(&src, &mut body).unwrap_err();
    assert!(matches!(err, CoreError::FrameTooLarge { size } if size == MAX_FRAME_SIZE + 1));
    assert_eq!(body.capacity(), 0);
}

/// A frame exactly at the limit is legal, so the check is `>` and not `>=`.
#[test]
fn a_frame_at_the_limit_is_accepted() {
    let mut src = (MAX_FRAME_SIZE as u32).to_be_bytes().to_vec();
    src.resize(LENGTH_PREFIX + MAX_FRAME_SIZE, 0);

    let mut body = Vec::new();
    assert_eq!(read_frame(&src, &mut body).unwrap(), Some(src.len()));
    assert_eq!(body.len(), MAX_FRAME_SIZE);
}

// ---------------------------------------------------------------------------
// Bounds on variable-length fields
// ---------------------------------------------------------------------------

fn long_name_invite(name_len: usize) -> InviteBody {
    InviteBody {
        version: PROTOCOL_VERSION,
        user_id: UserId::from_bytes([1; 32]),
        identity_pk: [2; 32],
        display_name: "x".repeat(name_len),
        addrs: Vec::new(),
        created_at: 0,
        expires_at: None,
    }
}

#[test]
fn a_display_name_over_the_bound_is_refused_on_the_way_in_and_out() {
    let ok = long_name_invite(MAX_DISPLAY_NAME);
    let mut buf = Vec::new();
    encode(&ok, &mut buf).unwrap();

    let too_long = long_name_invite(MAX_DISPLAY_NAME + 1);
    let err = encode(&too_long, &mut Vec::new()).unwrap_err();
    assert!(
        matches!(err, CoreError::FieldTooLong { field: "display_name", len, max }
            if len == MAX_DISPLAY_NAME + 1 && max == MAX_DISPLAY_NAME),
        "{err}"
    );

    // And on decode, where the sender is not us and validation is the only
    // thing standing between a peer and our allocator.
    let hostile = postcard::to_stdvec(&too_long).unwrap();
    let err = decode::<InviteBody>(&hostile).unwrap_err();
    assert!(matches!(
        err,
        CoreError::FieldTooLong {
            field: "display_name",
            ..
        }
    ));
}

#[test]
fn too_many_addresses_are_refused_on_decode() {
    let mut body = long_name_invite(0);
    body.addrs = vec![SocketAddr::from(([127, 0, 0, 1], 47100)); MAX_ADDRS + 1];

    let hostile = postcard::to_stdvec(&body).unwrap();
    let err = decode::<InviteBody>(&hostile).unwrap_err();
    assert!(
        matches!(err, CoreError::FieldTooLong { field: "addrs", len, max }
            if len == MAX_ADDRS + 1 && max == MAX_ADDRS),
        "{err}"
    );
}

#[test]
fn a_ciphertext_over_the_bound_is_refused_on_decode() {
    let frame = MessageFrame {
        header: MessageHeader {
            version: PROTOCOL_VERSION,
            msg_type: MsgType::Text,
            message_id: MessageId::from_bytes([0; 16]),
            conversation_id: ConversationId::from_bytes([0; 32]),
            sender_id: UserId::from_bytes([0; 32]),
            msg_seq: MsgSeq::ZERO,
            created_at: 0,
        },
        ciphertext: vec![0u8; MAX_CIPHERTEXT + 1],
    };

    let hostile = postcard::to_stdvec(&frame).unwrap();
    let err = decode::<MessageFrame>(&hostile).unwrap_err();
    assert!(
        matches!(
            err,
            CoreError::FieldTooLong {
                field: "ciphertext",
                ..
            }
        ),
        "{err}"
    );
}

/// The length field on its own must not be enough: this body announces a
/// `u32::MAX`-byte display name and then stops.
#[test]
fn a_length_field_with_nothing_behind_it_allocates_nothing() {
    let mut hostile = vec![1u8]; // version
    hostile.extend_from_slice(&[0u8; 32]); // user_id
    hostile.extend_from_slice(&[0u8; 32]); // identity_pk
    hostile.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]); // varint u32::MAX

    let err = decode::<InviteBody>(&hostile).unwrap_err();
    assert!(matches!(err, CoreError::Malformed(_)), "{err}");
}

/// Only `DELIVERED` and `READ` can arrive from a peer — `architecture.md` §11.
#[test]
fn a_local_only_status_is_not_an_acknowledgement() {
    for status in [
        DeliveryStatus::Pending,
        DeliveryStatus::Sent,
        DeliveryStatus::Failed,
    ] {
        let ack = Ack {
            conversation_id: ConversationId::from_bytes([0; 32]),
            message_id: MessageId::from_bytes([0; 16]),
            status,
        };
        let hostile = postcard::to_stdvec(&ack).unwrap();
        let err = decode::<Ack>(&hostile).unwrap_err();
        assert!(matches!(err, CoreError::NotAnAck { .. }), "{err}");
    }
}

/// Bounds nested inside an envelope are still checked.
#[test]
fn the_public_request_envelope_checks_its_payload() {
    let request = PublicRequest::Connection(ConnectionRequest {
        version: PROTOCOL_VERSION,
        from_user_id: UserId::from_bytes([1; 32]),
        from_identity_pk: [2; 32],
        display_name: "x".repeat(MAX_DISPLAY_NAME + 1),
        addrs: Vec::new(),
        created_at: 0,
    });

    let hostile = postcard::to_stdvec(&request).unwrap();
    let err = decode::<PublicRequest>(&hostile).unwrap_err();
    assert!(
        matches!(
            err,
            CoreError::FieldTooLong {
                field: "display_name",
                ..
            }
        ),
        "{err}"
    );
}
