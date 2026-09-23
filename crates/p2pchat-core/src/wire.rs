//! Every type that crosses the wire — `architecture.md` §6, §7, §9 and §10.
//!
//! Three rules hold for everything in this module:
//!
//! 1. It serializes with `postcard`, which has exactly one encoding per value.
//!    The handshake transcript in §6 is a hash of these bytes, computed
//!    independently by both peers, so a second valid encoding would be a bug,
//!    not a curiosity.
//! 2. Anything of variable length has a declared maximum, checked on decode by
//!    [`WireType::validate`]. A peer must not be able to size our allocations.
//! 3. A structure that is signed over "all preceding fields" is a separate
//!    struct holding exactly those fields, with the signature beside it.
//!    `postcard` writes nested structs inline, so the bytes are identical to
//!    the flat form in `architecture.md` while the signed range stays
//!    impossible to get wrong.

use std::net::SocketAddr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::id::{ConversationId, MessageId, MsgSeq, UserId};
use crate::CoreError;

/// `architecture.md` §6 check 1: `version == 1`, else abort.
///
/// The check itself belongs to the handshake, not to decoding: a v2 peer sends
/// a well-formed message that we decline, which is a different outcome from a
/// corrupt one.
pub const PROTOCOL_VERSION: u8 = 1;

/// F-13: messages up to 4 KiB of UTF-8.
pub const MAX_BODY: usize = 4 * 1024;

/// Body plus the ChaCha20-Poly1305 tag — `architecture.md` §7.
pub const MAX_CIPHERTEXT: usize = MAX_BODY + 16;

/// Advisory only and never trusted (§9), so it is bounded by what keeps an
/// invite blob under the 300 characters F-04 requires, not by generosity.
pub const MAX_DISPLAY_NAME: usize = 32;

/// Public node addresses carried in an invite or a connection request.
pub const MAX_ADDRS: usize = 4;

/// Length of `nonce_i` and `nonce_r`.
pub const NONCE_LEN: usize = 32;

/// Implemented by every wire type. [`crate::frame::decode`] calls
/// [`WireType::validate`] on the way in, so a bound cannot be forgotten at a
/// call site — there is only one call site.
pub trait WireType: Serialize + de::DeserializeOwned {
    /// Reject anything whose variable-length fields exceed their maximum.
    fn validate(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// The `postcard` bytes of a wire value, with no length prefix.
///
/// This is what `architecture.md` §6 means by `postcard(HELLO_INIT)`: the
/// transcript hashes the value, not the frame it travelled in. Validation runs
/// first, so a value that would be rejected on the way in is never hashed on
/// the way out.
pub fn to_bytes<T: WireType>(value: &T) -> Result<Vec<u8>, CoreError> {
    value.validate()?;
    Ok(postcard::to_stdvec(value)?)
}

fn bound(field: &'static str, len: usize, max: usize) -> Result<(), CoreError> {
    if len > max {
        return Err(CoreError::FieldTooLong { field, len, max });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/// A raw Ed25519 signature: 64 bytes, written and read as 64 bytes.
///
/// `serde` only derives array impls up to length 32, hence the hand-written
/// pair. They are a fixed-size tuple, so `postcard` emits no length prefix and
/// there is nothing to bound.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signature(..)")
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(64)?;
        for byte in self.0 {
            tuple.serialize_element(&byte)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SignatureVisitor;

        impl<'de> de::Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("64 signature bytes")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Signature, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(Signature(out))
            }
        }

        deserializer.deserialize_tuple(64, SignatureVisitor)
    }
}

// ---------------------------------------------------------------------------
// Handshake — architecture.md §6
// ---------------------------------------------------------------------------

/// `HELLO_INIT`. Every field is fixed-size.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HelloInit {
    pub version: u8,
    pub user_id_i: UserId,
    pub identity_pk_i: [u8; 32],
    pub eph_pk_i: [u8; 32],
    pub nonce_i: [u8; NONCE_LEN],
}

impl WireType for HelloInit {}

/// The part of `HELLO_RESP` that the transcript hashes: "all fields except
/// `sig_r`" — `architecture.md` §6.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HelloRespUnsigned {
    pub version: u8,
    pub user_id_r: UserId,
    pub identity_pk_r: [u8; 32],
    pub eph_pk_r: [u8; 32],
    pub nonce_r: [u8; NONCE_LEN],
}

impl WireType for HelloRespUnsigned {}

/// `HELLO_RESP`. `postcard(HelloResp) == postcard(unsigned) ‖ sig_r`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HelloResp {
    pub unsigned: HelloRespUnsigned,
    pub sig_r: Signature,
}

impl WireType for HelloResp {}

/// `HELLO_CONFIRM`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HelloConfirm {
    pub sig_i: Signature,
}

impl WireType for HelloConfirm {}

// ---------------------------------------------------------------------------
// Messages — architecture.md §7, §8, §10, §11
// ---------------------------------------------------------------------------

/// What the ciphertext of a frame holds. Travels in the clear inside the
/// header, and is covered by the AAD.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MsgType {
    /// A chat message: the plaintext is the UTF-8 body.
    Text,
    /// `postcard(Ack)`.
    Ack,
    /// `postcard(Resync)`.
    Resync,
}

/// The `status` column of the `messages` table — `architecture.md` §8 — and the
/// payload of an [`Ack`]. Declared in the order `0 pending 1 sent 2 delivered
/// 3 read 4 failed`, which is both the stored integer and the `postcard`
/// variant index.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Pending,
    Sent,
    Delivered,
    Read,
    Failed,
}

/// The plaintext header of a message frame — `architecture.md` §7.
///
/// Travels in the clear so the receiver can dedupe and order before
/// decrypting, and is passed to the AEAD as associated data, which is what
/// stops a peer from altering it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    pub version: u8,
    pub msg_type: MsgType,
    pub message_id: MessageId,
    pub conversation_id: ConversationId,
    pub sender_id: UserId,
    pub msg_seq: MsgSeq,
    pub created_at: u64,
}

impl MessageHeader {
    /// The associated data, exactly as §7 specifies it:
    /// `version ‖ msg_type ‖ message_id ‖ conversation_id ‖ sender_id ‖
    /// msg_seq ‖ created_at`.
    ///
    /// Field order in the struct *is* the AAD order. Building it by hand at
    /// the call site is how the two drift apart.
    pub fn aad(&self) -> Result<Vec<u8>, CoreError> {
        Ok(postcard::to_stdvec(self)?)
    }
}

impl WireType for MessageHeader {}

/// One encrypted frame on a conversation stream.
///
/// `frame_seq` is **not** here. It is a local per-direction counter, kept in
/// step on the two sides by the QUIC stream itself, which delivers exactly
/// once and in order — see `architecture.md` §7. Transmitting it would hand an
/// attacker a mutable nonce selector and buy nothing: the counters cannot
/// drift without the AEAD tag failing on the next frame.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MessageFrame {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

impl WireType for MessageFrame {
    fn validate(&self) -> Result<(), CoreError> {
        bound("ciphertext", self.ciphertext.len(), MAX_CIPHERTEXT)
    }
}

/// An acknowledgement — `architecture.md` §11. An ordinary encrypted frame on
/// the conversation stream; not itself acknowledged.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ack {
    pub conversation_id: ConversationId,
    pub message_id: MessageId,
    pub status: DeliveryStatus,
}

impl WireType for Ack {
    fn validate(&self) -> Result<(), CoreError> {
        // `SENT ──▶ DELIVERED ──▶ READ`: the first of those is local, set on
        // write to the socket, and pending/failed are local too. Only the two
        // the peer can observe may arrive from the peer.
        match self.status {
            DeliveryStatus::Delivered | DeliveryStatus::Read => Ok(()),
            other => Err(CoreError::NotAnAck { status: other }),
        }
    }
}

/// `RESYNC { conversation_id, have_through }` — `architecture.md` §10.
/// `have_through` is the highest `msg_seq` received from the peer.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Resync {
    pub conversation_id: ConversationId,
    pub have_through: MsgSeq,
}

impl WireType for Resync {}

// ---------------------------------------------------------------------------
// Invite — architecture.md §9
// ---------------------------------------------------------------------------

/// The signed part of an [`Invite`]: §9's "over all preceding fields".
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InviteBody {
    pub version: u8,
    pub user_id: UserId,
    pub identity_pk: [u8; 32],
    /// Advisory only, never trusted.
    pub display_name: String,
    /// Public node addresses.
    pub addrs: Vec<SocketAddr>,
    pub created_at: u64,
    /// `created_at + 24h` — OD-3.
    pub expires_at: Option<u64>,
}

impl WireType for InviteBody {
    fn validate(&self) -> Result<(), CoreError> {
        bound("display_name", self.display_name.len(), MAX_DISPLAY_NAME)?;
        bound("addrs", self.addrs.len(), MAX_ADDRS)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub body: InviteBody,
    pub sig: Signature,
}

impl WireType for Invite {
    fn validate(&self) -> Result<(), CoreError> {
        self.body.validate()
    }
}

// ---------------------------------------------------------------------------
// Public node — architecture.md §3
// ---------------------------------------------------------------------------

/// "Ask this node for its owner's profile." `user_id` is the owner the caller
/// expects; a node that is not that owner answers nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProfileRequest {
    pub version: u8,
    pub user_id: UserId,
}

impl WireType for ProfileRequest {}

/// "Let me open a private session with you." Everything it says about the
/// caller is self-declared: §3, "anything the public node says about identity
/// is untrusted", and F-06 requires the UI to show the fingerprint and user ID
/// rather than the display name alone. The private node authenticates the peer
/// itself in §6.
///
/// It carries **no address**, M9d: the requester dials the acceptor and the
/// acceptor never dials back (§10), so the requester's own address is of no use
/// to anybody. A requester behind NAT or CGNAT can therefore still connect.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConnectionRequest {
    pub version: u8,
    pub from_user_id: UserId,
    pub from_identity_pk: [u8; 32],
    pub display_name: String,
    pub created_at: u64,
}

impl WireType for ConnectionRequest {
    fn validate(&self) -> Result<(), CoreError> {
        bound("display_name", self.display_name.len(), MAX_DISPLAY_NAME)
    }
}

/// "What happened to my connection request?" Keyed by the caller, which is how
/// the pending-requests table is keyed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub version: u8,
    pub from_user_id: UserId,
}

impl WireType for ConnectionStatus {}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RequestState {
    Pending,
    Accepted,
    Rejected,
    /// No such request. Also the answer for one that has expired.
    Unknown,
}

/// The public node answers these three and nothing else — `architecture.md`
/// §3. A closed enum is what makes "and nothing else" structural.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PublicRequest {
    Profile(ProfileRequest),
    Connection(ConnectionRequest),
    Status(ConnectionStatus),
}

impl WireType for PublicRequest {
    fn validate(&self) -> Result<(), CoreError> {
        match self {
            Self::Profile(r) => r.validate(),
            Self::Connection(r) => r.validate(),
            Self::Status(r) => r.validate(),
        }
    }
}

/// The profile answer is the owner's signed invite, so the caller can verify
/// it instead of trusting the node that handed it over.
///
/// Boxed because an invite dwarfs the other variant; `postcard` writes a
/// `Box<T>` exactly as it writes a `T`, so the wire form is unchanged.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PublicResponse {
    Profile(Box<Invite>),
    /// The state of the caller's request and, **only when it is `Accepted`**,
    /// the answering node's advertised private address — M9d, §10. That is
    /// where the requester dials; a `Pending` or `Rejected` answer has nothing
    /// to dial and says nothing about where this node listens.
    ///
    /// The rule is enforced in [`WireType::validate`] and therefore on decode,
    /// so an address attached to any other state is a malformed response
    /// rather than something a caller has to remember to ignore.
    State(RequestState, Option<SocketAddr>),
}

impl WireType for PublicResponse {
    fn validate(&self) -> Result<(), CoreError> {
        match self {
            Self::Profile(invite) => invite.validate(),
            Self::State(_, None) => Ok(()),
            Self::State(RequestState::Accepted, Some(addr)) if !addr.ip().is_unspecified() => {
                Ok(())
            }
            Self::State(..) => Err(CoreError::MisplacedAddr),
        }
    }
}
