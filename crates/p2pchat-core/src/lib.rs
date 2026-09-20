//! Shared types, wire format and errors.
//!
//! Depends on nothing else in the workspace — see `architecture.md` §2.

#![forbid(unsafe_code)]

pub mod frame;
pub mod id;
pub mod wire;

pub use frame::{decode, encode, frame_len, read_frame, MAX_FRAME_SIZE};
pub use id::{ConversationId, FrameSeq, MessageId, MsgSeq, UserId};

use thiserror::Error;
use wire::DeliveryStatus;

#[derive(Debug, Error)]
pub enum CoreError {
    /// `architecture.md` §5: an over-size frame closes the connection instead of
    /// being allocated.
    #[error("frame of {size} bytes exceeds the {} byte limit", MAX_FRAME_SIZE)]
    FrameTooLarge { size: usize },

    /// A variable-length field beyond its declared maximum. Reported per field
    /// so the log says which peer sent what, without quoting the value.
    #[error("field `{field}` has {len} where at most {max} is allowed")]
    FieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },

    /// `architecture.md` §11: only the two states the peer can observe may
    /// arrive from the peer.
    #[error("{status:?} is not an acknowledgeable state")]
    NotAnAck { status: DeliveryStatus },

    /// Anything `postcard` refuses. Deliberately says nothing about where in
    /// the message the trouble was.
    #[error("malformed wire message")]
    Malformed(#[from] postcard::Error),

    /// `architecture.md` §6 check 1.
    #[error("unsupported protocol version")]
    UnsupportedVersion,
}
