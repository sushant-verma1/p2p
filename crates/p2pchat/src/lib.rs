//! The composition root — `architecture.md` §2.
//!
//! Everything below is a layer that may not know about its neighbours: the
//! store has no sockets, the net crate has no database. This is where they are
//! joined, so it is the only crate that may name all of them.
//!
//! It is a library as well as a binary because M8's tests drive two nodes, and
//! three of the five gates are cheaper and sharper in one process than through
//! a pipe.

#![forbid(unsafe_code)]

pub mod node;
pub mod registry;
pub mod session;
pub mod ui;

pub use node::{Config, Node};

use p2pchat_core::wire::{DeliveryStatus, RequestState};
use p2pchat_core::{MessageId, MsgSeq, UserId};

/// What a node tells whoever is driving it.
///
/// The UI is M9; until then the debug CLI prints these and the tests read
/// them. Either way the node does not know what a terminal is.
#[derive(Clone, Debug)]
pub enum Event {
    /// A session is live. `initiator` is who dialled, which is what §10's
    /// tiebreak is on — it is in the event because it is the only way for a
    /// test to see which of two simultaneous dials survived.
    Connected {
        peer: UserId,
        initiator: UserId,
    },

    /// Written to the socket, which is when §11 says `SENT`.
    Sent {
        peer: UserId,
        message_id: MessageId,
        msg_seq: MsgSeq,
    },

    /// Stored, and therefore acknowledged. A duplicate does not produce one:
    /// §7 rule 4 re-acks without storing a second row.
    Received {
        peer: UserId,
        message_id: MessageId,
        msg_seq: MsgSeq,
        body: String,
    },

    /// The peer acknowledged one of ours.
    Delivered {
        peer: UserId,
        message_id: MessageId,
        status: DeliveryStatus,
    },

    Closed {
        peer: UserId,
    },

    /// §10's state machine moved — F-25, M10.
    ///
    /// Carries who and not what: which phase it is now in is read back from
    /// `Node::phases`, like every other connection state. An event that said
    /// what the state *was* is the bug M9e fixed, in a new place.
    Phase {
        peer: UserId,
    },

    /// An accepted request was dialled and the dial did not arrive — M9e.
    ///
    /// Only a hint to re-read: there is no session with this peer, and
    /// [`Node::sessions`] says as much whether or not this ever gets through.
    /// It exists so the screen finds out now rather than at the next
    /// keystroke.
    DialFailed {
        peer: UserId,
        /// One line for a person: what went wrong and, where it is a silence
        /// rather than a refusal, what to check — M12.
        reason: String,
    },

    /// An unauthenticated connection request reached the public node — F-07.
    /// `display_name` is the caller's own claim about itself.
    Requested {
        from: UserId,
        display_name: String,
        state: RequestState,
    },
}
