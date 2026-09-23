//! What the TUI knows about the rest of the application.
//!
//! This crate may name `core` and nothing else (`architecture.md` §2), so the
//! types the store and the node deal in are re-declared here in the shape the
//! screen needs, and the binary maps between the two. That mapping is the
//! whole cost of the rule, and it is about thirty lines.

use p2pchat_core::wire::DeliveryStatus;
use p2pchat_core::{MessageId, MsgSeq, UserId};

/// F-25's five states, plus the sixth that is simply "no session".
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ConnState {
    #[default]
    Disconnected,
    Connecting,
    Handshaking,
    Established,
    Reconnecting,
    Failed,
}

impl ConnState {
    /// What the status bar shows. Distinct words, because F-25 asks for the
    /// five to be told apart and a colour alone does not do that.
    pub fn label(self) -> &'static str {
        match self {
            ConnState::Disconnected => "offline",
            ConnState::Connecting => "connecting",
            ConnState::Handshaking => "handshaking",
            ConnState::Established => "connected",
            ConnState::Reconnecting => "reconnecting",
            ConnState::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Conversation {
    pub peer: UserId,
    /// Advisory. Whatever the peer calls itself is not evidence of anything —
    /// §6 proves the key, not the name — so the fingerprint is shown beside it
    /// wherever it appears.
    pub display_name: Option<String>,
    pub verified: bool,
    pub state: ConnState,
    /// Why the last attempt failed, set only while `state` is `Failed` —
    /// M12. A bare "failed" is the same word for a typo, a closed port and a
    /// peer behind CGNAT, and the user can act on only one of them at a time.
    pub failure: Option<String>,
}

impl Conversation {
    /// The list entry: a name if there is one, the fingerprint otherwise.
    pub fn title(&self) -> String {
        match &self.display_name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => self.peer.fingerprint(),
        }
    }
}

/// One stored message, as a row on the screen.
#[derive(Clone, Debug)]
pub struct Line {
    pub message_id: MessageId,
    pub msg_seq: MsgSeq,
    /// Ours or theirs. Computed by the binary, which knows who we are.
    pub mine: bool,
    pub body: String,
    pub status: DeliveryStatus,
}

/// The oldest row on a page — F-22 asks for the fifty *older* rows, and an
/// offset into a result set that is still growing at the other end would skip
/// or repeat rows. The store's own cursor, named here for §2's sake.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cursor {
    pub msg_seq: MsgSeq,
    pub message_id: MessageId,
}

/// A queued connection request — F-06, F-07.
#[derive(Clone, Debug)]
pub struct Pending {
    pub from: UserId,
    /// The caller's claim about itself, shown next to the fingerprint and
    /// never instead of it (F-06).
    pub display_name: String,
}

/// What an imported invite says, before anything has been dialled — F-05.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub peer: UserId,
    pub display_name: String,
    pub addrs: usize,
}

/// Everything the TUI needs from the rest of the application.
///
/// A trait rather than a channel so that this crate stays free of the store
/// and the node (§2), and so that a test can hand the app a fake and count
/// what it asked for. The binary's implementation is channels: `blocking_send`
/// out, `blocking_recv` on a oneshot back, because the TUI thread is not a
/// runtime thread and must never `block_on`.
///
/// Note what is *not* here: there is no "read the whole conversation" call.
/// [`Core::page`] is the only way to reach history, and it returns one page.
pub trait Core {
    /// Our own user ID, for F-02's local fingerprint and the profile screen.
    fn me(&mut self) -> UserId;

    fn conversations(&mut self) -> Vec<Conversation>;

    fn pending(&mut self) -> Vec<Pending>;

    /// One page of messages, oldest first. `before` is the cursor of the
    /// oldest row already held; `None` asks for the newest page.
    fn page(&mut self, peer: UserId, before: Option<Cursor>) -> Vec<Line>;

    fn send(&mut self, peer: UserId, body: String);

    /// F-06's accept and reject.
    fn decide(&mut self, from: UserId, accept: bool);

    /// F-03: the user compared fingerprints out of band.
    fn verify(&mut self, peer: UserId);

    /// Parses an invite and stores the peer. **Does not connect**: F-05 wants
    /// the fingerprint compared first, and [`Core::connect`] is the separate
    /// call the user makes afterwards.
    fn import(&mut self, blob: &str) -> Result<Preview, String>;

    fn connect(&mut self, peer: UserId);
}

/// Core → TUI. A notification, never a payload.
///
/// The store holds the truth; this says only that it changed. That is what
/// lets the core deliver with `try_send` and carry on when the TUI is slow —
/// a dropped notice costs a redraw that the next one does anyway, where a
/// dropped payload would be a lost message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Notice {
    /// This conversation changed: a message arrived, a status moved, a session
    /// opened or closed.
    Changed(UserId),
    /// The peer list changed, or one peer's connection state did.
    Peers,
    /// The pending-request queue changed — F-07.
    Requests,
}
