//! The session registry and the simultaneous-dial rule — `architecture.md` §10.
//!
//! Two peers who dial each other at the same moment complete two handshakes and
//! hold two sound sessions to each other. Nothing is wrong cryptographically;
//! the problem is that messages would split across them. §10's rule settles it
//! without another round trip: **keep the session whose initiator has the lower
//! `user_id`, close the other.** Both sides compare the same two IDs, so both
//! reach the same answer on their own.

use std::collections::{HashMap, HashSet};

use p2pchat_core::UserId;
use tokio::sync::mpsc;

use crate::session::Outgoing;

/// One live session, as much of it as anyone outside the session task needs.
#[derive(Clone, Debug)]
pub struct Handle {
    /// Who dialled. Not "the peer" and not "us": the tiebreak is on this.
    pub initiator: UserId,
    /// The name of this session's keys — `SessionCipher::session_id`.
    /// Every session derives its own, so this is how a test tells one
    /// session from the one it replaced without ever seeing a key.
    pub session_id: [u8; 32],
    /// Everything that goes out on the conversation stream goes through here,
    /// so frames are sealed and written in one place and therefore in one
    /// order — see [`crate::session`].
    pub outgoing: mpsc::Sender<Outgoing>,
}

/// What [`Registry::insert`] decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admit {
    /// The only session to this peer.
    Only,
    /// Kept, and the session it displaced must be closed.
    Replaced,
    /// A duplicate that lost the tiebreak. The caller closes it.
    Rejected,
}

#[derive(Default)]
pub struct Registry {
    sessions: HashMap<UserId, Handle>,
}

impl Registry {
    /// Offers a freshly established session for `peer`.
    ///
    /// The `Admit` is the caller's instruction: on `Rejected` close the session
    /// just established, on `Replaced` close the one this returns.
    pub fn insert(&mut self, peer: UserId, handle: Handle) -> (Admit, Option<Handle>) {
        match self.sessions.get(&peer) {
            // §10: lower initiator wins. `<` and not `<=` is deliberate — two
            // sessions with the same initiator are the same dial retried, and
            // the newer one is the live one.
            Some(existing) if existing.initiator < handle.initiator => (Admit::Rejected, None),
            Some(_) => {
                let displaced = self.sessions.insert(peer, handle);
                (Admit::Replaced, displaced)
            }
            None => {
                self.sessions.insert(peer, handle);
                (Admit::Only, None)
            }
        }
    }

    /// Forgets a session, if the one registered is still the one ending.
    ///
    /// The comparison matters: a session that lost the tiebreak is closed
    /// *after* the winner was registered, and its cleanup must not take the
    /// winner with it. It is on `session_id` and not on the initiator because
    /// a reconnection redials from the same side — the dead session and the
    /// one that replaced it have the same initiator, and the dead one's
    /// cleanup arrives late, when the peer's idle timeout finally fires.
    pub fn remove(&mut self, peer: &UserId, session_id: &[u8; 32]) {
        if self
            .sessions
            .get(peer)
            .is_some_and(|h| h.session_id == *session_id)
        {
            self.sessions.remove(peer);
        }
    }

    pub fn get(&self, peer: &UserId) -> Option<&Handle> {
        self.sessions.get(peer)
    }

    /// Everyone there is a live session with — M9e.
    ///
    /// This is what "connected" means: the screen asks the registry rather
    /// than remembering what an event once said, so a lost event costs a late
    /// redraw instead of a word that stays wrong for the life of the process.
    pub fn peers(&self) -> HashSet<UserId> {
        self.sessions.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `session` names the keys, which is what tells two sessions apart.
    fn handle(initiator: UserId, session: u8) -> Handle {
        Handle {
            initiator,
            session_id: [session; 32],
            outgoing: mpsc::channel(1).0,
        }
    }

    fn user(tag: u8) -> UserId {
        UserId::from_bytes([tag; 32])
    }

    /// §10, both orders of arrival: whichever session lands second, the one
    /// kept is the one the lower ID dialled.
    #[test]
    fn the_lower_initiator_survives_whichever_arrives_first() {
        let (low, high) = (user(0x11), user(0x99));
        let peer = user(0x42);

        let mut first = Registry::default();
        assert_eq!(first.insert(peer, handle(low, 1)).0, Admit::Only);
        assert_eq!(first.insert(peer, handle(high, 2)).0, Admit::Rejected);
        assert_eq!(first.get(&peer).unwrap().initiator, low);

        let mut second = Registry::default();
        assert_eq!(second.insert(peer, handle(high, 1)).0, Admit::Only);
        let (admit, displaced) = second.insert(peer, handle(low, 2));
        assert_eq!(admit, Admit::Replaced);
        assert_eq!(displaced.unwrap().initiator, high);
        assert_eq!(second.get(&peer).unwrap().initiator, low);

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
    }

    /// A redial by the same side replaces rather than piling up: the old
    /// session is gone, whatever the registry was told about it.
    #[test]
    fn a_redial_from_the_same_initiator_replaces() {
        let mut registry = Registry::default();
        let peer = user(0x42);

        assert_eq!(registry.insert(peer, handle(peer, 1)).0, Admit::Only);
        assert_eq!(registry.insert(peer, handle(peer, 2)).0, Admit::Replaced);
        assert_eq!(registry.len(), 1);
    }

    /// M10, and the reason `remove` is on the session and not on who dialled:
    /// a peer that was killed is redialled from the same side, so the new
    /// session has the same initiator as the dead one — whose cleanup only
    /// runs when the idle timeout fires, which is *after* the redial.
    #[test]
    fn a_dead_sessions_cleanup_does_not_take_its_replacement() {
        let mut registry = Registry::default();
        let peer = user(0x42);

        registry.insert(peer, handle(peer, 1));
        registry.insert(peer, handle(peer, 2));
        registry.remove(&peer, &[1; 32]);

        assert_eq!(registry.get(&peer).map(|h| h.session_id), Some([2; 32]));
        registry.remove(&peer, &[2; 32]);
        assert!(registry.is_empty());
    }

    /// The loser's cleanup runs after the winner is registered. It must not
    /// remove the winner.
    #[test]
    fn the_losers_cleanup_does_not_take_the_winner() {
        let (low, high) = (user(0x11), user(0x99));
        let peer = user(0x42);
        let mut registry = Registry::default();

        registry.insert(peer, handle(high, 1));
        registry.insert(peer, handle(low, 2));
        registry.remove(&peer, &[1; 32]);

        assert_eq!(registry.get(&peer).unwrap().initiator, low);
        registry.remove(&peer, &[2; 32]);
        assert!(registry.is_empty());
    }
}
