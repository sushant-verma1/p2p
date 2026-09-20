//! The identifier newtypes — `architecture.md` §4, §7 and §8.
//!
//! Every one of these is a distinct type over the same handful of primitives.
//! That is deliberate: `architecture.md` §7 says confusing `frame_seq` with
//! `msg_seq` is the easiest way to reintroduce nonce reuse, and agent.md §3
//! invariant 7 repeats it. A wrapper makes that a compile error rather than
//! something a reviewer has to notice.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `BLAKE3(b"p2pchat-v1-userid" || identity_pk)`, 32 bytes.
///
/// Derivation lives in `p2pchat-crypto`; this crate only carries the type, so
/// that `store` and `tui` can name a user without depending on the crypto
/// layer.
///
/// `Debug` and `Display` both render the *fingerprint*, never the full ID: a
/// full ID in a log line is what agent.md §2 forbids, and making the safe form
/// the default is cheaper than remembering. `to_hex` is the explicit opt-in.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UserId([u8; 32]);

impl UserId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// All 64 hex characters. For the profile screen and the invite blob, not
    /// for logs.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// The first 16 hex characters in groups of four: `a83f 1e92 7c4b 0d15`.
    ///
    /// This is what users compare out-of-band to detect a swapped invite.
    pub fn fingerprint(&self) -> String {
        let mut out = String::with_capacity(19);
        for (i, byte) in self.0[..8].iter().enumerate() {
            if i % 2 == 0 && i != 0 {
                out.push(' ');
            }
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.fingerprint())
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId({})", self.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> UserId {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        UserId::from_bytes(bytes)
    }

    #[test]
    fn fingerprint_is_four_groups_of_four() {
        let id = UserId::from_bytes([
            0xa8, 0x3f, 0x1e, 0x92, 0x7c, 0x4b, 0x0d, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(id.fingerprint(), "a83f 1e92 7c4b 0d15");
    }

    #[test]
    fn hex_is_sixty_four_lowercase_chars() {
        let hex = sample().to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("000102030405"));
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    /// Neither rendering may leak the whole ID — agent.md §2.
    #[test]
    fn debug_and_display_show_only_the_fingerprint() {
        let id = sample();
        let full = id.to_hex();
        for rendered in [format!("{id}"), format!("{id:?}")] {
            assert!(!rendered.contains(&full), "{rendered} leaked the full id");
            assert!(rendered.contains(&id.fingerprint()));
        }
    }
}

/// `BLAKE3(b"p2pchat-v1-conv" || min(a, b) || max(a, b))` — `architecture.md` §8.
///
/// Derived, never negotiated, so both peers compute the same value. The
/// derivation itself lives in `p2pchat-crypto`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConversationId([u8; 32]);

impl ConversationId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// First 16 hex characters. A conversation ID identifies a *pair* of users,
    /// so the short form is what goes in a log line.
    pub fn short(&self) -> String {
        let mut out = String::with_capacity(16);
        for byte in &self.0[..8] {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Display for ConversationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

impl fmt::Debug for ConversationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConversationId({})", self.short())
    }
}

/// A UUIDv7 — `architecture.md` §8. Time-ordered, so the primary key index
/// stays dense.
///
/// Held as the 16 raw bytes rather than as a `Uuid` so that the wire encoding
/// is 16 fixed bytes with no length prefix and no dependence on how `uuid`
/// chooses to serialize itself.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MessageId([u8; 16]);

impl MessageId {
    /// A fresh time-ordered ID. The only place in this crate that is not a
    /// pure function of its input.
    pub fn now_v7() -> Self {
        Self(Uuid::now_v7().into_bytes())
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Uuid::from_bytes(self.0), f)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", Uuid::from_bytes(self.0))
    }
}

/// Transport sequence number: per-session, per-direction, reset to 0 on every
/// new session — `architecture.md` §7.
///
/// This is the value the AEAD nonce is derived from. It is **not**
/// interchangeable with [`MsgSeq`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct FrameSeq(u64);

impl FrameSeq {
    pub const ZERO: Self = Self(0);

    /// `architecture.md` §7: "If `frame_seq` would exceed 2^32, tear down the
    /// session and rekey. This will not happen in practice; assert it anyway."
    pub const LIMIT: u64 = 1 << 32;

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// `None` once the limit is reached — the caller tears the session down
    /// rather than wrapping a nonce.
    pub fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) if next <= Self::LIMIT => Some(Self(next)),
            _ => None,
        }
    }
}

/// Application sequence number: per-conversation, persistent across sessions,
/// used by resync — `architecture.md` §7 and §10.
///
/// Not interchangeable with [`FrameSeq`]; no nonce is ever derived from it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct MsgSeq(u64);

impl MsgSeq {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

#[cfg(test)]
mod seq_tests {
    use super::*;

    #[test]
    fn frame_seq_stops_at_the_limit() {
        let last = FrameSeq::new(FrameSeq::LIMIT - 1);
        assert_eq!(last.checked_next(), Some(FrameSeq::new(FrameSeq::LIMIT)));
        assert_eq!(FrameSeq::new(FrameSeq::LIMIT).checked_next(), None);
        assert_eq!(FrameSeq::new(u64::MAX).checked_next(), None);
    }

    #[test]
    fn a_conversation_id_renders_short() {
        let id = ConversationId::from_bytes([0xab; 32]);
        assert_eq!(id.short(), "abababababababab");
        assert_eq!(format!("{id:?}"), "ConversationId(abababababababab)");
    }

    #[test]
    fn message_ids_are_time_ordered() {
        let a = MessageId::now_v7();
        let b = MessageId::now_v7();
        // The first six bytes are the millisecond timestamp, big-endian; the
        // rest is random, so only the prefix is guaranteed to be ordered.
        assert!(a.as_bytes()[..6] <= b.as_bytes()[..6], "{a} came after {b}");
        assert_eq!(MessageId::from_bytes(*a.as_bytes()), a);
    }
}
