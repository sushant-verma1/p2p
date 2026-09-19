//! User IDs and their human-facing fingerprint — `architecture.md` §4.

use std::fmt;

/// `BLAKE3(b"p2pchat-v1-userid" || identity_pk)`, 32 bytes.
///
/// Derivation lives in `p2pchat-crypto`; this crate only carries the type, so
/// that `store` and `tui` can name a user without depending on the crypto
/// layer.
///
/// `Debug` and `Display` both render the *fingerprint*, never the full ID: a
/// full ID in a log line is what agent.md §2 forbids, and making the safe form
/// the default is cheaper than remembering. `to_hex` is the explicit opt-in.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
