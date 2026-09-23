//! Identity, handshake, AEAD, KDF and keystore.

#![forbid(unsafe_code)]

pub mod handshake;
pub mod identity;
pub mod invite;
pub mod keystore;
pub mod session;

pub use handshake::{Initiator, Responder, Role, Session};
pub use identity::{derive_conversation_id, derive_user_id, Identity};
pub use session::SessionCipher;

use std::path::PathBuf;

use thiserror::Error;

/// Handshake and session failures.
///
/// `architecture.md` §6: what a peer is told is deliberately coarse — which
/// check failed is an oracle, so the detail is logged locally and never sent.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("handshake failed")]
    Handshake,

    #[error("decryption failed")]
    Decrypt,

    /// §7 receiver rule 3. Local only: the peer is closed on, never told.
    #[error("frame is not from the authenticated peer")]
    SenderMismatch,

    /// `architecture.md` §7: "if `frame_seq` would exceed 2^32, tear down the
    /// session and rekey". An error, because wrapping reuses a nonce.
    #[error("frame sequence exhausted; the session must be torn down")]
    SequenceExhausted,

    #[error("key derivation failed")]
    Kdf,

    #[error("key file {} is accessible to other users (mode {mode:04o}); run: chmod 600 {}", path.display(), path.display())]
    KeyFilePermissions { path: PathBuf, mode: u32 },

    #[error("key file {} is malformed: expected {} bytes, found {found}", path.display(), identity::SEED_LEN)]
    MalformedKeyFile { path: PathBuf, found: usize },

    #[error("key file {}: {source}", path.display())]
    KeyFileIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    // The four invite outcomes are separate variants, unlike the handshake's
    // single `Handshake`, because `architecture.md` §9 requires it: an invite
    // is pasted by the user, not offered by a live peer, so there is no oracle
    // to protect and the user's next move differs in each case.
    /// Not an invite at all: wrong scheme, bad base64, bad `postcard`, or a
    /// field past the bounds in `wire`. Re-copy it.
    #[error("not a valid p2pchat invite")]
    InviteMalformed,

    /// `BLAKE3(domain ‖ identity_pk) != user_id` — the blob contradicts itself.
    #[error("invite user ID does not match its identity key")]
    InviteUserId,

    /// The signature does not verify: the invite was altered in transit, or it
    /// was written by someone else. Never a timing signal — see `invite`.
    #[error("invite signature does not verify")]
    InviteSignature,

    /// Signed, consistent, and past `expires_at` plus the skew allowance —
    /// OD-3. Its own variant because the answer is "ask for a new invite"
    /// rather than "re-copy the one you have".
    #[error("invite has expired; ask for a new one")]
    InviteExpired,

    /// `0.0.0.0` or `[::]`: a bind address, which names no host. Refused where
    /// the invite is built rather than where it is dialled, because by then it
    /// is a blob someone has already pasted into a chat.
    #[error("cannot advertise {0}: that is a bind address, not one another host can reach; pass --addr with an address peers can dial")]
    InviteUnspecifiedAddr(std::net::SocketAddr),

    /// Nothing to advertise at all — M9d. Same instruction as
    /// [`CryptoError::InviteUnspecifiedAddr`] for the same reason, and the
    /// same one `Node::decide` gives when a request cannot be accepted for
    /// want of an address to answer with.
    #[error("{}", invite::NO_ADDR)]
    InviteNoAddr,

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}

/// The AEAD says only "it did not authenticate", which is all §7 needs: the
/// receiver closes the connection either way.
impl From<chacha20poly1305::Error> for CryptoError {
    fn from(_: chacha20poly1305::Error) -> Self {
        Self::Decrypt
    }
}
