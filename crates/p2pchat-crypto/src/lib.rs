//! Identity, handshake, AEAD, KDF and keystore.

#![forbid(unsafe_code)]

pub mod handshake;
pub mod identity;
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
