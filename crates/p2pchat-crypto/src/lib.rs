//! Identity, handshake, AEAD, KDF and keystore.

#![forbid(unsafe_code)]

pub mod identity;
pub mod keystore;

pub use identity::{derive_user_id, Identity};

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
