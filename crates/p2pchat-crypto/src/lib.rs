//! Identity, handshake, AEAD, KDF and keystore.

#![forbid(unsafe_code)]

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

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}
