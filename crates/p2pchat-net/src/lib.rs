//! QUIC endpoints, public node, private node, sessions.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("connection closed")]
    ConnectionClosed,

    #[error(transparent)]
    Crypto(#[from] p2pchat_crypto::CryptoError),

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}
