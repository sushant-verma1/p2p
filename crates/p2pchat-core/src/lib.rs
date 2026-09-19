//! Shared types, wire format and errors.
//!
//! Depends on nothing else in the workspace — see `architecture.md` §2.

#![forbid(unsafe_code)]

pub mod id;

pub use id::UserId;

use thiserror::Error;

/// Maximum size of a single wire frame — `architecture.md` §5.
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum CoreError {
    /// `architecture.md` §5: an over-size frame closes the connection instead of
    /// being allocated.
    #[error("frame of {size} bytes exceeds the {} byte limit", MAX_FRAME_SIZE)]
    FrameTooLarge { size: usize },

    /// `architecture.md` §6 check 1.
    #[error("unsupported protocol version")]
    UnsupportedVersion,
}
