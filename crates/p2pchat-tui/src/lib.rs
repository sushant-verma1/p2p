//! ratatui rendering and input.
//!
//! Talks to the rest of the application over channels only, and nothing in the
//! workspace depends on this crate — see `architecture.md` §2.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal I/O failed")]
    Terminal(#[source] std::io::Error),

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}
