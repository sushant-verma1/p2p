//! SQLite schema, migrations and repositories.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database is at schema version {found}, expected {expected}")]
    SchemaVersion { found: i64, expected: i64 },

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}
