//! SQLite schema, migrations and repositories — `architecture.md` §8.
//!
//! `rusqlite::Connection` is not `Sync` and SQLite serializes writes anyway, so
//! one actor task owns the connection and everything else reaches it over a
//! channel — `architecture.md` §2. No pool, no `Arc<Mutex<Connection>>`.
//!
//! **The database never stores wire ciphertext** (agent.md §3 invariant 12).
//! `body` holds the plaintext, per OD-1: history outlives the session that
//! carried it, and keeping the ciphertext would mean keeping every session key
//! ever used. Since the rows are readable by anyone who can read the file, the
//! file's permissions are the only protection — see [`db::PERMISSIONS_ENFORCED`].

#![forbid(unsafe_code)]

mod actor;
mod db;
mod repo;
mod schema;

pub use actor::Store;
pub use db::{db_path, open, FILE_NAME, PERMISSIONS_ENFORCED};
pub use repo::{conversations, messages, peers, Conversation, Cursor, Message, Peer, PAGE_SIZE};
pub use schema::SCHEMA_VERSION;

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database is at schema version {found}, expected {expected}")]
    SchemaVersion { found: i64, expected: i64 },

    /// Bodies are plaintext (OD-1), so this is the same trust boundary as the
    /// identity key file, and it is refused the same way.
    #[error("database file {} is accessible to other users (mode {mode:04o}); run: chmod 600 {}", path.display(), path.display())]
    FilePermissions { path: PathBuf, mode: u32 },

    #[error("database file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The actor task is gone: either the handle was dropped, or opening the
    /// database failed and the task never started.
    #[error("the store actor has stopped")]
    ActorStopped,

    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}
