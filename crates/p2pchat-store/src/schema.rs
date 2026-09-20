//! Schema and migrations — `architecture.md` §8.
//!
//! The table definitions are that section, copied. If the two ever disagree,
//! the document is right and this file is the bug.
//!
//! Migrations run forward from whatever `schema_version` holds, each inside its
//! own transaction, so a second run over a current database applies nothing.

use rusqlite::{Connection, OptionalExtension};

use crate::StoreError;

/// One entry per version, in order. Index 0 takes an empty file to version 1.
///
/// Migrations are append-only: an already-shipped entry is never edited,
/// because a database that has run it will not run it again.
const MIGRATIONS: &[&str] = &[MIGRATION_1];

pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

const MIGRATION_1: &str = "
CREATE TABLE peers (
    user_id       BLOB PRIMARY KEY,
    identity_pk   BLOB NOT NULL,
    display_name  TEXT,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER,
    verified      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE conversations (
    conversation_id BLOB PRIMARY KEY,
    peer_id         BLOB NOT NULL REFERENCES peers(user_id),
    created_at      INTEGER NOT NULL,
    last_msg_seq    INTEGER NOT NULL DEFAULT 0,
    peer_acked_seq  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE messages (
    message_id      BLOB PRIMARY KEY,
    conversation_id BLOB NOT NULL REFERENCES conversations(conversation_id),
    sender_id       BLOB NOT NULL,
    msg_seq         INTEGER NOT NULL,
    body            BLOB NOT NULL,
    created_at      INTEGER NOT NULL,
    received_at     INTEGER,
    status          INTEGER NOT NULL,
    UNIQUE (conversation_id, sender_id, msg_seq)
);

CREATE INDEX idx_messages_conv_seq ON messages(conversation_id, msg_seq);

CREATE TABLE schema_version (version INTEGER NOT NULL);
";

/// Brings `conn` up to [`SCHEMA_VERSION`], doing nothing if it is already there.
pub fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let found = current_version(conn)?;
    if found > SCHEMA_VERSION {
        // Written by a newer build. Guessing at a forward schema is worse than
        // refusing, so refuse.
        return Err(StoreError::SchemaVersion {
            found,
            expected: SCHEMA_VERSION,
        });
    }

    for (index, sql) in MIGRATIONS.iter().enumerate().skip(found as usize) {
        let version = index as i64 + 1;
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        // One row, replaced rather than appended: the table records where the
        // database is, not where it has been.
        tx.execute("DELETE FROM schema_version", [])?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [version],
        )?;
        tx.commit()?;
    }

    Ok(())
}

/// The version on disk; 0 for a database that has never been migrated.
///
/// `schema_version` is itself created by migration 1, so its absence is the
/// empty case rather than an error.
fn current_version(conn: &Connection) -> Result<i64, StoreError> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    if !exists {
        return Ok(0);
    }

    Ok(conn
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .optional()?
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrated() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        conn
    }

    /// M6 gate 5, first half: empty file to current.
    #[test]
    fn migrating_an_empty_database_reaches_the_current_version() {
        let conn = migrated();
        assert_eq!(current_version(&conn).unwrap(), SCHEMA_VERSION);

        for table in ["peers", "conversations", "messages", "schema_version"] {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{table} was not created");
        }
    }

    /// M6 gate 5, second half. A migration that re-ran would fail on
    /// `CREATE TABLE`, so this is not merely a version assertion.
    #[test]
    fn a_second_migration_is_a_no_op() {
        let mut conn = migrated();
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();

        assert_eq!(current_version(&conn).unwrap(), SCHEMA_VERSION);
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "schema_version accumulated rows");
    }

    #[test]
    fn a_database_from_the_future_is_refused() {
        let mut conn = migrated();
        conn.execute(
            "UPDATE schema_version SET version = ?1",
            [SCHEMA_VERSION + 1],
        )
        .unwrap();

        let err = migrate(&mut conn).unwrap_err();
        assert!(matches!(err, StoreError::SchemaVersion { .. }), "{err:?}");
    }
}
