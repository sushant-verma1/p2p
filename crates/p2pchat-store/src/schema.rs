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
const MIGRATIONS: &[&str] = &[
    MIGRATION_1,
    MIGRATION_2,
    MIGRATION_3,
    MIGRATION_4,
    MIGRATION_5,
];

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

/// The public node's pending-request queue — `architecture.md` §3 and §8, F-07.
///
/// Its own migration rather than an edit to [`MIGRATION_1`]: a database created
/// at M6 exists, and an already-shipped migration is never edited.
const MIGRATION_2: &str = "
CREATE TABLE pending_requests (
    from_user_id     BLOB PRIMARY KEY,
    from_identity_pk BLOB NOT NULL,
    display_name     TEXT NOT NULL,
    addrs            TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    received_at      INTEGER NOT NULL,
    state            INTEGER NOT NULL
);

CREATE INDEX idx_pending_requests_state ON pending_requests(state, received_at);
";

/// Per-peer acceptance — `architecture.md` §8 and §10, M8a.
///
/// `ADD COLUMN` with a default, so every peer in an existing database starts
/// unaccepted. That is the safe direction and the honest one: those rows were
/// written when a handshake was all it took to get a session, and none of them
/// records a decision the user made.
const MIGRATION_3: &str = "
ALTER TABLE peers ADD COLUMN accepted INTEGER NOT NULL DEFAULT 0;
";

/// The requester's own half of §10's connection flow — M9d.
///
/// `outbound_requests` is one row per `CONNECTION_REQUEST` we sent and have not
/// had an answer to. It exists so that polling resumes after a restart: the
/// acceptor may take days to decide, and a request that stopped being asked
/// about when the process ended would need the user to send it again.
///
/// `addr` is the *public* node address the request went to, which is where the
/// status query goes as well. The private address to dial arrives in the
/// `Accepted` answer and is never stored: by then the dial is immediate.
///
/// `pending_requests.addrs` goes in the same migration. A `CONNECTION_REQUEST`
/// no longer carries an address (§3), so the column could only ever hold what
/// it already held — and a stale address in the one field that says where to
/// dial back is worse than no field at all.
const MIGRATION_4: &str = "
CREATE TABLE outbound_requests (
    to_user_id BLOB PRIMARY KEY,
    addr       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

ALTER TABLE pending_requests DROP COLUMN addrs;
";

/// Where to dial a peer again — `architecture.md` §10, M10.
///
/// Reconnection needs an address, and until now the only one on disk was the
/// *public* node's in `outbound_requests`, which is deleted the moment the
/// request is answered. This holds the private address §6 last completed a
/// handshake on: the peer answered there and proved who it was, which is the
/// only evidence this node has that the address is worth dialling again.
///
/// It is a cache, not a record. A peer that moves is unreachable here until it
/// asks again, and that is the accepted V0.1 limitation — only the requester
/// dials, so only the requester needs an address.
const MIGRATION_5: &str = "
ALTER TABLE peers ADD COLUMN last_addr TEXT;
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

        for table in [
            "peers",
            "conversations",
            "messages",
            "pending_requests",
            "outbound_requests",
            "schema_version",
        ] {
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

    /// A database left at M6's version gains M7's table without losing its
    /// rows. Migrations are append-only precisely so this works.
    #[test]
    fn an_existing_database_migrates_forward() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATION_1).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO peers (user_id, identity_pk, first_seen, verified)
             VALUES (?1, ?2, 0, 0)",
            rusqlite::params![[1u8; 32].as_slice(), [2u8; 32].as_slice()],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(current_version(&conn).unwrap(), SCHEMA_VERSION);
        let peers: i64 = conn
            .query_row("SELECT count(*) FROM peers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(peers, 1, "migrating dropped a row");
        let pending: i64 = conn
            .query_row("SELECT count(*) FROM pending_requests", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending, 0);

        // M8a: a peer that predates the acceptance column starts unaccepted.
        // The other default would hand a session to everyone already in the
        // database the moment the check appeared.
        let accepted: i64 = conn
            .query_row("SELECT accepted FROM peers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(accepted, 0, "an old peer row migrated in as accepted");
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
