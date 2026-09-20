//! The repositories — `architecture.md` §8.
//!
//! Free functions over a borrowed connection rather than structs holding one:
//! the connection has exactly one owner (the actor), so a repository object
//! would be a name for a borrow and nothing else.
//!
//! Identifiers bind as `&[u8]`, which `rusqlite` already handles, and read back
//! through [`Blob`], which is where a column of the wrong length is caught.

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use rusqlite::{params, Connection, OptionalExtension, Row};

use p2pchat_core::wire::DeliveryStatus;
use p2pchat_core::{ConversationId, MessageId, MsgSeq, UserId};

use crate::StoreError;

/// F-22: scrollback loads history in pages of this size rather than reading a
/// whole conversation.
pub const PAGE_SIZE: usize = 50;

// ---------------------------------------------------------------------------
// Column conversions
// ---------------------------------------------------------------------------

/// A fixed-length BLOB column. The core ID types cannot implement `FromSql`
/// here — both traits are foreign to this crate — so this is the local type
/// that can.
struct Blob<const N: usize>([u8; N]);

impl<const N: usize> FromSql for Blob<N> {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let bytes = value.as_blob()?;
        bytes.try_into().map(Blob).map_err(|_| {
            FromSqlError::Other(format!("expected a {N}-byte blob, found {}", bytes.len()).into())
        })
    }
}

/// `architecture.md` §8: `0 pending 1 sent 2 delivered 3 read 4 failed`, which
/// is both the stored integer and the `postcard` variant index.
fn status_to_i64(status: DeliveryStatus) -> i64 {
    match status {
        DeliveryStatus::Pending => 0,
        DeliveryStatus::Sent => 1,
        DeliveryStatus::Delivered => 2,
        DeliveryStatus::Read => 3,
        DeliveryStatus::Failed => 4,
    }
}

fn status_from_i64(value: i64) -> FromSqlResult<DeliveryStatus> {
    Ok(match value {
        0 => DeliveryStatus::Pending,
        1 => DeliveryStatus::Sent,
        2 => DeliveryStatus::Delivered,
        3 => DeliveryStatus::Read,
        4 => DeliveryStatus::Failed,
        other => return Err(FromSqlError::OutOfRange(other)),
    })
}

/// SQLite's only integer type is signed. Sequence numbers and millisecond
/// timestamps both stay far below 2^63, so this round-trips; the cast is here
/// rather than at twenty call sites so that it is one thing to be wrong about.
fn as_i64(value: u64) -> i64 {
    value as i64
}

fn as_u64(value: i64) -> u64 {
    value as u64
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub user_id: UserId,
    pub identity_pk: [u8; 32],
    /// Advisory only and never trusted — agent.md §7.
    pub display_name: Option<String>,
    pub first_seen: u64,
    pub last_seen: Option<u64>,
    /// Fingerprint confirmed out-of-band — F-09.
    pub verified: bool,
}

pub mod peers {
    use super::*;

    /// Inserts, or refreshes what a later sighting can tell us.
    ///
    /// `first_seen` and `verified` are deliberately left alone: the first
    /// sighting is the first sighting, and F-09 requires a confirmed
    /// fingerprint to survive everything short of the user unconfirming it.
    pub fn upsert(conn: &Connection, peer: &Peer) -> Result<(), StoreError> {
        conn.execute(
            "INSERT INTO peers (user_id, identity_pk, display_name, first_seen, last_seen, verified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user_id) DO UPDATE SET
                 identity_pk  = excluded.identity_pk,
                 display_name = excluded.display_name,
                 last_seen    = excluded.last_seen",
            params![
                peer.user_id.as_bytes().as_slice(),
                peer.identity_pk.as_slice(),
                peer.display_name,
                as_i64(peer.first_seen),
                peer.last_seen.map(as_i64),
                peer.verified as i64,
            ],
        )?;
        Ok(())
    }

    pub fn get(conn: &Connection, user_id: &UserId) -> Result<Option<Peer>, StoreError> {
        Ok(conn
            .query_row(
                "SELECT user_id, identity_pk, display_name, first_seen, last_seen, verified
                 FROM peers WHERE user_id = ?1",
                [user_id.as_bytes().as_slice()],
                row_to_peer,
            )
            .optional()?)
    }

    fn row_to_peer(row: &Row<'_>) -> rusqlite::Result<Peer> {
        Ok(Peer {
            user_id: UserId::from_bytes(row.get::<_, Blob<32>>(0)?.0),
            identity_pk: row.get::<_, Blob<32>>(1)?.0,
            display_name: row.get(2)?,
            first_seen: as_u64(row.get(3)?),
            last_seen: row.get::<_, Option<i64>>(4)?.map(as_u64),
            verified: row.get::<_, i64>(5)? != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Conversations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conversation {
    pub conversation_id: ConversationId,
    pub peer_id: UserId,
    pub created_at: u64,
    /// Highest we have sent.
    pub last_msg_seq: MsgSeq,
    /// Highest the peer has confirmed.
    pub peer_acked_seq: MsgSeq,
}

pub mod conversations {
    use super::*;

    /// Opens the conversation if it is not already open.
    ///
    /// `conversation_id` is derived from the pair of user IDs
    /// (`p2pchat_crypto::derive_conversation_id`), so "already open" is the
    /// normal case on every reconnect and is not worth a round trip to check.
    pub fn open(
        conn: &Connection,
        conversation_id: &ConversationId,
        peer_id: &UserId,
        created_at: u64,
    ) -> Result<(), StoreError> {
        conn.execute(
            "INSERT OR IGNORE INTO conversations (conversation_id, peer_id, created_at)
             VALUES (?1, ?2, ?3)",
            params![
                conversation_id.as_bytes().as_slice(),
                peer_id.as_bytes().as_slice(),
                as_i64(created_at),
            ],
        )?;
        Ok(())
    }

    pub fn get(
        conn: &Connection,
        conversation_id: &ConversationId,
    ) -> Result<Option<Conversation>, StoreError> {
        Ok(conn
            .query_row(
                "SELECT conversation_id, peer_id, created_at, last_msg_seq, peer_acked_seq
                 FROM conversations WHERE conversation_id = ?1",
                [conversation_id.as_bytes().as_slice()],
                row_to_conversation,
            )
            .optional()?)
    }

    fn row_to_conversation(row: &Row<'_>) -> rusqlite::Result<Conversation> {
        Ok(Conversation {
            conversation_id: ConversationId::from_bytes(row.get::<_, Blob<32>>(0)?.0),
            peer_id: UserId::from_bytes(row.get::<_, Blob<32>>(1)?.0),
            created_at: as_u64(row.get(2)?),
            last_msg_seq: MsgSeq::new(as_u64(row.get(3)?)),
            peer_acked_seq: MsgSeq::new(as_u64(row.get(4)?)),
        })
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub message_id: MessageId,
    pub conversation_id: ConversationId,
    pub sender_id: UserId,
    pub msg_seq: MsgSeq,
    /// Plaintext — OD-1, and agent.md §3 invariant 12: never wire ciphertext.
    pub body: Vec<u8>,
    pub created_at: u64,
    pub received_at: Option<u64>,
    pub status: DeliveryStatus,
}

impl Message {
    /// Where a page ends, so the next one can start below it.
    pub fn cursor(&self) -> Cursor {
        Cursor {
            msg_seq: self.msg_seq,
            message_id: self.message_id,
        }
    }
}

/// The position of the oldest row on a page — F-22 asks for the next fifty
/// older rows, not for an offset into a result set that is still growing at the
/// other end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub msg_seq: MsgSeq,
    pub message_id: MessageId,
}

pub mod messages {
    use super::*;

    const COLUMNS: &str = "message_id, conversation_id, sender_id, msg_seq, body,
                           created_at, received_at, status";

    /// `msg_seq` counts per sender, so within a conversation the two peers both
    /// number from their own counter and the column is not unique on its own —
    /// hence the tie-break on `message_id`, the primary key. Being a UUIDv7 it
    /// compares in time order under SQLite's `memcmp` on blobs, so the
    /// tie-break is the arrival order of the two sides' Nth messages.
    const ORDER: &str = "ORDER BY msg_seq DESC, message_id DESC";

    /// `true` if the row was stored, `false` if we already had it — F-15.
    ///
    /// The `UNIQUE (conversation_id, sender_id, msg_seq)` constraint is the
    /// dedupe mechanism and `INSERT OR IGNORE` is how it reports: zero rows
    /// affected means "already have it". A `SELECT` first and an `INSERT` after
    /// would be the same answer with a race in the middle.
    pub fn insert(conn: &Connection, message: &Message) -> Result<bool, StoreError> {
        let affected = conn.execute(
            "INSERT OR IGNORE INTO messages
                 (message_id, conversation_id, sender_id, msg_seq, body,
                  created_at, received_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                message.message_id.as_bytes().as_slice(),
                message.conversation_id.as_bytes().as_slice(),
                message.sender_id.as_bytes().as_slice(),
                as_i64(message.msg_seq.get()),
                message.body,
                as_i64(message.created_at),
                message.received_at.map(as_i64),
                status_to_i64(message.status),
            ],
        )?;
        Ok(affected == 1)
    }

    /// One page of history, newest first. `before` is [`Message::cursor`] of the
    /// last row of the previous page, or `None` for the newest page.
    ///
    /// Keyset, not `OFFSET`: `OFFSET n` makes SQLite walk and discard n rows, so
    /// scrolling back through a long conversation gets slower the further it
    /// goes, which is exactly the direction F-22 scrolls.
    pub fn page(
        conn: &Connection,
        conversation_id: &ConversationId,
        before: Option<Cursor>,
    ) -> Result<Vec<Message>, StoreError> {
        let limit = as_i64(PAGE_SIZE as u64);
        let conversation_id = conversation_id.as_bytes().as_slice();

        match before {
            None => {
                let sql = format!(
                    "SELECT {COLUMNS} FROM messages
                     WHERE conversation_id = ?1
                     {ORDER} LIMIT ?2"
                );
                collect(conn, &sql, params![conversation_id, limit])
            }
            Some(cursor) => {
                let sql = format!(
                    "SELECT {COLUMNS} FROM messages
                     WHERE conversation_id = ?1
                       AND (msg_seq < ?2 OR (msg_seq = ?2 AND message_id < ?3))
                     {ORDER} LIMIT ?4"
                );
                collect(
                    conn,
                    &sql,
                    params![
                        conversation_id,
                        as_i64(cursor.msg_seq.get()),
                        cursor.message_id.as_bytes().as_slice(),
                        limit
                    ],
                )
            }
        }
    }

    /// How many messages a conversation holds. Not on the scrollback path; it
    /// is what a test asserts a duplicate did not add.
    pub fn count(conn: &Connection, conversation_id: &ConversationId) -> Result<i64, StoreError> {
        Ok(conn.query_row(
            "SELECT count(*) FROM messages WHERE conversation_id = ?1",
            [conversation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?)
    }

    fn collect(
        conn: &Connection,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<Message>, StoreError> {
        let mut statement = conn.prepare(sql)?;
        let rows = statement.query_map(params, row_to_message)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn row_to_message(row: &Row<'_>) -> rusqlite::Result<Message> {
        Ok(Message {
            message_id: MessageId::from_bytes(row.get::<_, Blob<16>>(0)?.0),
            conversation_id: ConversationId::from_bytes(row.get::<_, Blob<32>>(1)?.0),
            sender_id: UserId::from_bytes(row.get::<_, Blob<32>>(2)?.0),
            msg_seq: MsgSeq::new(as_u64(row.get(3)?)),
            body: row.get(4)?,
            created_at: as_u64(row.get(5)?),
            received_at: row.get::<_, Option<i64>>(6)?.map(as_u64),
            status: status_from_i64(row.get(7)?)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored integer is `architecture.md` §8's numbering, and it round
    /// trips. A renumbering would silently rewrite the meaning of every stored
    /// row, so it is pinned to the literals rather than to a derive.
    #[test]
    fn delivery_status_maps_to_the_documented_integers() {
        let expected = [
            (DeliveryStatus::Pending, 0),
            (DeliveryStatus::Sent, 1),
            (DeliveryStatus::Delivered, 2),
            (DeliveryStatus::Read, 3),
            (DeliveryStatus::Failed, 4),
        ];
        for (status, stored) in expected {
            assert_eq!(status_to_i64(status), stored);
            assert_eq!(status_from_i64(stored).unwrap(), status);
        }
        assert!(status_from_i64(5).is_err());
    }
}
