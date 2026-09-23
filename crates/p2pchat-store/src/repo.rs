//! The repositories — `architecture.md` §8.
//!
//! Free functions over a borrowed connection rather than structs holding one:
//! the connection has exactly one owner (the actor), so a repository object
//! would be a name for a borrow and nothing else.
//!
//! Identifiers bind as `&[u8]`, which `rusqlite` already handles, and read back
//! through [`Blob`], which is where a column of the wrong length is caught.

use std::net::SocketAddr;

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use rusqlite::{params, Connection, OptionalExtension, Row};

use p2pchat_core::wire::{DeliveryStatus, RequestState};
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
    /// The user let this peer in — `architecture.md` §10, F-06. Written by
    /// [`peers::set_accepted`] and by nothing else; in particular a handshake
    /// does not set it, or a peer would be granting itself access by
    /// connecting.
    pub accepted: bool,
}

pub mod peers {
    use super::*;

    /// Named once: `get` and `list` read the same row, and a column added to
    /// one list and not the other is an off-by-one in `row_to_peer`.
    const COLUMNS: &str =
        "user_id, identity_pk, display_name, first_seen, last_seen, verified, accepted";

    /// Inserts, or refreshes what a later sighting can tell us.
    ///
    /// `first_seen`, `verified` and `accepted` are deliberately left alone: the
    /// first sighting is the first sighting, F-09 requires a confirmed
    /// fingerprint to survive everything short of the user unconfirming it, and
    /// §10's acceptance is the user's decision rather than a side effect of the
    /// peer turning up.
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
                &format!("SELECT {COLUMNS} FROM peers WHERE user_id = ?1"),
                [user_id.as_bytes().as_slice()],
                row_to_peer,
            )
            .optional()?)
    }

    /// Everyone we have ever had a session with, first sighting first — F-09's
    /// list, and what the debug CLI prints.
    pub fn list(conn: &Connection) -> Result<Vec<Peer>, StoreError> {
        let mut statement = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM peers ORDER BY first_seen, user_id"
        ))?;
        let rows = statement.query_map([], row_to_peer)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// F-09: the user compared the fingerprint out of band and said so.
    ///
    /// `false` if there is no such peer. Deliberately reversible — a user who
    /// verified the wrong person needs a way back.
    pub fn set_verified(
        conn: &Connection,
        user_id: &UserId,
        verified: bool,
    ) -> Result<bool, StoreError> {
        let affected = conn.execute(
            "UPDATE peers SET verified = ?2 WHERE user_id = ?1",
            params![user_id.as_bytes().as_slice(), verified as i64],
        )?;
        Ok(affected == 1)
    }

    /// The user's standing decision about this peer — `architecture.md` §10.
    ///
    /// Upserts, because the decision normally comes *before* the first
    /// handshake: the row it creates holds no key. `identity_pk` stays all-zero
    /// until §6 proves one, and an all-zero value can never satisfy check 2, so
    /// nothing can mistake the row for a peer we have authenticated — which is
    /// the distinction §8 draws between `pending_requests` and `peers`.
    ///
    /// `first_seen` comes from SQLite's clock rather than a parameter threaded
    /// through three layers; it is the same wall clock, for a column that only
    /// orders the peer list.
    pub fn set_accepted(
        conn: &Connection,
        user_id: &UserId,
        accepted: bool,
    ) -> Result<(), StoreError> {
        conn.execute(
            "INSERT INTO peers (user_id, identity_pk, first_seen, verified, accepted)
             VALUES (?1, zeroblob(32), unixepoch(), 0, ?2)
             ON CONFLICT(user_id) DO UPDATE SET accepted = excluded.accepted",
            params![user_id.as_bytes().as_slice(), accepted as i64],
        )?;
        Ok(())
    }

    /// Remembers where §6 last completed a handshake with this peer — M10.
    ///
    /// Written only after a handshake succeeded at that address, so it is an
    /// address the peer has proved it answers at rather than one it claimed.
    pub fn set_addr(
        conn: &Connection,
        user_id: &UserId,
        addr: SocketAddr,
    ) -> Result<(), StoreError> {
        conn.execute(
            "UPDATE peers SET last_addr = ?2 WHERE user_id = ?1",
            params![user_id.as_bytes().as_slice(), addr.to_string()],
        )?;
        Ok(())
    }

    /// Accepted peers there is an address for — M10's reconnect-at-startup.
    ///
    /// Both conditions are the whole list: §10 dials only accepted peers, and
    /// a peer with no address is one this node has never dialled and so is not
    /// the requester for.
    pub fn reconnectable(conn: &Connection) -> Result<Vec<(UserId, SocketAddr)>, StoreError> {
        let mut statement = conn.prepare(
            "SELECT user_id, last_addr FROM peers
             WHERE accepted = 1 AND last_addr IS NOT NULL
             ORDER BY first_seen, user_id",
        )?;
        let rows = statement.query_map([], |row| {
            let addr = row
                .get::<_, String>(1)?
                .parse::<SocketAddr>()
                .map_err(|e| FromSqlError::Other(Box::new(e)))?;
            Ok((UserId::from_bytes(row.get::<_, Blob<32>>(0)?.0), addr))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Whether a session with this peer is permitted — `architecture.md` §10.
    ///
    /// A peer nobody has decided about is not accepted, which is where every
    /// peer starts.
    pub fn is_accepted(conn: &Connection, user_id: &UserId) -> Result<bool, StoreError> {
        Ok(conn
            .query_row(
                "SELECT accepted FROM peers WHERE user_id = ?1",
                [user_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|accepted| accepted != 0))
    }

    fn row_to_peer(row: &Row<'_>) -> rusqlite::Result<Peer> {
        Ok(Peer {
            user_id: UserId::from_bytes(row.get::<_, Blob<32>>(0)?.0),
            identity_pk: row.get::<_, Blob<32>>(1)?.0,
            display_name: row.get(2)?,
            first_seen: as_u64(row.get(3)?),
            last_seen: row.get::<_, Option<i64>>(4)?.map(as_u64),
            verified: row.get::<_, i64>(5)? != 0,
            accepted: row.get::<_, i64>(6)? != 0,
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

    /// Reserves the next `msg_seq` for the messages *we* send here.
    ///
    /// The increment and the read are one statement, so two sends that race
    /// cannot take the same number — which the `UNIQUE (conversation_id,
    /// sender_id, msg_seq)` constraint would turn into a silently dropped
    /// message rather than an error.
    pub fn next_seq(
        conn: &Connection,
        conversation_id: &ConversationId,
    ) -> Result<MsgSeq, StoreError> {
        conn.query_row(
            "UPDATE conversations SET last_msg_seq = last_msg_seq + 1
             WHERE conversation_id = ?1
             RETURNING last_msg_seq",
            [conversation_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|seq| MsgSeq::new(as_u64(seq)))
        .ok_or_else(|| StoreError::UnknownConversation(conversation_id.short()))
    }

    /// Raises `peer_acked_seq` to `msg_seq` — §11's last-acked tracking.
    ///
    /// `max`, never a plain assignment: an ACK for an older message can arrive
    /// after a newer one, and going backwards would ask the peer to resend
    /// what it has already confirmed.
    pub fn note_acked(
        conn: &Connection,
        conversation_id: &ConversationId,
        msg_seq: MsgSeq,
    ) -> Result<(), StoreError> {
        conn.execute(
            "UPDATE conversations SET peer_acked_seq = max(peer_acked_seq, ?2)
             WHERE conversation_id = ?1",
            params![conversation_id.as_bytes().as_slice(), as_i64(msg_seq.get())],
        )?;
        Ok(())
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

    /// Advances the status of a message **we** sent — §11's `SENT ──▶
    /// DELIVERED ──▶ READ`. Returns its `msg_seq`, or `None` if there was no
    /// such row.
    ///
    /// `sender_id` is part of the statement rather than checked afterwards: an
    /// ACK arrives from the peer, and without it a peer could move the status
    /// of its *own* messages, which is a claim it does not get to make.
    pub fn set_status(
        conn: &Connection,
        message_id: &MessageId,
        sender_id: &UserId,
        status: DeliveryStatus,
    ) -> Result<Option<MsgSeq>, StoreError> {
        Ok(conn
            .query_row(
                "UPDATE messages SET status = ?3
                 WHERE message_id = ?1 AND sender_id = ?2
                 RETURNING msg_seq",
                params![
                    message_id.as_bytes().as_slice(),
                    sender_id.as_bytes().as_slice(),
                    status_to_i64(status),
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|seq| MsgSeq::new(as_u64(seq))))
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

    /// The highest `msg_seq` this store holds from `sender_id` — §10's
    /// `have_through`, and zero for a conversation with nothing from them.
    ///
    /// Per sender, because each side numbers its own messages from its own
    /// counter: one conversation holds two independent sequences, and the
    /// highest of both together would ask the peer for nothing.
    pub fn have_through(
        conn: &Connection,
        conversation_id: &ConversationId,
        sender_id: &UserId,
    ) -> Result<MsgSeq, StoreError> {
        Ok(conn
            .query_row(
                "SELECT max(msg_seq) FROM messages
                 WHERE conversation_id = ?1 AND sender_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    sender_id.as_bytes().as_slice()
                ],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
            .map(|seq| MsgSeq::new(as_u64(seq)))
            .unwrap_or(MsgSeq::ZERO))
    }

    /// What §10 retransmits: our own messages above the peer's `have_through`,
    /// oldest first, so the peer receives them in the order they were written.
    ///
    /// `limit` bounds it — a peer that has been away for a month asks for
    /// everything it missed, and one reconnection is not the place to write a
    /// month of history to a socket.
    pub fn after(
        conn: &Connection,
        conversation_id: &ConversationId,
        sender_id: &UserId,
        after: MsgSeq,
        limit: usize,
    ) -> Result<Vec<Message>, StoreError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM messages
             WHERE conversation_id = ?1 AND sender_id = ?2 AND msg_seq > ?3
             ORDER BY msg_seq ASC, message_id ASC LIMIT ?4"
        );
        collect(
            conn,
            &sql,
            params![
                conversation_id.as_bytes().as_slice(),
                sender_id.as_bytes().as_slice(),
                as_i64(after.get()),
                as_i64(limit as u64)
            ],
        )
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

// ---------------------------------------------------------------------------
// Pending connection requests
// ---------------------------------------------------------------------------

/// `architecture.md` §8: the public node's queue, and the only state it keeps.
///
/// Everything above `received_at` is a claim that arrived over an
/// unauthenticated connection. A row here is emphatically not a [`Peer`]: the
/// handshake in §6 is what turns a claimed identity into a known one, and until
/// the user has compared the fingerprint (F-06) the display name is decoration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequest {
    pub from_user_id: UserId,
    pub from_identity_pk: [u8; 32],
    /// Advisory only and attacker-controlled — agent.md §7.
    pub display_name: String,
    /// The caller's clock, in seconds. Unverified, and possibly a lie.
    pub created_at: u64,
    /// Ours, in seconds. This is the one that orders the queue.
    pub received_at: u64,
    pub state: RequestState,
}

/// How many requests may be waiting for the user at once — F-07.
///
/// The public node is reachable by anyone who has the address, so the queue is
/// the obvious thing to fill up. Sixty-four is far more than a person will work
/// through in a sitting and small enough that a full queue costs nothing;
/// `p2pchat_net::public::Limits` is what stops a caller reaching it quickly.
pub const MAX_PENDING: usize = 64;

pub mod requests {
    use super::*;

    /// §8: `0 pending 1 accepted 2 rejected`. [`RequestState::Unknown`] is not
    /// a stored state — it is the answer for a row that is not there — so it
    /// has no number and cannot be written.
    fn state_from_i64(value: i64) -> FromSqlResult<RequestState> {
        Ok(match value {
            0 => RequestState::Pending,
            1 => RequestState::Accepted,
            2 => RequestState::Rejected,
            other => return Err(FromSqlError::OutOfRange(other)),
        })
    }

    /// Records a request, unless the queue is full or the caller already has a
    /// row, and answers with the state the caller should be told.
    ///
    /// The cap is enforced *inside* the insert, so a burst of concurrent
    /// requests cannot each see room and then all take it. [`RequestState::
    /// Rejected`] covers both "you were refused" and "there was no room": the
    /// caller is not owed the difference, and telling them would say how full
    /// the queue is.
    pub fn enqueue(
        conn: &mut Connection,
        request: &PendingRequest,
        cap: usize,
    ) -> Result<RequestState, StoreError> {
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO pending_requests
                 (from_user_id, from_identity_pk, display_name,
                  created_at, received_at, state)
             SELECT ?1, ?2, ?3, ?4, ?5, 0
             WHERE (SELECT count(*) FROM pending_requests WHERE state = 0) < ?6",
            params![
                request.from_user_id.as_bytes().as_slice(),
                request.from_identity_pk.as_slice(),
                request.display_name,
                as_i64(request.created_at),
                as_i64(request.received_at),
                as_i64(cap as u64),
            ],
        )?;

        // Whatever is there now is the truth, whether this call put it there,
        // an earlier one did, or the cap refused it.
        let state = state(&tx, &request.from_user_id)?;
        tx.commit()?;

        Ok(match state {
            RequestState::Unknown => RequestState::Rejected,
            stored => stored,
        })
    }

    /// The caller's answer to `CONNECTION_STATUS`.
    ///
    /// [`RequestState::Unknown`] for a request that was never made — and for
    /// one the user has since cleared, which is the same answer on purpose.
    pub fn state(conn: &Connection, from: &UserId) -> Result<RequestState, StoreError> {
        Ok(conn
            .query_row(
                "SELECT state FROM pending_requests WHERE from_user_id = ?1",
                [from.as_bytes().as_slice()],
                |row| state_from_i64(row.get(0)?).map_err(Into::into),
            )
            .optional()?
            .unwrap_or(RequestState::Unknown))
    }

    /// The user's decision — F-06. `true` if there was a pending request to
    /// decide; `false` if it had gone, or had already been decided.
    ///
    /// Two effects, in one transaction so a crash cannot separate them: the
    /// queue row is closed, and the peer's acceptance (§10) is recorded. The
    /// second happens either way, because the decision is about the *peer* and
    /// not about the row — a user accepting someone whose invite they pasted
    /// has no queued request to resolve, and one who changes their mind about a
    /// request they already rejected is still entitled to say so. The queue row
    /// stays final; it is history, and `peers.accepted` is the live policy.
    pub fn resolve(
        conn: &mut Connection,
        from: &UserId,
        accepted: bool,
    ) -> Result<bool, StoreError> {
        let tx = conn.transaction()?;
        let affected = tx.execute(
            "UPDATE pending_requests SET state = ?2
             WHERE from_user_id = ?1 AND state = 0",
            params![from.as_bytes().as_slice(), if accepted { 1 } else { 2 }],
        )?;
        peers::set_accepted(&tx, from, accepted)?;
        tx.commit()?;
        Ok(affected == 1)
    }

    /// Everything still waiting, oldest first, which is the order F-07's badge
    /// counts and the TUI will list.
    pub fn pending(conn: &Connection) -> Result<Vec<PendingRequest>, StoreError> {
        let mut statement = conn.prepare(
            "SELECT from_user_id, from_identity_pk, display_name,
                    created_at, received_at, state
             FROM pending_requests WHERE state = 0
             ORDER BY received_at ASC, from_user_id ASC",
        )?;
        let rows = statement.query_map([], row_to_request)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn row_to_request(row: &Row<'_>) -> rusqlite::Result<PendingRequest> {
        Ok(PendingRequest {
            from_user_id: UserId::from_bytes(row.get::<_, Blob<32>>(0)?.0),
            from_identity_pk: row.get::<_, Blob<32>>(1)?.0,
            display_name: row.get(2)?,
            created_at: as_u64(row.get(3)?),
            received_at: as_u64(row.get(4)?),
            state: state_from_i64(row.get(5)?)?,
        })
    }
}

/// The requester's own half of §10's flow — M9d.
///
/// One row per `CONNECTION_REQUEST` sent and not yet answered, so that status
/// polling resumes after a restart. The address is the *public* node's, which
/// is where both the request and its status queries go.
pub mod outbound {
    use super::*;

    /// Idempotent: re-sending a request to the same peer keeps the first row,
    /// because `created_at` is when *we* first asked and the poller's backoff
    /// has no reason to restart.
    pub fn add(
        conn: &Connection,
        to: &UserId,
        addr: SocketAddr,
        created_at: u64,
    ) -> Result<(), StoreError> {
        conn.execute(
            "INSERT OR IGNORE INTO outbound_requests (to_user_id, addr, created_at)
             VALUES (?1, ?2, ?3)",
            params![
                to.as_bytes().as_slice(),
                addr.to_string(),
                as_i64(created_at)
            ],
        )?;
        Ok(())
    }

    /// Everything still to poll, oldest first.
    pub fn list(conn: &Connection) -> Result<Vec<(UserId, SocketAddr)>, StoreError> {
        let mut statement = conn.prepare(
            "SELECT to_user_id, addr FROM outbound_requests
             ORDER BY created_at ASC, to_user_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let addr = row
                .get::<_, String>(1)?
                .parse::<SocketAddr>()
                .map_err(|e| FromSqlError::Other(Box::new(e)))?;
            Ok((UserId::from_bytes(row.get::<_, Blob<32>>(0)?.0), addr))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Called once the request is answered, either way.
    pub fn remove(conn: &Connection, to: &UserId) -> Result<(), StoreError> {
        conn.execute(
            "DELETE FROM outbound_requests WHERE to_user_id = ?1",
            [to.as_bytes().as_slice()],
        )?;
        Ok(())
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
