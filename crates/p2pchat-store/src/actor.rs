//! The store actor — `architecture.md` §2.
//!
//! One task owns the `rusqlite::Connection`; every caller holds a [`Store`] and
//! reaches it over a channel with a oneshot reply. SQLite calls block, so the
//! task lives on the blocking pool rather than on a runtime worker.

use std::net::SocketAddr;
use std::path::Path;

use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use p2pchat_core::wire::{DeliveryStatus, RequestState};
use p2pchat_core::{ConversationId, MessageId, MsgSeq, UserId};

use crate::{db, repo, Conversation, Cursor, Message, Peer, PendingRequest, StoreError};

/// One unit of work for the actor: a closure that gets the connection.
///
/// A request enum would write every call three times — the variant, the match
/// arm, and the method that builds it. The public API is still the typed
/// methods below; only this box crosses the channel.
type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// Depth before a caller waits. Requests are short and replies are awaited, so
/// this is a burst allowance, not a queue.
const CAPACITY: usize = 32;

pub struct Store {
    tx: mpsc::Sender<Job>,
    task: JoinHandle<()>,
}

impl Store {
    /// Opens the database at `path`, migrating it, and starts the actor.
    ///
    /// Opening happens on the actor's own thread, so the connection is never
    /// sent between threads — and an open that fails returns here rather than
    /// surfacing on the first query.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let (tx, mut rx) = mpsc::channel::<Job>(CAPACITY);
        let (ready_tx, ready_rx) = oneshot::channel();

        let task = tokio::task::spawn_blocking(move || {
            let mut conn = match db::open(&path) {
                Ok(conn) => {
                    let _ = ready_tx.send(Ok(()));
                    conn
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };

            // Ends when the last `Store` drops, which closes the connection.
            // `close` waits for exactly that.
            while let Some(job) = rx.blocking_recv() {
                job(&mut conn);
            }
        });

        match ready_rx.await {
            Ok(Ok(())) => Ok(Self { tx, task }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(StoreError::ActorStopped),
        }
    }

    /// Closes the database and waits for it to be closed.
    ///
    /// Dropping a `Store` does the same thing without waiting, which is fine
    /// for shutdown and not fine for anything that reopens the file straight
    /// afterwards.
    pub async fn close(self) -> Result<(), StoreError> {
        let Self { tx, task } = self;
        drop(tx);
        task.await.map_err(|_| StoreError::ActorStopped)
    }

    async fn call<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Box::new(move |conn| {
                let _ = reply_tx.send(f(conn));
            }))
            .await
            .map_err(|_| StoreError::ActorStopped)?;

        reply_rx.await.map_err(|_| StoreError::ActorStopped)?
    }

    pub async fn upsert_peer(&self, peer: Peer) -> Result<(), StoreError> {
        self.call(move |conn| repo::peers::upsert(conn, &peer))
            .await
    }

    pub async fn peer(&self, user_id: UserId) -> Result<Option<Peer>, StoreError> {
        self.call(move |conn| repo::peers::get(conn, &user_id))
            .await
    }

    /// `architecture.md` §10: may this peer have a session? Asked once per
    /// connection, after §6 has said who the peer actually is.
    pub async fn is_accepted(&self, user_id: UserId) -> Result<bool, StoreError> {
        self.call(move |conn| repo::peers::is_accepted(conn, &user_id))
            .await
    }

    /// Where §6 last completed a handshake with this peer — M10's reconnect.
    pub async fn set_peer_addr(&self, user_id: UserId, addr: SocketAddr) -> Result<(), StoreError> {
        self.call(move |conn| repo::peers::set_addr(conn, &user_id, addr))
            .await
    }

    /// Accepted peers with an address to dial — M10, §10.
    pub async fn reconnectable(&self) -> Result<Vec<(UserId, SocketAddr)>, StoreError> {
        self.call(|conn| repo::peers::reconnectable(conn)).await
    }

    pub async fn open_conversation(
        &self,
        conversation_id: ConversationId,
        peer_id: UserId,
        created_at: u64,
    ) -> Result<(), StoreError> {
        self.call(move |conn| {
            repo::conversations::open(conn, &conversation_id, &peer_id, created_at)
        })
        .await
    }

    pub async fn conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Option<Conversation>, StoreError> {
        self.call(move |conn| repo::conversations::get(conn, &conversation_id))
            .await
    }

    /// `true` if the message was stored, `false` if it was already there — F-15.
    pub async fn insert_message(&self, message: Message) -> Result<bool, StoreError> {
        self.call(move |conn| repo::messages::insert(conn, &message))
            .await
    }

    /// Reserves the next `msg_seq` for our side of a conversation.
    pub async fn next_seq(&self, conversation_id: ConversationId) -> Result<MsgSeq, StoreError> {
        self.call(move |conn| repo::conversations::next_seq(conn, &conversation_id))
            .await
    }

    /// `SENT`, on write to the socket — §11. `false` if the row is not ours.
    pub async fn set_status(
        &self,
        message_id: MessageId,
        sender_id: UserId,
        status: DeliveryStatus,
    ) -> Result<bool, StoreError> {
        self.call(move |conn| {
            Ok(repo::messages::set_status(conn, &message_id, &sender_id, status)?.is_some())
        })
        .await
    }

    /// An ACK from the peer: the status and the conversation's `peer_acked_seq`
    /// move together or not at all, so a crash between them cannot leave a
    /// message confirmed that the resync would then ask for again.
    pub async fn note_ack(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        sender_id: UserId,
        status: DeliveryStatus,
    ) -> Result<bool, StoreError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let seq = repo::messages::set_status(&tx, &message_id, &sender_id, status)?;
            if let Some(seq) = seq {
                repo::conversations::note_acked(&tx, &conversation_id, seq)?;
            }
            tx.commit()?;
            Ok(seq.is_some())
        })
        .await
    }

    /// Every peer we have seen — F-09.
    pub async fn peers(&self) -> Result<Vec<Peer>, StoreError> {
        self.call(|conn| repo::peers::list(conn)).await
    }

    /// F-09: fingerprint confirmed out of band. `false` if there is no such peer.
    pub async fn set_verified(&self, user_id: UserId, verified: bool) -> Result<bool, StoreError> {
        self.call(move |conn| repo::peers::set_verified(conn, &user_id, verified))
            .await
    }

    /// One page of history, newest first — F-22.
    pub async fn page(
        &self,
        conversation_id: ConversationId,
        before: Option<Cursor>,
    ) -> Result<Vec<Message>, StoreError> {
        self.call(move |conn| repo::messages::page(conn, &conversation_id, before))
            .await
    }

    /// §10's `have_through`: the highest `msg_seq` held from `sender_id`.
    pub async fn have_through(
        &self,
        conversation_id: ConversationId,
        sender_id: UserId,
    ) -> Result<MsgSeq, StoreError> {
        self.call(move |conn| repo::messages::have_through(conn, &conversation_id, &sender_id))
            .await
    }

    /// §10's retransmission set: `sender_id`'s messages above `after`, oldest
    /// first, at most `limit` of them.
    pub async fn after(
        &self,
        conversation_id: ConversationId,
        sender_id: UserId,
        after: MsgSeq,
        limit: usize,
    ) -> Result<Vec<Message>, StoreError> {
        self.call(move |conn| {
            repo::messages::after(conn, &conversation_id, &sender_id, after, limit)
        })
        .await
    }

    pub async fn message_count(&self, conversation_id: ConversationId) -> Result<i64, StoreError> {
        self.call(move |conn| repo::messages::count(conn, &conversation_id))
            .await
    }

    /// Queues an unauthenticated connection request, or refuses it because the
    /// queue is full — F-07. The answer is what the caller is told.
    pub async fn enqueue_request(
        &self,
        request: PendingRequest,
        cap: usize,
    ) -> Result<RequestState, StoreError> {
        self.call(move |conn| repo::requests::enqueue(conn, &request, cap))
            .await
    }

    pub async fn request_state(&self, from: UserId) -> Result<RequestState, StoreError> {
        self.call(move |conn| repo::requests::state(conn, &from))
            .await
    }

    /// The user's accept or reject — F-06, and §10's acceptance with it.
    /// `false` if nothing was pending; the acceptance is recorded regardless.
    pub async fn resolve_request(&self, from: UserId, accepted: bool) -> Result<bool, StoreError> {
        self.call(move |conn| repo::requests::resolve(conn, &from, accepted))
            .await
    }

    pub async fn pending_requests(&self) -> Result<Vec<PendingRequest>, StoreError> {
        self.call(|conn| repo::requests::pending(conn)).await
    }

    /// Remembers a request we sent, so that its status polling survives a
    /// restart — M9d, §10.
    pub async fn add_outbound_request(
        &self,
        to: UserId,
        addr: SocketAddr,
        created_at: u64,
    ) -> Result<(), StoreError> {
        self.call(move |conn| repo::outbound::add(conn, &to, addr, created_at))
            .await
    }

    /// The requests still to poll, oldest first.
    pub async fn outbound_requests(&self) -> Result<Vec<(UserId, SocketAddr)>, StoreError> {
        self.call(|conn| repo::outbound::list(conn)).await
    }

    pub async fn remove_outbound_request(&self, to: UserId) -> Result<(), StoreError> {
        self.call(move |conn| repo::outbound::remove(conn, &to))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An open that fails must fail here, not later and elsewhere.
    #[tokio::test]
    async fn a_database_that_cannot_be_opened_reports_at_open() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be: creating it fails, and so does
        // everything after.
        let path = dir.path().join("p2pchat.db");
        std::fs::create_dir(&path).unwrap();

        assert!(Store::open(&path).await.is_err());
    }

    /// `close` has to actually release the file, or gate 1's reopen is testing
    /// the connection it meant to drop.
    #[tokio::test]
    async fn closing_releases_the_file_for_a_fresh_open() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(db::db_path(dir.path())).await.unwrap();
        let id = ConversationId::from_bytes([1; 32]);

        store.close().await.unwrap();

        let reopened = Store::open(db::db_path(dir.path())).await.unwrap();
        assert_eq!(reopened.message_count(id).await.unwrap(), 0);
    }
}
