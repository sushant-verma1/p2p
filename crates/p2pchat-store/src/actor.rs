//! The store actor — `architecture.md` §2.
//!
//! One task owns the `rusqlite::Connection`; every caller holds a [`Store`] and
//! reaches it over a channel with a oneshot reply. SQLite calls block, so the
//! task lives on the blocking pool rather than on a runtime worker.

use std::path::Path;

use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use p2pchat_core::{ConversationId, UserId};

use crate::{db, repo, Conversation, Cursor, Message, Peer, StoreError};

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

    /// One page of history, newest first — F-22.
    pub async fn page(
        &self,
        conversation_id: ConversationId,
        before: Option<Cursor>,
    ) -> Result<Vec<Message>, StoreError> {
        self.call(move |conn| repo::messages::page(conn, &conversation_id, before))
            .await
    }

    pub async fn message_count(&self, conversation_id: ConversationId) -> Result<i64, StoreError> {
        self.call(move |conn| repo::messages::count(conn, &conversation_id))
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
