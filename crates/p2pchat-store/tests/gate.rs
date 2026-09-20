//! The M6 gate, plus the tests that catch each mandated mutation.
//!
//! No networking: the store is driven directly. Every test here runs against a
//! database on disk — an in-memory SQLite would pass the timing gate that a
//! real file has to earn.

use std::time::Instant;

use p2pchat_core::wire::DeliveryStatus;
use p2pchat_core::{ConversationId, MessageId, MsgSeq, UserId};
use p2pchat_store::{db_path, messages, open, Message, Peer, Store, PAGE_SIZE};
use tempfile::TempDir;

const ALICE: UserId = UserId::from_bytes([0xa1; 32]);
const BOB: UserId = UserId::from_bytes([0xb0; 32]);

/// Stands in for `p2pchat_crypto::derive_conversation_id`, which this crate may
/// not depend on (architecture.md §2 — `store` sees `core` and nothing else).
/// Gate 6, the order-independence of that derivation, is tested where it lives.
const CONVERSATION: ConversationId = ConversationId::from_bytes([0xc0; 32]);

fn peer(user_id: UserId) -> Peer {
    Peer {
        user_id,
        identity_pk: [7; 32],
        display_name: Some("advisory".into()),
        first_seen: 1_700_000_000,
        last_seen: None,
        verified: false,
    }
}

fn message(sender: UserId, seq: u64, body: &str) -> Message {
    Message {
        message_id: MessageId::now_v7(),
        conversation_id: CONVERSATION,
        sender_id: sender,
        msg_seq: MsgSeq::new(seq),
        body: body.as_bytes().to_vec(),
        created_at: 1_700_000_000 + seq,
        received_at: None,
        status: DeliveryStatus::Sent,
    }
}

/// A store on disk with Alice, Bob and one open conversation.
async fn fixture() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(db_path(dir.path())).await.unwrap();

    store.upsert_peer(peer(ALICE)).await.unwrap();
    store.upsert_peer(peer(BOB)).await.unwrap();
    store
        .open_conversation(CONVERSATION, BOB, 1_700_000_000)
        .await
        .unwrap();

    (dir, store)
}

// ---------------------------------------------------------------------------
// Gate 1 — messages survive a restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn messages_survive_a_restart() {
    let (dir, store) = fixture().await;

    store
        .insert_message(message(ALICE, 1, "written before the restart"))
        .await
        .unwrap();
    store.close().await.unwrap();

    let reopened = Store::open(db_path(dir.path())).await.unwrap();
    let page = reopened.page(CONVERSATION, None).await.unwrap();

    assert_eq!(page.len(), 1);
    assert_eq!(page[0].body, b"written before the restart");
    assert_eq!(page[0].sender_id, ALICE);
    assert_eq!(page[0].status, DeliveryStatus::Sent);

    // The peer and the conversation came back too, or the history has nothing
    // to hang from.
    assert_eq!(reopened.peer(BOB).await.unwrap().unwrap(), peer(BOB));
    assert!(reopened.conversation(CONVERSATION).await.unwrap().is_some());
}

// ---------------------------------------------------------------------------
// Gate 2 — a duplicate insert affects zero rows and is not an error
// ---------------------------------------------------------------------------

/// Catches both "drop the UNIQUE constraint" and "INSERT OR IGNORE becomes
/// plain INSERT".
///
/// The two inserts carry *different* `message_id`s on purpose. With the same
/// ID the primary key would absorb the duplicate on its own, the UNIQUE
/// constraint would never be consulted, and dropping it would break nothing
/// here.
#[tokio::test]
async fn a_resent_message_is_stored_once() {
    let (_dir, store) = fixture().await;

    let first = message(BOB, 4, "hello");
    let mut resent = message(BOB, 4, "hello");
    resent.message_id = MessageId::now_v7();
    assert_ne!(first.message_id, resent.message_id);

    assert!(store.insert_message(first).await.unwrap(), "first insert");
    assert!(
        !store.insert_message(resent).await.unwrap(),
        "the resend should have affected zero rows, and said so without erroring"
    );

    assert_eq!(store.message_count(CONVERSATION).await.unwrap(), 1);
}

/// The same triple from a *different sender* is a different message. A UNIQUE
/// constraint narrowed to `(conversation_id, msg_seq)` would swallow it.
#[tokio::test]
async fn the_two_sides_may_both_use_a_sequence_number() {
    let (_dir, store) = fixture().await;

    assert!(store
        .insert_message(message(ALICE, 9, "mine"))
        .await
        .unwrap());
    assert!(store
        .insert_message(message(BOB, 9, "theirs"))
        .await
        .unwrap());

    assert_eq!(store.message_count(CONVERSATION).await.unwrap(), 2);
}

// ---------------------------------------------------------------------------
// Gate 3 — 10,000 messages paginate in under 50 ms per page, on disk
// ---------------------------------------------------------------------------

/// The gate's number, split across the two senders so that the `msg_seq`
/// tie-break is exercised on every page rather than never.
const BULK: u64 = 10_000;

/// Seeds directly on a connection, in one transaction. Ten thousand round trips
/// through the actor would be measuring the channel, and the gate is about the
/// query.
fn seed(dir: &TempDir) {
    let mut conn = open(&db_path(dir.path())).unwrap();
    let tx = conn.transaction().unwrap();

    for sender in [ALICE, BOB] {
        p2pchat_store::peers::upsert(&tx, &peer(sender)).unwrap();
    }
    p2pchat_store::conversations::open(&tx, &CONVERSATION, &BOB, 1_700_000_000).unwrap();

    for seq in 1..=BULK / 2 {
        for sender in [ALICE, BOB] {
            messages::insert(&tx, &message(sender, seq, &format!("message {seq}"))).unwrap();
        }
    }

    tx.commit().unwrap();
}

#[tokio::test]
async fn ten_thousand_messages_paginate_under_fifty_milliseconds_per_page() {
    let dir = tempfile::tempdir().unwrap();
    seed(&dir);

    let store = Store::open(db_path(dir.path())).await.unwrap();
    assert_eq!(
        store.message_count(CONVERSATION).await.unwrap(),
        BULK as i64
    );

    let mut cursor = None;
    let mut pages = 0;
    let mut seen = 0;
    let mut slowest = std::time::Duration::ZERO;

    loop {
        let start = Instant::now();
        let page = store.page(CONVERSATION, cursor).await.unwrap();
        let elapsed = start.elapsed();
        slowest = slowest.max(elapsed);

        assert!(
            elapsed.as_millis() < 50,
            "page {pages} took {elapsed:?}, the gate is 50 ms"
        );

        if page.is_empty() {
            break;
        }
        seen += page.len();
        pages += 1;
        cursor = Some(page[page.len() - 1].cursor());
    }

    eprintln!("{pages} pages, {seen} rows, slowest page {slowest:?}");
    assert_eq!(seen, BULK as usize, "paging lost or repeated rows");
}

// ---------------------------------------------------------------------------
// Gate 4 — the database file is 0600 on Unix
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn the_database_file_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, store) = fixture().await;
    store
        .insert_message(message(ALICE, 1, "force a write"))
        .await
        .unwrap();

    let path = db_path(dir.path());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600, "database created with mode {mode:o}");

    // WAL and shared-memory files carry the same rows; SQLite gives them the
    // main file's mode, and this is where we would find out if it stopped.
    for suffix in ["-wal", "-shm"] {
        let sidecar = path.with_extension(format!("db{suffix}"));
        if let Ok(metadata) = std::fs::metadata(&sidecar) {
            let mode = metadata.permissions().mode() & 0o7777;
            assert_eq!(mode, 0o600, "{} has mode {mode:o}", sidecar.display());
        }
    }
}

#[cfg(not(unix))]
#[test]
fn permissions_are_not_enforced_here_and_say_so() {
    assert!(!p2pchat_store::PERMISSIONS_ENFORCED);
}

// ---------------------------------------------------------------------------
// Gate 5 — migrations run from empty and are idempotent
// ---------------------------------------------------------------------------

/// The unit tests in `schema` cover the version arithmetic; this covers the
/// same thing through the real file, where a re-run would meet real tables.
#[tokio::test]
async fn reopening_a_database_migrates_nothing() {
    let dir = tempfile::tempdir().unwrap();

    for _ in 0..3 {
        let store = Store::open(db_path(dir.path())).await.unwrap();
        store.close().await.unwrap();
    }

    let conn = open(&db_path(dir.path())).unwrap();
    let version: i64 = conn
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, p2pchat_store::SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Mutation: foreign_keys left OFF
// ---------------------------------------------------------------------------

/// A message whose conversation does not exist is a bug upstream, and the
/// column says `REFERENCES conversations(conversation_id)`. That reference
/// means nothing unless `foreign_keys` is on, and nothing else in the suite
/// notices when it is not.
#[tokio::test]
async fn a_message_in_an_unknown_conversation_is_refused() {
    let (_dir, store) = fixture().await;

    let mut orphan = message(ALICE, 1, "nowhere to live");
    orphan.conversation_id = ConversationId::from_bytes([0xff; 32]);

    let err = store.insert_message(orphan).await.unwrap_err();
    assert!(
        err.to_string().contains("FOREIGN KEY"),
        "expected a foreign key violation, got {err}"
    );
}

#[tokio::test]
async fn a_conversation_with_an_unknown_peer_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(db_path(dir.path())).await.unwrap();

    let err = store
        .open_conversation(CONVERSATION, BOB, 1_700_000_000)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("FOREIGN KEY"),
        "expected a foreign key violation, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Mutation: pagination LIMIT ignored
// ---------------------------------------------------------------------------

/// F-22 loads fifty rows at a time *rather than* the whole conversation, so the
/// size of a full page is the property, not an implementation detail.
#[tokio::test]
async fn a_full_page_is_exactly_fifty_rows_newest_first() {
    let (_dir, store) = fixture().await;

    for seq in 1..=(PAGE_SIZE as u64 + 10) {
        store
            .insert_message(message(ALICE, seq, &format!("message {seq}")))
            .await
            .unwrap();
    }

    let first = store.page(CONVERSATION, None).await.unwrap();
    assert_eq!(first.len(), PAGE_SIZE);
    assert_eq!(first[0].msg_seq, MsgSeq::new(PAGE_SIZE as u64 + 10));
    assert!(
        first.windows(2).all(|w| w[0].msg_seq > w[1].msg_seq),
        "a page must be newest-first"
    );

    let second = store
        .page(CONVERSATION, Some(first[first.len() - 1].cursor()))
        .await
        .unwrap();
    assert_eq!(second.len(), 10);
    assert_eq!(second[0].msg_seq, MsgSeq::new(10));

    // The pages abut: no row is dropped between them and none is repeated.
    assert_eq!(
        first[first.len() - 1].msg_seq,
        MsgSeq::new(second[0].msg_seq.get() + 1)
    );
}

/// An empty conversation pages to nothing rather than to an error.
#[tokio::test]
async fn an_empty_conversation_has_no_pages() {
    let (_dir, store) = fixture().await;
    assert!(store.page(CONVERSATION, None).await.unwrap().is_empty());
}
