//! The conversation stream — `architecture.md` §7 and §11.
//!
//! One session is two tasks over the stream the handshake ran on: a writer that
//! owns everything going out, and a reader that applies §7's receiver rules to
//! everything coming in.
//!
//! **Everything outbound goes through one channel.** Text the user typed and
//! ACKs the reader owes both arrive as [`Outgoing`], so sealing and writing
//! happen in one place and therefore in one order. Two producers sealing
//! independently would advance the send counter in one order and reach the
//! socket in another, and the peer's very next frame would fail its tag.
//!
//! Two orderings here are load-bearing and easy to write backwards:
//!
//! - **The ACK is emitted after the store commit**, never on receipt (§11,
//!   F-13, F-16). A crash between the two must not have reported as delivered
//!   a message that was never stored.
//! - **`SENT` is set on write to the socket**, not when the send is enqueued.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use p2pchat_core::wire::{
    to_bytes, Ack, DeliveryStatus, MessageFrame, MessageHeader, MsgType, Resync, PROTOCOL_VERSION,
};
use p2pchat_core::{decode, ConversationId, MessageId, MsgSeq, UserId};
use p2pchat_crypto::session::SessionCipher;
use p2pchat_net::{recv_frame, send_frame, NetError};
use p2pchat_store::{Message, Store};
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::sync::{mpsc, Mutex};

use crate::Event;

/// Close code for a session the receiver rules ended. One code, as in the
/// handshake: which rule failed is not the peer's business.
pub const SESSION_ERROR_CODE: u32 = 2;
pub const SESSION_ERROR_REASON: &[u8] = b"session closed";

/// Depth of the outgoing queue. Sends are cheap and the writer is never slow
/// for long; this is a burst allowance.
const OUTGOING: usize = 64;

/// How many messages one resync may retransmit — `architecture.md` §10.
///
/// ponytail: a flat cap, and the peer asks again on the next reconnection if
/// it is not enough. A peer that has been away long enough to be more than
/// this behind is not going to be caught up by one burst down one stream, and
/// the alternative — paging the backlog out over the session — is M11 work
/// that nothing has asked for.
const RESYNC_MAX: usize = 1_000;

/// Something to seal and write.
#[derive(Clone, Debug)]
pub enum Outgoing {
    /// F-13: a UTF-8 body, bounded by `wire`'s `MAX_BODY`.
    Text(String),
    /// §10: a stored message the peer has not got, sent again on a new
    /// session under the new key. Keeps its `message_id`, `msg_seq` and
    /// `created_at` — a retransmission is the same message, and a fresh
    /// `message_id` would defeat the receiver's dedupe (§7 rule 4) and store
    /// it twice.
    Resend(Box<Message>),
    /// §11: an ordinary encrypted frame, and not itself acknowledged.
    Ack {
        message_id: MessageId,
        status: DeliveryStatus,
    },
    /// End the session. §10's loser is closed this way rather than by handing
    /// the registry a `Connection` to hold: the channel is already the handle
    /// everyone outside the session task has.
    Close,
}

/// What both tasks share.
pub struct Conversation {
    /// Us. Receiver rule 3 is in [`SessionCipher::open`]; this is the other
    /// half of it, the ID our own rows are written under.
    pub me: UserId,
    pub peer: UserId,
    pub conversation_id: ConversationId,
    pub store: Arc<Store>,
    pub events: mpsc::Sender<Event>,
    /// One mutex per session, held across a single AEAD call.
    ///
    /// ponytail: the two directions have separate keys and counters and could
    /// hold separate locks — or none, if `SessionCipher` split. One lock is
    /// smaller and is never contended for longer than a ChaCha20-Poly1305 call
    /// on at most 4 KiB.
    pub cipher: Arc<Mutex<SessionCipher>>,
    pub connection: Connection,
    /// The lowest `msg_seq` this session has written itself — §10.
    ///
    /// A resync asks for everything above the peer's `have_through`, and that
    /// span overlaps whatever was typed after this session opened: the peer's
    /// RESYNC is answered out of the store, and the store already holds those
    /// rows. Sending them again is not wrong — §7 rule 4 deduplicates — but it
    /// is the same message twice down the same stream. `u64::MAX` until
    /// something is written, which is what makes the first resync send
    /// everything.
    pub written_from: AtomicU64,
    /// Test-only: how long to wait in the window between the store commit and
    /// the ACK. Zero in every build that is not being deliberately killed
    /// there — see [`commit_pause`].
    pub pause: Duration,
}

/// The window a crash is allowed to land in, stretched on demand.
///
/// M8's gate kills a process between the store commit and the ACK. That window
/// is one SQLite insert wide, which no test can aim at reliably, so this makes
/// it as wide as the test needs. Unset — every real run — it is zero.
pub fn commit_pause() -> Duration {
    match std::env::var("P2PCHAT_DEBUG_COMMIT_PAUSE_MS") {
        Ok(value) => Duration::from_millis(value.parse().unwrap_or(0)),
        Err(_) => Duration::ZERO,
    }
}

/// Starts the two tasks and hands back the channel the registry publishes.
pub fn spawn(
    conversation: Arc<Conversation>,
    send: SendStream,
    recv: RecvStream,
) -> mpsc::Sender<Outgoing> {
    let (tx, rx) = mpsc::channel(OUTGOING);

    tokio::spawn(writer(Arc::clone(&conversation), send, rx));
    tokio::spawn(reader(conversation, recv, tx.clone()));

    tx
}

/// The only place a frame is sealed and written.
async fn writer(conv: Arc<Conversation>, mut stream: SendStream, mut rx: mpsc::Receiver<Outgoing>) {
    // §10: the first frame on every session, before anything queued behind it.
    // Sent unconditionally and by both sides, because whichever side has
    // nothing to ask for still has something to tell: `have_through` is what
    // the *peer* retransmits from.
    if let Err(error) = resync(&conv, &mut stream).await {
        tracing::warn!(peer = %conv.peer, %error, "sending the resync failed");
        close(&conv, error.to_string());
        return;
    }

    while let Some(outgoing) = rx.recv().await {
        if matches!(outgoing, Outgoing::Close) {
            close(&conv, "superseded".to_owned());
            return;
        }
        if let Err(error) = write_one(&conv, &mut stream, outgoing).await {
            tracing::warn!(peer = %conv.peer, %error, "sending failed");
            close(&conv, error.to_string());
            return;
        }
    }
    // The channel closed: the session is gone from the registry.
    let _ = stream.finish();
}

/// `RESYNC { conversation_id, have_through }` — §10.
///
/// `have_through` is the highest `msg_seq` this store holds *from the peer*,
/// so the peer knows what to send again. Per sender: the two sides number
/// their own messages from their own counters.
async fn resync(conv: &Conversation, stream: &mut SendStream) -> Result<(), Error> {
    let have_through = conv
        .store
        .have_through(conv.conversation_id, conv.peer)
        .await?;
    let body = Resync {
        conversation_id: conv.conversation_id,
        have_through,
    };
    let header = header(
        conv,
        MsgType::Resync,
        MessageId::now_v7(),
        MsgSeq::ZERO,
        now_ms(),
    );
    let frame = conv.cipher.lock().await.seal(&header, &to_bytes(&body)?)?;
    send_frame(stream, &frame).await?;
    tracing::info!(peer = %conv.peer, have_through = have_through.get(), "resync sent");
    Ok(())
}

async fn write_one(
    conv: &Conversation,
    stream: &mut SendStream,
    outgoing: Outgoing,
) -> Result<(), Error> {
    match outgoing {
        Outgoing::Text(body) => {
            // The number is taken here rather than at the call site so that
            // `msg_seq` order and wire order are the same order by
            // construction.
            let msg_seq = conv.store.next_seq(conv.conversation_id).await?;
            // Before the insert, not after: a resync answered in between would
            // otherwise find the row and send it a second time.
            conv.written_from
                .fetch_min(msg_seq.get(), Ordering::Relaxed);
            let message_id = MessageId::now_v7();
            let created_at = now_ms();
            let header = header(conv, MsgType::Text, message_id, msg_seq, created_at);

            conv.store
                .insert_message(Message {
                    message_id,
                    conversation_id: conv.conversation_id,
                    sender_id: conv.me,
                    msg_seq,
                    body: body.clone().into_bytes(),
                    created_at,
                    received_at: None,
                    status: DeliveryStatus::Pending,
                })
                .await?;

            let frame = conv.cipher.lock().await.seal(&header, body.as_bytes())?;
            send_frame(stream, &frame).await?;

            // §11: on write to the socket, not on enqueue.
            conv.store
                .set_status(message_id, conv.me, DeliveryStatus::Sent)
                .await?;
            emit(
                conv,
                Event::Sent {
                    peer: conv.peer,
                    message_id,
                    msg_seq,
                },
            );
        }
        // §10, and M9g's queued rows with it: stored already, so there is no
        // insert and no new number — only the write, and the status the write
        // earns. Sealed by the same cipher as everything else on this session,
        // which is the *new* one: the old session's keys went with it.
        Outgoing::Resend(message) => {
            let header = header(
                conv,
                MsgType::Text,
                message.message_id,
                message.msg_seq,
                message.created_at,
            );
            let frame = conv.cipher.lock().await.seal(&header, &message.body)?;
            send_frame(stream, &frame).await?;

            // Only forward. A message the peer acknowledged before the session
            // dropped is `DELIVERED`, and retransmitting it — which happens
            // whenever the ACK was the frame that was lost — must not take it
            // back to `SENT`.
            if message.status == DeliveryStatus::Pending {
                conv.store
                    .set_status(message.message_id, conv.me, DeliveryStatus::Sent)
                    .await?;
            }
            emit(
                conv,
                Event::Sent {
                    peer: conv.peer,
                    message_id: message.message_id,
                    msg_seq: message.msg_seq,
                },
            );
        }
        Outgoing::Ack { message_id, status } => {
            let ack = Ack {
                conversation_id: conv.conversation_id,
                message_id,
                status,
            };
            // An ACK carries its own fresh `message_id` and sits at `msg_seq`
            // zero: it is never stored, so it needs no number in the
            // conversation, and reusing the acked message's identifiers would
            // put two frames' worth of meaning on one field. What it is about
            // is in the payload.
            let header = header(
                conv,
                MsgType::Ack,
                MessageId::now_v7(),
                MsgSeq::ZERO,
                now_ms(),
            );
            let frame = conv.cipher.lock().await.seal(&header, &to_bytes(&ack)?)?;
            send_frame(stream, &frame).await?;
        }
        // Taken by the writer loop, which has to stop rather than carry on.
        // Not `unreachable!`: agent.md §3 — nothing on a network path panics,
        // including on a case the code above makes impossible.
        Outgoing::Close => {}
    }
    Ok(())
}

/// §7's receiver rules, in order, for as long as the stream holds.
async fn reader(conv: Arc<Conversation>, mut stream: RecvStream, outgoing: mpsc::Sender<Outgoing>) {
    loop {
        let frame: MessageFrame = match recv_frame(&mut stream).await {
            Ok(frame) => frame,
            Err(error) => {
                tracing::info!(peer = %conv.peer, %error, "conversation stream ended");
                break;
            }
        };

        if let Err(error) = accept(&conv, frame, &outgoing).await {
            // §7 rule 2: a frame that does not verify ends the session. There
            // is no "drop it and carry on" — the next frame would decrypt
            // under a counter the peer never used anyway.
            tracing::warn!(peer = %conv.peer, %error, "receiver rule failed");
            close(&conv, error.to_string());
            break;
        }
    }

    emit(&conv, Event::Closed { peer: conv.peer });
}

async fn accept(
    conv: &Conversation,
    frame: MessageFrame,
    outgoing: &mpsc::Sender<Outgoing>,
) -> Result<(), Error> {
    // Rules 1 to 3: counter, tag, and `sender_id` against the authenticated
    // peer. All three are `SessionCipher::open`, which is where the key is.
    let plaintext = conv.cipher.lock().await.open(&frame)?;
    let header = frame.header;

    // A session carries exactly one conversation, derived from the two user
    // IDs. A frame naming another one is a peer writing into a history it is
    // not part of — in V0.1 that is someone else's conversation, and the rows
    // would carry this peer's authenticated `sender_id` inside it.
    if header.conversation_id != conv.conversation_id {
        return Err(Error::WrongConversation);
    }

    match header.msg_type {
        MsgType::Text => {
            let stored = conv
                .store
                .insert_message(Message {
                    message_id: header.message_id,
                    conversation_id: conv.conversation_id,
                    sender_id: header.sender_id,
                    msg_seq: header.msg_seq,
                    body: plaintext.clone(),
                    created_at: header.created_at,
                    received_at: Some(now_ms()),
                    // From this side the message has arrived and is on disk.
                    status: DeliveryStatus::Delivered,
                })
                .await?;

            // The whole of §11's ordering: the commit has happened, and only
            // now is there anything to acknowledge. The pause is zero unless a
            // test is about to kill this process in exactly this window.
            if !conv.pause.is_zero() {
                tokio::time::sleep(conv.pause).await;
            }

            // Rule 4: a `message_id` already in the store gets the ACK again
            // and nothing else — no second row, and no second event.
            let _ = outgoing
                .send(Outgoing::Ack {
                    message_id: header.message_id,
                    status: DeliveryStatus::Delivered,
                })
                .await;

            // The whole of §11's ordering: the commit has happened, and only
            // now is there anything to acknowledge. The pause is zero unless a
            // test is about to kill this process in exactly this window.
            if !conv.pause.is_zero() {
                tokio::time::sleep(conv.pause).await;
            }

            // Rule 4: a `message_id` already in the store gets the ACK again
            // and nothing else — no second row, and no second event.

            if stored {
                emit(
                    conv,
                    Event::Received {
                        peer: conv.peer,
                        message_id: header.message_id,
                        msg_seq: header.msg_seq,
                        body: String::from_utf8_lossy(&plaintext).into_owned(),
                    },
                );
            } else {
                tracing::debug!(peer = %conv.peer, "duplicate message re-acked");
            }
        }
        MsgType::Ack => {
            // `decode` runs `Ack::validate`, which refuses any status the peer
            // does not get to assert — `SENT` is local to the sender.
            let ack: Ack = decode(&plaintext)?;
            if ack.conversation_id != conv.conversation_id {
                return Err(Error::WrongConversation);
            }

            // `conv.me` as the sender: an ACK may only advance a message we
            // sent. The peer acknowledging its own message is not a claim it
            // owns.
            if conv
                .store
                .note_ack(conv.conversation_id, ack.message_id, conv.me, ack.status)
                .await?
            {
                emit(
                    conv,
                    Event::Delivered {
                        peer: conv.peer,
                        message_id: ack.message_id,
                        status: ack.status,
                    },
                );
            }
        }
        // §10: what the peer holds from us. Everything above it goes again,
        // in `msg_seq` order, through the same channel as everything else —
        // so a resend cannot overtake a message the user is typing now, and
        // both are sealed in one place and therefore in one order.
        MsgType::Resync => {
            let resync: Resync = decode(&plaintext)?;
            if resync.conversation_id != conv.conversation_id {
                return Err(Error::WrongConversation);
            }

            // From the beginning of the conversation and not from
            // `have_through`, because the rows at or below it have something
            // owed to them too — see below.
            //
            // ponytail: reads the last `RESYNC_MAX` rows once per session to
            // find the few that matter. A conversation longer than that is
            // caught up over two sessions instead of one.
            let backlog = conv
                .store
                .after(conv.conversation_id, conv.me, MsgSeq::ZERO, RESYNC_MAX)
                .await?;
            // Read after the query: anything written since is numbered above
            // everything the query returned.
            let written_from = conv.written_from.load(Ordering::Relaxed);
            let (acknowledged, backlog): (Vec<_>, Vec<_>) = backlog
                .into_iter()
                .filter(|message| message.msg_seq.get() < written_from)
                .partition(|message| message.msg_seq.get() <= resync.have_through.get());

            // §11: `have_through` is the peer saying it has these stored, which
            // is what `DELIVERED` means. Their ACKs went down with the session
            // that carried them — the peer will never send them again, because
            // from its side those messages arrived — so this is the only thing
            // that will ever move them off `SENT`.
            for message in acknowledged {
                if conv
                    .store
                    .note_ack(
                        conv.conversation_id,
                        message.message_id,
                        conv.me,
                        DeliveryStatus::Delivered,
                    )
                    .await?
                {
                    emit(
                        conv,
                        Event::Delivered {
                            peer: conv.peer,
                            message_id: message.message_id,
                            status: DeliveryStatus::Delivered,
                        },
                    );
                }
            }

            tracing::info!(
                peer = %conv.peer,
                have_through = resync.have_through.get(),
                count = backlog.len(),
                "resync received; retransmitting what the peer is missing",
            );

            for message in backlog {
                // The session ending mid-resync is not an error here: the
                // writer is gone, the next session asks again, and the store
                // still holds every row.
                if outgoing
                    .send(Outgoing::Resend(Box::new(message)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn header(
    conv: &Conversation,
    msg_type: MsgType,
    message_id: MessageId,
    msg_seq: MsgSeq,
    created_at: u64,
) -> MessageHeader {
    MessageHeader {
        version: PROTOCOL_VERSION,
        msg_type,
        message_id,
        conversation_id: conv.conversation_id,
        sender_id: conv.me,
        msg_seq,
        created_at,
    }
}

fn close(conv: &Conversation, reason: String) {
    tracing::info!(peer = %conv.peer, reason, "closing session");
    conv.connection
        .close(VarInt::from_u32(SESSION_ERROR_CODE), SESSION_ERROR_REASON);
}

/// Core -> UI, and never a wait.
///
/// `architecture.md` §2: the core must not block on whoever is reading. A
/// stalled TUI holding this channel full would otherwise stop the session task
/// mid-receive, and with it the ACK the peer is waiting for. An event is a
/// notification — the store already holds everything it describes — so a
/// dropped one costs a redraw that the next event asks for anyway.
fn emit(conv: &Conversation, event: Event) {
    if conv.events.try_send(event).is_err() {
        tracing::debug!(peer = %conv.peer, "event dropped: the reader is behind");
    }
}

/// Milliseconds since the epoch — §8's unit for `messages.created_at`.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Everything that can end a session, in one place so that the writer and the
/// reader close the connection the same way.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("frame names a conversation this session does not carry")]
    WrongConversation,

    #[error(transparent)]
    Net(#[from] NetError),

    #[error(transparent)]
    Crypto(#[from] p2pchat_crypto::CryptoError),

    #[error(transparent)]
    Store(#[from] p2pchat_store::StoreError),

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}
