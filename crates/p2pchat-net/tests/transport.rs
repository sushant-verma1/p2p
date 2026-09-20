//! M3 gate.
//!
//! 1. two processes on localhost connect and exchange framed messages;
//! 2. both sides independently derive the same 32-byte channel binding;
//! 3. two separate connections derive *different* channel bindings — without
//!    this, a constant satisfies (2) and M4's relay defence is worthless while
//!    appearing to work;
//! 4. a client offering the wrong ALPN is rejected;
//! 5. a frame arriving split across several reads decodes correctly, because
//!    QUIC does not preserve message boundaries within a stream;
//! 6. M5: a real handshake over that transport, then a hundred encrypted
//!    frames each way, with the two sides' counters staying in step and no
//!    counter byte on the wire.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use p2pchat_core::frame::encode;
use p2pchat_core::id::{ConversationId, MessageId, MsgSeq};
use p2pchat_core::wire::{
    self, ConnectionStatus, MessageFrame, MessageHeader, MsgType, PROTOCOL_VERSION,
};
use p2pchat_core::UserId;
use p2pchat_crypto::{Identity, SessionCipher};
use p2pchat_net::{
    channel_binding, client_endpoint, connect, recv_frame, send_frame, NodeKind,
    CHANNEL_BINDING_LEN,
};
use quinn::{Connection, Endpoint};
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::process::{ChildStdout, Command};

/// Every wait in this file is bounded. A transport test that hangs tells you
/// nothing and blocks CI for the full timeout.
const PATIENCE: Duration = Duration::from_secs(20);

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn server(kind: NodeKind) -> Endpoint {
    p2pchat_net::server_endpoint(loopback(), kind).unwrap()
}

/// Sender is the peer's ID in a real exchange; here it is just a recognisable
/// 32-byte value, chosen per message so an echo cannot be faked by silence.
fn message(tag: u8) -> ConnectionStatus {
    ConnectionStatus {
        version: PROTOCOL_VERSION,
        from_user_id: UserId::from_bytes([tag; 32]),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The child's next line starting with `prefix`, with the prefix removed.
async fn next_line(lines: &mut Lines<BufReader<ChildStdout>>, prefix: &str) -> String {
    tokio::time::timeout(PATIENCE, async {
        while let Some(line) = lines.next_line().await.unwrap() {
            if let Some(rest) = line.trim().strip_prefix(prefix) {
                return rest.to_owned();
            }
        }
        panic!("the child exited before printing a {prefix:?} line");
    })
    .await
    .unwrap_or_else(|_| panic!("the child never printed a {prefix:?} line"))
}

async fn accept(endpoint: &Endpoint) -> Connection {
    endpoint.accept().await.unwrap().await.unwrap()
}

/// Like [`accept`], but hands back the failure instead of unwrapping it.
async fn accept_result(endpoint: &Endpoint) -> Result<Connection, quinn::ConnectionError> {
    endpoint.accept().await.unwrap().await
}

/// Reads one frame from a stream and writes it straight back.
async fn echo(connection: &Connection, frames: usize) {
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    for _ in 0..frames {
        let received: ConnectionStatus = recv_frame(&mut recv).await.unwrap();
        send_frame(&mut send, &received).await.unwrap();
    }
    send.finish().unwrap();
}

// ---------------------------------------------------------------------------
// Gates 1 and 2 — two real processes
// ---------------------------------------------------------------------------

/// The second process. Ignored, so it only runs when the test below invokes
/// this same binary by name.
///
/// It prints two lines and nothing else that starts with those prefixes: the
/// port it ended up on, and its own channel binding. The parent compares that
/// binding with the one it derived from its end of the same connection — which
/// is the point of gate 2, and it is worth the process boundary: two values
/// derived in one address space could agree by sharing a variable.
#[tokio::test]
#[ignore = "started as a child process by two_processes_exchange_framed_messages"]
async fn responder_child_process() {
    let endpoint = server(NodeKind::Private);
    println!("PORT {}", endpoint.local_addr().unwrap().port());

    let connection = accept(&endpoint).await;
    println!("CB {}", hex(&channel_binding(&connection).unwrap()));

    echo(&connection, 3).await;
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn two_processes_exchange_framed_messages() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "responder_child_process",
            "--ignored",
            "--nocapture",
        ])
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    let port: u16 = next_line(&mut lines, "PORT ").await.parse().unwrap();
    let endpoint = client_endpoint(NodeKind::Private).unwrap();
    let connection = tokio::time::timeout(
        PATIENCE,
        connect(&endpoint, SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
    )
    .await
    .unwrap()
    .unwrap();

    // Gate 1: framed messages, over a real stream, between real processes.
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    for tag in [1u8, 2, 3] {
        send_frame(&mut send, &message(tag)).await.unwrap();
        let back: ConnectionStatus = tokio::time::timeout(PATIENCE, recv_frame(&mut recv))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(back, message(tag));
    }

    // Gate 2: the two ends derived the same 32 bytes without exchanging them.
    let theirs = next_line(&mut lines, "CB ").await;
    let ours = hex(&channel_binding(&connection).unwrap());
    assert_eq!(ours.len(), CHANNEL_BINDING_LEN * 2);
    assert_eq!(ours, theirs, "the two ends disagree on the channel binding");
    assert_ne!(ours, hex(&[0u8; CHANNEL_BINDING_LEN]));

    child.kill().await.unwrap();
}

// ---------------------------------------------------------------------------
// Gate 3 — a constant would pass gate 2
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_connections_derive_different_channel_bindings() {
    let endpoint = server(NodeKind::Private);
    let addr = endpoint.local_addr().unwrap();
    let client = client_endpoint(NodeKind::Private).unwrap();

    let mut bindings = Vec::new();
    for _ in 0..2 {
        let (accepted, dialled) = tokio::join!(accept(&endpoint), connect(&client, addr));
        let dialled = dialled.unwrap();
        let server_side = channel_binding(&accepted).unwrap();
        let client_side = channel_binding(&dialled).unwrap();
        assert_eq!(server_side, client_side, "ends of one connection disagree");
        bindings.push(server_side);
    }

    assert_ne!(
        bindings[0], bindings[1],
        "two connections produced the same channel binding, so it is a \
         constant and the relay defence in M4 would protect nothing"
    );
}

// ---------------------------------------------------------------------------
// Gate 4 — ALPN
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_offering_the_wrong_alpn_is_rejected() {
    let endpoint = server(NodeKind::Private);
    let addr = endpoint.local_addr().unwrap();

    // The server is alive and willing: a matching ALPN gets in.
    let right = client_endpoint(NodeKind::Private).unwrap();
    let (accepted, dialled) = tokio::join!(accept(&endpoint), connect(&right, addr));
    assert!(dialled.is_ok());
    drop(accepted);

    // The public node's ALPN on the private node's port does not.
    let wrong = client_endpoint(NodeKind::Public).unwrap();
    let outcome = tokio::time::timeout(PATIENCE, async {
        let (server_side, client_side) =
            tokio::join!(accept_result(&endpoint), connect(&wrong, addr));
        assert!(
            server_side.is_err(),
            "the private node completed the handshake"
        );
        client_side
    })
    .await
    .expect("the wrong ALPN neither connected nor failed");

    let error = outcome.expect_err("a client offering p2pchat-pub/1 reached the private node");
    // TLS alert 120 is `no_application_protocol`. Asserting on the reason
    // matters: a rejection for any other cause would pass a bare `is_err`
    // while the ALPN separation did nothing.
    assert!(
        error.to_string().contains("error 120"),
        "rejected, but not over the ALPN: {error}"
    );
}

// ---------------------------------------------------------------------------
// Gate 5 — QUIC delivers a stream, not messages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_frame_split_across_several_reads_decodes() {
    let endpoint = server(NodeKind::Private);
    let addr = endpoint.local_addr().unwrap();
    let client = client_endpoint(NodeKind::Private).unwrap();

    let (accepted, dialled) = tokio::join!(accept(&endpoint), connect(&client, addr));
    let dialled = dialled.unwrap();

    let reader = tokio::spawn(async move {
        let (_send, mut recv) = accepted.accept_bi().await.unwrap();
        let first: ConnectionStatus = recv_frame(&mut recv).await.unwrap();
        let second: ConnectionStatus = recv_frame(&mut recv).await.unwrap();
        (first, second)
    });

    let mut buf = Vec::new();
    encode(&message(9), &mut buf).unwrap();
    let whole = buf.len();
    // Two frames back to back, so the second one also proves the reader stops
    // at the right byte rather than swallowing whatever is in the buffer.
    encode(&message(8), &mut buf).unwrap();

    let (mut send, _recv) = dialled.open_bi().await.unwrap();
    // One byte, then two, then a chunk ending mid-way through the first
    // frame's body, then a chunk spanning the boundary between the two frames,
    // then whatever is left. The length prefix itself arrives in pieces.
    let mut offset = 0;
    for size in [1, 2, whole - 4, 5, buf.len()] {
        let end = (offset + size).min(buf.len());
        if end == offset {
            continue;
        }
        send.write_all(&buf[offset..end]).await.unwrap();
        offset = end;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(offset, buf.len());
    send.finish().unwrap();

    let (first, second) = tokio::time::timeout(PATIENCE, reader)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, message(9));
    assert_eq!(second, message(8));
}

// ---------------------------------------------------------------------------
// Gate 6 — handshake, then a hundred frames each way
// ---------------------------------------------------------------------------

/// How many frames each side sends.
const ROUNDS: u64 = 100;

fn message_header(sender: UserId, seq: u64) -> MessageHeader {
    MessageHeader {
        version: PROTOCOL_VERSION,
        msg_type: MsgType::Text,
        message_id: MessageId::now_v7(),
        conversation_id: ConversationId::from_bytes([5u8; 32]),
        sender_id: sender,
        msg_seq: MsgSeq::new(seq),
        created_at: 1_700_000_000,
    }
}

/// A frame's wire form is the header and the ciphertext, and nothing else.
///
/// The `postcard` length of the whole frame has to equal the header plus one
/// byte of length prefix plus the ciphertext — with a body this short that
/// prefix is a single byte — which leaves no room for a counter to hide in.
/// This is the structural half of "`frame_seq` is never transmitted"; the two
/// sides agreeing after a hundred rounds is the behavioural half.
fn assert_no_counter_on_the_wire(frame: &MessageFrame) {
    let whole = wire::to_bytes(frame).unwrap().len();
    let header = wire::to_bytes(&frame.header).unwrap().len();
    assert_eq!(
        whole,
        header + 1 + frame.ciphertext.len(),
        "a frame carries bytes that are neither its header nor its ciphertext"
    );
}

/// Talks and listens at the same time, a hundred of each.
///
/// Both sides run this, so each one is sending while the other is receiving
/// and neither can pass by staying quiet.
///
/// The connection is borrowed, not consumed: dropping a `Connection` closes it
/// at once and discards whatever is still in flight, which would lose the last
/// frame the other side is waiting on.
async fn exchange(
    connection: &Connection,
    identity: &Identity,
    mut cipher: SessionCipher,
    accept: bool,
) -> SessionCipher {
    let (mut send, mut recv) = if accept {
        connection.accept_bi().await.unwrap()
    } else {
        connection.open_bi().await.unwrap()
    };

    for seq in 0..ROUNDS {
        let body = format!("frame {seq}");
        let frame = cipher
            .seal(&message_header(identity.user_id(), seq), body.as_bytes())
            .unwrap();
        assert_no_counter_on_the_wire(&frame);
        send_frame(&mut send, &frame).await.unwrap();

        let received: MessageFrame = recv_frame(&mut recv).await.unwrap();
        let plaintext = cipher.open(&received).unwrap();
        assert_eq!(plaintext, body.as_bytes());
        assert_eq!(received.header.msg_seq, MsgSeq::new(seq));
    }

    send.finish().unwrap();
    cipher
}

#[tokio::test]
async fn a_hundred_frames_each_way_keep_the_counters_in_step() {
    let endpoint = server(NodeKind::Private);
    let addr = endpoint.local_addr().unwrap();
    let client = client_endpoint(NodeKind::Private).unwrap();
    let (identity_i, identity_r) = (Identity::generate(), Identity::generate());

    let (accepted, dialled) = tokio::join!(accept(&endpoint), connect(&client, addr));
    let dialled = dialled.unwrap();

    // Taken before the identity moves into the task: a signing key is not
    // `Clone`, deliberately.
    let expected_peer = identity_r.user_id();
    let responder = tokio::spawn(async move {
        let session = p2pchat_net::handshake::respond(&accepted, &identity_r)
            .await
            .unwrap();
        let cipher = SessionCipher::derive(session).unwrap();
        exchange(&accepted, &identity_r, cipher, true).await
    });

    let session = p2pchat_net::handshake::initiate(&dialled, &identity_i, Some(expected_peer))
        .await
        .unwrap();
    let cipher = SessionCipher::derive(session).unwrap();
    let initiator = exchange(&dialled, &identity_i, cipher, false).await;

    let responder = tokio::time::timeout(PATIENCE, responder)
        .await
        .unwrap()
        .unwrap();

    // In step: what each side sent is what the other received, on both
    // directions, without either counter ever being transmitted.
    assert_eq!(initiator.frames_sent(), ROUNDS);
    assert_eq!(initiator.frames_sent(), responder.frames_received());
    assert_eq!(responder.frames_sent(), ROUNDS);
    assert_eq!(responder.frames_sent(), initiator.frames_received());
}
