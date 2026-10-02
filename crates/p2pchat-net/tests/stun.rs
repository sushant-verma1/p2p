//! M13, end to end over real loopback sockets: gate 4 (symmetric NAT never
//! reported punchable), gate 5 (a spoofed reply with the wrong transaction ID
//! is discarded), and gate 7 (one server answering is `Unknown`, not a
//! guess).
//!
//! Gate 4's disagreeing-servers test below is a permanent regression check,
//! not a substitute for a real symmetric NAT: two fake local servers handing
//! back two fixed, different ports are the right *shape*, but a real
//! symmetric NAT varies its mapping under live conditions in ways two
//! hardcoded answers cannot. It does not by itself close gate 4 — the mobile
//! network classification reported alongside M13's results is what actually
//! does, if that carrier turns out to be symmetric. If it does not, gate 4
//! stays partly simulated, and M13's report says so rather than claiming it
//! met.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use p2pchat_crypto::Identity;
use p2pchat_net::stun::{self, Datagrams, Mapping};
use p2pchat_net::{client_endpoint, connect, handshake, node_endpoint, server_endpoint, NodeKind};
use tokio::net::UdpSocket;

const PATIENCE: Duration = Duration::from_secs(5);

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;

/// A correct Binding Success Response carrying one XOR-MAPPED-ADDRESS,
/// encoded independently of `p2pchat_net`'s own encoder so this does not just
/// check the module against itself.
fn success_response(transaction_id: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(mapped) = mapped else {
        panic!("test helper handles IPv4 only");
    };
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let xor_port = mapped.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let mut xor_ip = mapped.ip().octets();
    for (byte, mask) in xor_ip.iter_mut().zip(cookie) {
        *byte ^= mask;
    }

    let mut value = vec![0u8, FAMILY_IPV4];
    value.extend_from_slice(&xor_port.to_be_bytes());
    value.extend_from_slice(&xor_ip);

    let mut msg = Vec::new();
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&(4 + value.len() as u16).to_be_bytes());
    msg.extend_from_slice(&cookie);
    msg.extend_from_slice(&transaction_id);
    msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
    msg.extend_from_slice(&value);
    msg
}

async fn loopback_socket() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap()
}

/// Spawns a fake STUN server that always answers with `mapped`, using
/// whatever transaction ID the client actually sent.
async fn fake_server(mapped: SocketAddr) -> SocketAddr {
    let socket = loopback_socket().await;
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let mut buf = [0u8; 1500];
            let Ok((_, from)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(id) = buf[8..20].try_into() else {
                break;
            };
            if socket
                .send_to(&success_response(id, mapped), from)
                .await
                .is_err()
            {
                break;
            }
        }
    });
    addr
}

/// Gate 5, end to end: a spoofed reply with the wrong transaction ID arrives
/// first. If `query` trusted it, the returned address would be the spoofed
/// one — exactly what "transaction ID check removed" would produce.
#[tokio::test]
async fn a_spoofed_reply_with_the_wrong_transaction_id_is_discarded() {
    let client = loopback_socket().await;
    let server = loopback_socket().await;
    let server_addr = server.local_addr().unwrap();

    let real = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 47100));
    let spoofed = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 6), 6666));

    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (_, from) = server.recv_from(&mut buf).await.unwrap();
        let real_id: [u8; 12] = buf[8..20].try_into().unwrap();

        let wrong_id = [0xAAu8; 12];
        server
            .send_to(&success_response(wrong_id, spoofed), from)
            .await
            .unwrap();
        server
            .send_to(&success_response(real_id, real), from)
            .await
            .unwrap();
    });

    let result = tokio::time::timeout(PATIENCE, stun::query(&client, server_addr, PATIENCE))
        .await
        .expect("query hung")
        .expect("query failed");
    assert_eq!(result, real, "the spoofed reply was accepted");
}

/// A regression check for gate 4's shape (see module doc for why this alone
/// does not close the gate): two servers disagreeing on the port is what a
/// symmetric NAT looks like from the outside, and must never be reported
/// punchable.
#[tokio::test]
async fn two_servers_disagreeing_on_the_port_is_never_reported_as_punchable() {
    let client = loopback_socket().await;
    let one = fake_server(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 40001))).await;
    let two = fake_server(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 40002))).await;

    let servers = [("one", one), ("two", two)];
    let report = stun::discover(&client, &servers, PATIENCE).await;

    assert_eq!(report.mapping, Mapping::AddressOrPortDependent);
    assert!(!report.mapping.punchable());
}

/// The same two servers agreeing is the punchable case, so the disagreement
/// above is known to be what makes the difference.
#[tokio::test]
async fn two_servers_agreeing_is_reported_as_punchable() {
    let client = loopback_socket().await;
    let same = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 40001));
    let one = fake_server(same).await;
    let two = fake_server(same).await;

    let servers = [("one", one), ("two", two)];
    let report = stun::discover(&client, &servers, PATIENCE).await;

    assert_eq!(report.mapping, Mapping::EndpointIndependent);
    assert!(report.mapping.punchable());
}

/// Gate 7: with only one server answering, the result is `Unknown`, not a
/// guess built from that one answer.
#[tokio::test]
async fn one_server_is_unknown_not_a_guess() {
    let client = loopback_socket().await;
    let one = fake_server(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 40001))).await;

    let servers = [("one", one)];
    let report = stun::discover(&client, &servers, PATIENCE).await;

    assert_eq!(report.mapping, Mapping::Unknown);
    assert!(!report.mapping.punchable());
}

/// A server that never answers is skipped, not fatal: the two that do still
/// produce a classification, and the failed one is visible in the report.
#[tokio::test]
async fn an_unreachable_server_is_skipped_not_fatal() {
    let client = loopback_socket().await;
    let same = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 40001));
    let one = fake_server(same).await;
    let two = fake_server(same).await;
    // Nothing is listening on this loopback port.
    let dead = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));

    let servers = [("one", one), ("dead", dead), ("two", two)];
    let report = stun::discover(&client, &servers, Duration::from_millis(200)).await;

    assert!(report.probes[1].result.is_err());
    assert_eq!(report.mapping, Mapping::EndpointIndependent);
}

// ---------------------------------------------------------------------------
// M13a: STUN on the QUIC endpoint's own socket
// ---------------------------------------------------------------------------

/// Long enough to be sure nothing more is coming, on loopback.
const QUIET: Duration = Duration::from_millis(500);

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A Binding Request with no attributes, encoded here rather than by the
/// module under test.
fn binding_request(transaction_id: [u8; 12]) -> Vec<u8> {
    let mut msg = vec![0x00, 0x01, 0x00, 0x00];
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&transaction_id);
    msg
}

/// A STUN server that answers with the address the request really came from —
/// a genuine reflexive address, which on loopback is the socket itself.
async fn echo_server() -> SocketAddr {
    let socket = loopback_socket().await;
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((_, from)) = socket.recv_from(&mut buf).await {
            let id = buf[8..20].try_into().unwrap();
            if socket
                .send_to(&success_response(id, from), from)
                .await
                .is_err()
            {
                break;
            }
        }
    });
    addr
}

/// A peer dials `addr` and both sides run §6 to the end.
async fn full_handshake(endpoint: &quinn::Endpoint, addr: SocketAddr) {
    let responder = Identity::generate();
    let initiator = Identity::generate();
    let dialler = client_endpoint(NodeKind::Private).unwrap();
    let accept = async {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        handshake::respond(&connection, &responder).await
    };
    let dial = async {
        let connection = connect(&dialler, addr).await.unwrap();
        handshake::initiate(&connection, &initiator, None).await
    };
    let (accepted, dialled) = tokio::join!(accept, dial);
    accepted.expect("the responder finishes §6");
    dialled.expect("the initiator finishes §6");
}

/// M13a gate 1: QUIC and then §6 complete on the node's socket while STUN
/// queries go out and come back on that same port, one after another for as
/// long as the handshake takes — so at least one is in flight across it.
#[tokio::test]
async fn a_full_handshake_completes_while_stun_is_in_flight_on_the_same_port() {
    let (endpoint, socket) = node_endpoint(loopback(), NodeKind::Private).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let server = echo_server().await;
    let done = AtomicBool::new(false);

    let handshake = async {
        full_handshake(&endpoint, addr).await;
        done.store(true, Ordering::SeqCst);
    };
    let queries = async {
        let mut answered = 0;
        while !done.load(Ordering::SeqCst) {
            let reflexive = stun::query(&socket, server, PATIENCE)
                .await
                .expect("STUN answered on the QUIC socket");
            assert_eq!(reflexive.port(), addr.port());
            answered += 1;
        }
        answered
    };

    let ((), answered) = tokio::time::timeout(PATIENCE, async { tokio::join!(handshake, queries) })
        .await
        .expect("the handshake or STUN hung on the shared socket");
    assert!(answered >= 1);
}

/// M13a gate 2, both directions, with real QUIC going both ways across the
/// socket: sixteen STUN requests are sent first, so their answers land in
/// the middle of it.
///
/// - QUIC never reaches STUN: every datagram STUN's side receives is from
///   the STUN server and answers one of our requests.
/// - STUN never reaches quinn: all sixteen answers reach STUN's side, and
///   the demux routes each datagram exactly one way. The unit tests in
///   `socket.rs` check that at the bytes quinn is handed.
#[tokio::test]
async fn quic_never_reaches_stun_and_stun_never_reaches_quinn() {
    let (endpoint, socket) = node_endpoint(loopback(), NodeKind::Private).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let server = echo_server().await;

    let ids: Vec<[u8; 12]> = (0..16u8).map(|i| [i; 12]).collect();
    for id in &ids {
        socket.send_to(&binding_request(*id), server).await.unwrap();
    }

    tokio::time::timeout(PATIENCE, async {
        // In: a peer dials the node.
        full_handshake(&endpoint, addr).await;
        // Out: the node dials a peer, from the same socket.
        let peer = server_endpoint(loopback(), NodeKind::Private).unwrap();
        let accepted = async { peer.accept().await.unwrap().await.unwrap() };
        let (_, dialled) = tokio::join!(accepted, connect(&endpoint, peer.local_addr().unwrap()));
        dialled.expect("the node's outbound QUIC completes");
    })
    .await
    .expect("QUIC hung on the shared socket");

    let mut answered = HashSet::new();
    let mut buf = [0u8; 1500];
    while let Ok(received) = tokio::time::timeout(QUIET, socket.recv_from(&mut buf)).await {
        let (len, from) = received.unwrap();
        assert_eq!(from, server, "a datagram from {from} reached STUN");
        let id: [u8; 12] = buf[8..20].try_into().unwrap();
        assert!(
            len >= 20 && ids.contains(&id),
            "STUN got something it never asked for"
        );
        assert!(answered.insert(id), "one answer reached STUN twice");
    }
    assert_eq!(answered.len(), ids.len(), "a STUN answer went to quinn");
}

/// M13a gate 3: what STUN reports is the socket quinn uses. The reflexive
/// port is the endpoint's local port, it holds across repeated queries, and
/// a QUIC peer the endpoint dials sees exactly that address.
#[tokio::test]
async fn the_mapping_reported_is_the_mapping_of_the_quic_socket() {
    let (endpoint, socket) = node_endpoint(loopback(), NodeKind::Private).unwrap();
    let local = endpoint.local_addr().unwrap();
    let one = echo_server().await;
    let two = echo_server().await;

    let first = stun::query(&socket, one, PATIENCE).await.unwrap();
    assert_eq!(first.port(), local.port());
    for _ in 0..5 {
        assert_eq!(stun::query(&socket, one, PATIENCE).await.unwrap(), first);
    }

    let report = stun::discover(&socket, &[("one", one), ("two", two)], PATIENCE).await;
    assert_eq!(report.mapping, Mapping::EndpointIndependent);
    assert_eq!(report.no_nat, Some(true));

    let peer = server_endpoint(loopback(), NodeKind::Private).unwrap();
    let _connecting = endpoint
        .connect(peer.local_addr().unwrap(), "p2pchat")
        .unwrap();
    let incoming = tokio::time::timeout(PATIENCE, peer.accept())
        .await
        .expect("the dial arrived")
        .unwrap();
    assert_eq!(incoming.remote_address(), first);
}
