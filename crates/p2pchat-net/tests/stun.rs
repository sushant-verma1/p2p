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

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use p2pchat_net::stun::{self, Mapping};
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
