//! M13a gate 4: a node's outbound dials leave from its own private endpoint's
//! socket — both the private dial and the ask to a public node — so the
//! mapping STUN learned for that socket, and any hole punched from it, is the
//! one they use. A dial from a fresh socket would arrive from another port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use p2pchat::{Config, Node};
use p2pchat_crypto::Identity;
use p2pchat_net::{server_endpoint, NodeKind};

const PATIENCE: Duration = Duration::from_secs(20);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("a literal address")
}

/// The address the next connection attempt to `endpoint` comes from.
async fn source_of_next(endpoint: &quinn::Endpoint) -> SocketAddr {
    tokio::time::timeout(PATIENCE, endpoint.accept())
        .await
        .expect("a connection attempt arrives")
        .expect("the endpoint is open")
        .remote_address()
}

#[tokio::test(flavor = "multi_thread")]
async fn dials_and_asks_leave_from_the_private_endpoints_socket() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (node, _events) = Node::start(Config {
        config_dir: dir.path().join("config"),
        data_dir: dir.path().join("data"),
        private_bind: loopback(),
        public_bind: None,
        advertise: vec!["127.0.0.1:47100".parse().expect("a literal address")],
        private_advertise: None,
        display_name: "test".to_owned(),
        bootstrap: Vec::new(),
    })
    .await
    .expect("the node starts");
    let own = node.private_addr().expect("a bound address");

    // A private dial. Nobody answers §6; the source is all this needs.
    let private = server_endpoint(loopback(), NodeKind::Private).expect("an endpoint");
    let target = private.local_addr().expect("a bound address");
    let dialler = Arc::clone(&node);
    tokio::spawn(async move { dialler.dial(target, None).await });
    assert_eq!(source_of_next(&private).await, own, "the dial");

    // An ask to a public node.
    let public = server_endpoint(loopback(), NodeKind::Public).expect("an endpoint");
    let target = public.local_addr().expect("a bound address");
    let asker = Arc::clone(&node);
    let owner = Identity::generate().user_id();
    tokio::spawn(async move { asker.request_connection(owner, target).await });
    assert_eq!(source_of_next(&public).await, own, "the ask");
}

/// M13b: a running node still holds STUN's side of its private socket. A
/// STUN-shaped datagram sent to the node's private port reaches
/// [`Node::stun`] — dropped, it would be discarded in the demux, and the next
/// thing to want a reflexive address would bind a second socket for one.
#[tokio::test(flavor = "multi_thread")]
async fn the_running_node_holds_the_stun_side_of_its_socket() {
    use p2pchat_net::stun::Datagrams;

    let dir = tempfile::tempdir().expect("a temporary directory");
    let (node, _events) = Node::start(Config {
        config_dir: dir.path().join("config"),
        data_dir: dir.path().join("data"),
        private_bind: loopback(),
        public_bind: None,
        advertise: Vec::new(),
        private_advertise: None,
        display_name: "test".to_owned(),
        bootstrap: Vec::new(),
    })
    .await
    .expect("the node starts");

    // A Binding Success header: first two bits clear, magic cookie at 4..8.
    let mut datagram = vec![0x01, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42];
    datagram.extend_from_slice(&[7; 12]);
    let sender = std::net::UdpSocket::bind(loopback()).expect("a socket");
    sender
        .send_to(&datagram, node.private_addr().expect("a bound address"))
        .expect("sent");

    let mut buf = [0u8; 64];
    let (len, from) = tokio::time::timeout(PATIENCE, node.stun().recv_from(&mut buf))
        .await
        .expect("the datagram reached the node's STUN channel")
        .expect("the channel is open");
    assert_eq!(&buf[..len], &datagram[..]);
    assert_eq!(from, sender.local_addr().expect("a bound address"));
}
