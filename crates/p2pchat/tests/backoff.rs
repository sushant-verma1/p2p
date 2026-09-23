//! M10 gate 6: the backoff gives up — `architecture.md` §10.
//!
//! Its own binary because the budget is read from the environment and the
//! environment is process-wide: every other reconnection gate needs the loop
//! to keep trying, and this one needs it to stop. One process cannot have
//! both.
//!
//! The schedule's shape — 1, 2, 4, 8, 16, 30, then 30 with jitter, and `None`
//! past ten minutes — is asserted on the real numbers in `node`'s own unit
//! tests. What cannot be asserted there is that a *node* stops: that the loop
//! consults the budget at all, and that when it runs out there is no task
//! still dialling.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use tokio::sync::mpsc::Receiver;

use p2pchat::{Config, Event, Node};

/// Scaled from §10's seconds so the whole schedule fits in a test: the first
/// three sleeps become 50ms, 100ms and 200ms.
const BACKOFF_MS: &str = "50";

/// Shorter than the first sleep would be misleading; longer than the budget
/// would make the give-up the dial's timeout rather than the budget's.
const DIAL_TIMEOUT_MS: &str = "400";

/// Ten minutes, scaled the same way.
const BUDGET: Duration = Duration::from_millis(1_500);

fn addr() -> SocketAddr {
    let port = std::net::UdpSocket::bind(("127.0.0.1", 0))
        .expect("a socket")
        .local_addr()
        .expect("a bound address")
        .port();
    format!("127.0.0.1:{port}")
        .parse()
        .expect("a literal address")
}

/// One runtime for both nodes: nothing here has to stop, only to give up.
fn start(runtime: &Runtime, dir: &std::path::Path) -> (Arc<Node>, Receiver<Event>, SocketAddr) {
    let private = addr();
    let (node, events) = runtime
        .block_on(Node::start(Config {
            config_dir: dir.join("config"),
            data_dir: dir.join("data"),
            private_bind: private,
            public_bind: None,
            advertise: Vec::new(),
            private_advertise: None,
            display_name: "test".to_owned(),
        }))
        .expect("the node starts");
    (node, events, private)
}

/// A session, then an address that will never answer again, then the drop.
///
/// The give-up is visible as the phase disappearing: `Node::report` holds the
/// `Reconnecting` phase for exactly as long as the loop runs, so a loop that
/// never returns is a peer that says `reconnecting` for ever.
#[test]
fn the_reconnect_loop_gives_up_when_the_budget_runs_out() {
    std::env::set_var("P2PCHAT_BACKOFF_MS", BACKOFF_MS);
    std::env::set_var("P2PCHAT_DIAL_TIMEOUT_MS", DIAL_TIMEOUT_MS);
    std::env::set_var(
        "P2PCHAT_RECONNECT_BUDGET_MS",
        BUDGET.as_millis().to_string(),
    );
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (host, _host_events, host_addr) = start(&runtime, &dir.path().join("host"));
    let (bob, mut events, _bob_addr) = start(&runtime, &dir.path().join("bob"));
    let host_id = host.me;

    runtime.block_on(async {
        host.store
            .resolve_request(bob.me, true)
            .await
            .expect("the store answers");
        bob.store
            .resolve_request(host_id, true)
            .await
            .expect("the store answers");
        bob.dial(host_addr, Some(host_id))
            .await
            .expect("the dial succeeds");

        // The peer moves to an address nothing is bound to: a peer that went
        // away and did not come back, which is the only case the budget is
        // for. One that comes back is every other gate.
        bob.store
            .set_peer_addr(host_id, addr())
            .await
            .expect("the store answers");
        bob.disconnect(host_id).await;
    });
    let dropped = Instant::now();

    // It starts, or there is no budget to run out of.
    until("the reconnect loop to start", || {
        bob.phases().contains_key(&host_id)
    });
    until("the reconnect loop to give up", || {
        !bob.phases().contains_key(&host_id)
    });
    let gave_up = dropped.elapsed();

    // Not immediately: a loop that never tried at all would also leave no
    // phase behind.
    assert!(
        gave_up >= BUDGET,
        "it gave up after {gave_up:?}, before the {BUDGET:?} budget was spent"
    );

    // And it stays given up — the mutation that matters is a loop that reads
    // the budget and carries on regardless.
    std::thread::sleep(BUDGET);
    assert!(
        !bob.phases().contains_key(&host_id),
        "the peer is in a phase again after the budget ran out: {:?}",
        bob.phases()
    );

    // §10 says the user is told. `DialFailed` is what the screen reads.
    let mut told = false;
    while let Ok(event) = events.try_recv() {
        told |= matches!(event, Event::DialFailed { peer, .. } if peer == host_id);
    }
    assert!(told, "the loop gave up and nothing was reported");
}

/// Polls until `done`, or fails. Never a hang.
fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + BUDGET * 20;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
