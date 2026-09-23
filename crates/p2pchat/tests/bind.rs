//! M9c's gates: the bind address is not the advertised address.
//!
//! The bug these are here for was invisible to every other test in this
//! workspace, and for a structural reason: they all run both nodes on one
//! machine, where loopback works and nothing else has to. A node that binds
//! `127.0.0.1` passes all of them and cannot be reached by anybody.
//!
//! Two of these deliberately listen somewhere other than loopback, because
//! that is the property — a test that binds loopback to prove reachability
//! proves nothing. They use an OS-chosen port and live for a fraction of a
//! second. Every *other* test in the workspace stays pinned to loopback.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Stdio;
use std::time::Duration;

use p2pchat_crypto::Identity;
use p2pchat_net::{client_endpoint, connect, handshake, NodeKind};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// Long enough for a process to start and a handshake to finish on a loaded
/// machine, short enough that a stuck test fails rather than hangs.
const PATIENCE: Duration = Duration::from_secs(20);

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ---------------------------------------------------------------------------
// Gate 1 and gate 4: what the binary binds
// ---------------------------------------------------------------------------

/// A running `p2pchat node`, and the two addresses its `ready` line reported.
struct Started {
    /// Killed on drop, so a gate never leaves a listener behind.
    _child: Child,
    _dir: tempfile::TempDir,
    user_id: String,
    private: SocketAddr,
    public: SocketAddr,
}

/// Starts the node with both endpoints on OS-chosen ports and reads the
/// `ready` line.
///
/// `P2PCHAT_BIND_ADDR` is removed before `env` is applied: gate 1 is about the
/// default, and a variable that happened to be set in the shell running
/// `cargo test` would quietly make it pass for the wrong reason.
async fn start(args: &[&str], env: &[(&str, &str)]) -> Started {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut command = Command::new(env!("CARGO_BIN_EXE_p2pchat"));
    command
        .arg("node")
        // Port 0 on both, so the gates never collide with a real node.
        .arg("--public-port")
        .arg("0")
        // M9d: a public node refuses to start without an address to advertise,
        // and these gates are about the *bind* address, which this is not.
        // TEST-NET-3, so it names nothing that exists.
        .arg("--addr")
        .arg("203.0.113.4:47100")
        .args(args)
        .env("P2PCHAT_CONFIG_DIR", dir.path().join("config"))
        .env("P2PCHAT_DATA_DIR", dir.path().join("data"))
        .env_remove("P2PCHAT_BIND_ADDR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in env {
        command.env(key, value);
    }

    let mut child = command.spawn().expect("the binary runs");
    let mut lines = BufReader::new(child.stdout.take().expect("a pipe from stdout")).lines();
    let ready = tokio::time::timeout(PATIENCE, lines.next_line())
        .await
        .expect("a ready line before the deadline")
        .expect("stdout is readable")
        .expect("the node started");

    let fields: Vec<&str> = ready.split('\t').collect();
    assert_eq!(fields.first(), Some(&"ready"), "unexpected line: {ready}");

    Started {
        _child: child,
        _dir: dir,
        user_id: fields[1].to_owned(),
        private: fields[2].parse().expect("a private address"),
        public: fields[3].parse().expect("a public address"),
    }
}

/// Gate 1. Both endpoints, default config: bound to every interface, which is
/// the whole point — `--addr` is advisory and never decided where to listen.
#[tokio::test]
async fn the_default_bind_is_every_interface() {
    let node = start(&[], &[]).await;

    assert!(
        node.private.ip().is_unspecified(),
        "the private endpoint bound {}; no other host can reach it",
        node.private
    );
    assert!(
        node.public.ip().is_unspecified(),
        "the public endpoint bound {}; no other host can reach it",
        node.public
    );
}

/// Gate 4. The flag moves the bind, and the environment beats the flag — F-27
/// says the override wins, and it is the same rule for every config value.
///
/// Both values are loopback addresses: `127.0.0.0/8` is entirely loopback, so
/// `127.0.0.2` proves the override took effect without listening anywhere a
/// packet could arrive from.
#[tokio::test]
async fn the_bind_flag_takes_effect_and_the_environment_beats_it() {
    let second: IpAddr = "127.0.0.2".parse().unwrap();

    let by_flag = start(&["--bind", "127.0.0.1"], &[]).await;
    assert_eq!(by_flag.private.ip(), LOOPBACK, "--bind was ignored");
    assert_eq!(by_flag.public.ip(), LOOPBACK, "--bind was ignored");

    let by_env = start(&[], &[("P2PCHAT_BIND_ADDR", "127.0.0.2")]).await;
    assert_eq!(by_env.private.ip(), second, "the override was ignored");
    assert_eq!(by_env.public.ip(), second, "the override was ignored");

    let both = start(
        &["--bind", "127.0.0.1"],
        &[("P2PCHAT_BIND_ADDR", "127.0.0.2")],
    )
    .await;
    assert_eq!(
        both.private.ip(),
        second,
        "the flag beat the environment; F-27 says the override wins"
    );
    assert_eq!(both.public.ip(), second, "the flag beat the environment");
}

// ---------------------------------------------------------------------------
// Gate 2: reachable by an address that is not loopback
// ---------------------------------------------------------------------------

/// This host's own address on the route off this machine, found without
/// sending anything: a connected UDP socket picks a route and binds the local
/// address a peer on that route would have to send to. No packet leaves, and
/// the destination is TEST-NET-2, which is reserved for documentation.
///
/// `None` when there is no route off loopback at all — a container started
/// with no network. That is the one case the gate cannot run in.
fn routable_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("198.51.100.1", 9)).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// Gate 2. The binary, started with default config, completes §6 with a caller
/// that dialled it at a non-loopback address of this host — the thing loopback
/// can never demonstrate, and the manual run this milestone came from.
///
/// It drives the binary rather than building a `Node` here on purpose: the
/// property is about the *default*, and a test that passes its own bind
/// address would still pass with the default put back to `127.0.0.1`.
#[tokio::test]
async fn a_node_is_reachable_by_a_non_loopback_address() {
    let Some(ip) = routable_ip() else {
        // `libtest` has no way to report a skip, so this is a failure naming
        // why it could not run. Passing would be a lie: nothing was proven.
        panic!(
            "SKIPPED, reported as a failure because libtest cannot report a skip: \
             this host has no non-loopback address, so there is no address to \
             test reachability over"
        );
    };

    let node = start(&[], &[]).await;
    assert!(
        node.private.ip().is_unspecified(),
        "the default bind is {}, so {ip} was never going to reach it",
        node.private
    );

    // The same listener, addressed the way a peer on another machine has to
    // address it.
    let addr = SocketAddr::new(ip, node.private.port());
    let caller = Identity::generate();
    let endpoint = client_endpoint(NodeKind::Private).expect("a client endpoint");
    let connection = connect(&endpoint, addr)
        .await
        .unwrap_or_else(|error| panic!("dialling {addr} failed: {error}"));

    let established =
        tokio::time::timeout(PATIENCE, handshake::initiate(&connection, &caller, None))
            .await
            .expect("the handshake resolves before the deadline")
            .unwrap_or_else(|error| panic!("the handshake over {addr} failed: {error}"));

    // Reached the node we meant to reach, not something else on that port.
    assert_eq!(
        established.session.peer_user_id().to_hex(),
        node.user_id,
        "{addr} answered, but not with the identity the node reported"
    );
}

// ---------------------------------------------------------------------------
// Gate 3: what an invite is allowed to advertise
// ---------------------------------------------------------------------------

fn invite_cmd(args: &[&str]) -> std::process::Output {
    let dir = tempfile::tempdir().expect("a temporary directory");
    std::process::Command::new(env!("CARGO_BIN_EXE_p2pchat"))
        .arg("invite")
        .args(args)
        .env("P2PCHAT_CONFIG_DIR", dir.path().join("config"))
        .env("P2PCHAT_DATA_DIR", dir.path().join("data"))
        .output()
        .expect("the binary runs")
}

/// Gate 3. `0.0.0.0` is where a node listens, not somewhere a peer can dial.
/// An invite carrying one is refused at the point it is built, with a message
/// that says what to do instead — F-04.
#[test]
fn an_invite_refuses_to_advertise_an_unspecified_address() {
    for addr in ["0.0.0.0:47100", "[::]:47100"] {
        let out = invite_cmd(&["--addr", addr]);

        assert!(!out.status.success(), "{addr} was accepted: {out:?}");
        assert_eq!(out.stdout, b"", "a blob was printed for {addr} anyway");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--addr"),
            "the error for {addr} does not say to pass --addr: {stderr}"
        );
    }

    // An address a peer can actually dial is untouched by the check.
    let out = invite_cmd(&["--addr", "203.0.113.4:47100"]);
    assert!(out.status.success(), "{out:?}");
}

/// M9d gate 5, the invite half. An invite with no address in it is a blob
/// nobody can act on, so it is refused where it is built rather than printed
/// and pasted — and the refusal says which flag to pass.
///
/// This replaces M9c's test recording the opposite: what a node ought to
/// auto-advertise was an open decision then, and M9d closed it. Nothing is
/// derived; the user is asked.
#[test]
fn an_invite_with_no_address_is_refused() {
    let out = invite_cmd(&["--name", "ada"]);

    assert!(
        !out.status.success(),
        "an addressless invite was built: {out:?}"
    );
    assert_eq!(out.stdout, b"", "a blob was printed anyway");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--addr"),
        "the error does not say to pass --addr: {stderr}"
    );
}
