//! The flow a user actually performs, driven through the screen's own code.
//!
//! `connect.rs` gate 1 calls `Node::request_connection` directly. The TUI never
//! does: it goes `App::on_key` → `Core` → `ui::Channel` → `ui::serve` → the
//! node, and the state the user reads lives in the first three of those. A gate
//! below that line cannot see a screen that stays on `connecting`.
//!
//! So this drives the real [`App`] over the real [`Channel`], with the
//! keystrokes a person makes: paste the invite, Enter on the fingerprint,
//! `Ctrl-R` and `a` on the other side. Everything but `crossterm`'s reader and
//! the draw — and the draw only reads what is asserted here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::Terminal;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::Receiver;

use p2pchat::ui::Channel;
use p2pchat::{Config, Node};
use p2pchat_core::wire::DeliveryStatus;
use p2pchat_core::UserId;
use p2pchat_crypto::{invite, keystore};
use p2pchat_tui::{App, ConnState, Core, Notice, Overlay};

/// Long enough for a loopback exchange and the 2s first poll on a loaded
/// machine, short enough that a stuck flow fails rather than hangs.
const PATIENCE: Duration = Duration::from_secs(60);

/// The host both nodes advertise. Loopback: both are on this machine.
const HOST: &str = "127.0.0.1";

/// What the failing-dial gate sets `P2PCHAT_DIAL_TIMEOUT_MS` to — M9f.
const DIAL_TIMEOUT: Duration = Duration::from_secs(2);

/// `node::POLL_MIN`, which is how long after the acceptance the requester next
/// asks and so the earliest the dial can start.
const POLL: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// One node, as the binary starts it, with the screen's half in hand
// ---------------------------------------------------------------------------

/// A node and the `App` that would be drawing it.
///
/// The `App` is driven from the test thread, which is a plain OS thread and
/// not a runtime one — the same rule `ui::run` follows, and the reason
/// [`Channel`] may block on it at all.
struct Screen {
    app: App<'static>,
    core: Channel,
    notices: Receiver<Notice>,
    /// The node under the screen. M10's gates reach past the keyboard — there
    /// is no keystroke for "the cable came out", and the screen is what has to
    /// say so when it does.
    node: Arc<Node>,
    me: UserId,
    /// What this node advertises, which is what its invite carries.
    advertise: SocketAddr,
    _dir: tempfile::TempDir,
}

/// A node with a public endpoint on the port it advertises — what `--addr
/// 127.0.0.1:P --public-port P` gives. `public == false` runs no public node,
/// which is the requester: nobody can ask it anything.
fn screen(runtime: &Runtime, public: bool) -> Screen {
    screen_with(runtime, public, |_| {})
}

/// The same, with the flags the second gate needs changed — `tweak` is what a
/// different command line would have produced.
fn screen_with(runtime: &Runtime, public: bool, tweak: impl FnOnce(&mut Config)) -> Screen {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let advertise: SocketAddr = format!("{HOST}:{}", free_port())
        .parse()
        .expect("a literal address");

    let mut config = Config {
        config_dir: dir.path().join("config"),
        data_dir: dir.path().join("data"),
        private_bind: format!("{HOST}:0").parse().expect("a literal address"),
        public_bind: public.then_some(advertise),
        advertise: vec![advertise],
        private_advertise: None,
        display_name: "test".to_owned(),
    };

    tweak(&mut config);

    // Loaded here first so the test knows the user ID; `Node::start` loads the
    // same file a moment later.
    let me = keystore::load_or_create(&keystore::key_path(&config.config_dir))
        .expect("an identity")
        .user_id();

    let (mut core, notices, node) = runtime
        .block_on(p2pchat::ui::start(config))
        .expect("the node starts");
    let app = App::new(&mut core);
    Screen {
        app,
        core,
        notices,
        node,
        me,
        advertise,
        _dir: dir,
    }
}

/// `RUST_LOG` into the test output, once per binary. These gates are the ones
/// a flow is diagnosed from when it fails on somebody's machine, and the log
/// is the only witness there.
fn logs() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

/// A UDP port nothing is listening on, since the advertised port and the bound
/// one have to be the same number and only one of them can be asked for.
fn free_port() -> u16 {
    std::net::UdpSocket::bind((HOST, 0))
        .expect("a socket")
        .local_addr()
        .expect("a bound address")
        .port()
}

impl Screen {
    /// One keystroke, as `p2pchat_tui::run` delivers it.
    fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        self.app.on_key(
            KeyEvent {
                code,
                modifiers,
                kind: KeyEventKind::Press,
                state: KeyEventState::NONE,
            },
            &mut self.core,
        );
    }

    /// A paste, which arrives as one `Char` event per character.
    fn type_str(&mut self, text: &str) {
        for c in text.chars() {
            self.key(KeyCode::Char(c), KeyModifiers::NONE);
        }
    }

    /// Drains whatever the core has sent, exactly as the run loop does.
    fn pump(&mut self) {
        while let Ok(notice) = self.notices.try_recv() {
            self.app.on_notice(notice, &mut self.core);
        }
    }

    /// F-07's queue, as the screen would find it on `Ctrl-R`.
    fn requests(&mut self) -> usize {
        self.core.pending().len()
    }

    /// The blob this node's user pastes to somebody else — what `p2pchat
    /// invite` prints, from the same identity file and the same `--addr`.
    fn invite(&self) -> String {
        let identity =
            keystore::load_or_create(&keystore::key_path(&self._dir.path().join("config")))
                .expect("the identity the node loaded");
        let invite = invite::create(&identity, "host", vec![self.advertise], invite::now())
            .expect("an invite");
        invite::encode(&invite).expect("the blob")
    }
}

/// Pumps both screens until `done`, or gives up.
///
/// Both, because the flow is two screens: the other side's notices have to be
/// drained for its `App` to be where its user would be.
fn until(a: &mut Screen, b: &mut Screen, what: &str, mut done: impl FnMut(&mut Screen) -> bool) {
    let deadline = Instant::now() + PATIENCE;
    loop {
        a.pump();
        b.pump();
        if done(a) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Paste an invite, press Enter, be accepted — and the screen says connected.
///
/// The assertion is the status column rather than an `Event`, because the
/// column is what the user reads and what was wrong.
#[test]
fn a_pasted_invite_that_is_accepted_ends_on_a_connected_screen() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    logs();

    let mut host = screen(&runtime, true);
    let mut caller = screen(&runtime, false);
    let blob = host.invite();

    // The requester pastes and presses Enter: F-05's preview, nothing dialled.
    caller.type_str(&blob);
    caller.key(KeyCode::Enter, KeyModifiers::NONE);
    assert!(
        matches!(caller.app.overlay_ref(), Overlay::Invite(_)),
        "the invite was not previewed: {:?}",
        caller.app.overlay_ref()
    );

    // Enter on the fingerprint — the only path from an invite to a connection.
    caller.key(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        caller.app.peer(),
        Some(host.me),
        "the peer list lost the host"
    );

    until(
        &mut host,
        &mut caller,
        "the request to reach the host",
        |host| host.requests() == 1,
    );

    // Ctrl-R opens the queue; `a` accepts the selected request.
    host.key(KeyCode::Char('r'), KeyModifiers::CONTROL);
    host.key(KeyCode::Char('a'), KeyModifiers::NONE);

    until(
        &mut caller,
        &mut host,
        "the requester's screen to say connected",
        |caller| caller.app.state() == ConnState::Established,
    );

    assert_eq!(host.app.peer(), Some(caller.me));
    assert_eq!(
        host.app.state(),
        ConnState::Established,
        "the acceptor's screen never said connected"
    );
}

/// An accepted request whose advertised private endpoint answers nothing — a
/// forwarded public port and an unforwarded private one, which is the default
/// on any host behind NAT. The dial cannot succeed, and the screen must say so
/// rather than sit on `connecting` for ever.
///
/// M9f adds the clock. Without an overall dial deadline the screen still gets
/// here eventually, on whatever QUIC decides — so the assertion that means
/// anything is *when*, against a deadline this test sets itself.
#[test]
fn an_accepted_request_whose_dial_fails_ends_on_a_failed_screen() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    logs();

    // Process-wide, and read on every dial — so this also shortens the other
    // gate's dial, which takes milliseconds over loopback and does not care.
    // Set low deliberately: at the default it is QUIC's own timeout being
    // measured and the deadline below proves nothing.
    std::env::set_var(
        "P2PCHAT_DIAL_TIMEOUT_MS",
        DIAL_TIMEOUT.as_millis().to_string(),
    );

    // Nothing is bound here: the port was free when it was taken and the
    // socket is gone.
    let nowhere: SocketAddr = format!("{HOST}:{}", free_port())
        .parse()
        .expect("a literal address");
    let mut host = screen_with(&runtime, true, |config| {
        config.private_advertise = Some(nowhere)
    });
    let mut caller = screen(&runtime, false);
    let blob = host.invite();

    caller.type_str(&blob);
    caller.key(KeyCode::Enter, KeyModifiers::NONE);
    caller.key(KeyCode::Enter, KeyModifiers::NONE);

    until(
        &mut host,
        &mut caller,
        "the request to reach the host",
        |host| host.requests() == 1,
    );
    host.key(KeyCode::Char('r'), KeyModifiers::CONTROL);
    host.key(KeyCode::Char('a'), KeyModifiers::NONE);

    let accepted = Instant::now();
    until(
        &mut caller,
        &mut host,
        "the requester's screen to stop saying connecting",
        |caller| caller.app.state() != ConnState::Connecting,
    );
    assert_eq!(
        caller.app.state(),
        ConnState::Failed,
        "the dial failed and the screen does not say so"
    );

    // The dial is one poll interval behind the acceptance, so the budget is
    // the deadline plus that plus slack — and still far below what QUIC on
    // its own takes to give up on an address nothing answers.
    let took = accepted.elapsed();
    assert!(
        took < DIAL_TIMEOUT + POLL + Duration::from_secs(3),
        "the dial was not bounded by its own deadline: {took:?}"
    );
}

/// M9f's root cause: a session that nobody types into must still be a session
/// a minute later.
///
/// quinn's defaults are a 30-second idle timeout and no keep-alive, so every
/// conversation here died thirty seconds after it opened — both screens still
/// saying `connected`, both connections gone. A chat is silent most of the
/// time, which is exactly the case those defaults close.
///
/// The gate is the screen rather than the connection, because the screen is
/// what was wrong: it said connected for a session that had already ended.
/// Nothing is sent for the whole wait — traffic would hide the bug, since any
/// packet resets the idle timer and the keep-alive would not be what kept it.
#[test]
fn a_silent_session_outlives_the_idle_timeout() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    logs();

    let mut host = screen(&runtime, true);
    let mut caller = screen(&runtime, false);
    let blob = host.invite();

    caller.type_str(&blob);
    caller.key(KeyCode::Enter, KeyModifiers::NONE);
    caller.key(KeyCode::Enter, KeyModifiers::NONE);

    until(
        &mut host,
        &mut caller,
        "the request to reach the host",
        |host| host.requests() == 1,
    );
    host.key(KeyCode::Char('r'), KeyModifiers::CONTROL);
    host.key(KeyCode::Char('a'), KeyModifiers::NONE);
    until(
        &mut caller,
        &mut host,
        "the requester's screen to say connected",
        |caller| caller.app.state() == ConnState::Established,
    );

    // Past the idle timeout with slack, and pumping throughout: a screen that
    // is never asked cannot notice the session ending, which would pass this
    // for the wrong reason.
    let deadline = Instant::now() + p2pchat_net::MAX_IDLE + Duration::from_secs(4);
    while Instant::now() < deadline {
        caller.pump();
        host.pump();
        std::thread::sleep(Duration::from_millis(200));
    }

    assert_eq!(
        caller.app.state(),
        ConnState::Established,
        "the requester's session did not survive {:?} of silence",
        p2pchat_net::MAX_IDLE
    );
    assert_eq!(
        host.app.state(),
        ConnState::Established,
        "the acceptor's session did not survive {:?} of silence",
        p2pchat_net::MAX_IDLE
    );
}

/// Bob types, presses Enter, and there is no session: what he typed must not
/// vanish.
///
/// `Node::send` used to fail with "no session with that peer" before anything
/// was written, so the composer cleared and nothing took its place — the
/// message was gone from the screen and had never reached the store. All three
/// of what is left are asserted here, because only the first is invisible: the
/// row exists, it is `PENDING`, and the screen shows it as `me.` rather than
/// as the `me>` a sent message gets.
#[test]
fn a_message_typed_with_no_session_is_stored_pending_and_shown() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    logs();

    // Never started as a public node and never dialled: the invite is only how
    // the peer gets into the list, which is what a conversation to type into
    // requires. Esc on the preview is the user reading the fingerprint and
    // walking away — F-05's import without the connect.
    let host = screen(&runtime, false);
    let mut bob = screen(&runtime, false);
    let blob = host.invite();

    bob.type_str(&blob);
    bob.key(KeyCode::Enter, KeyModifiers::NONE);
    bob.key(KeyCode::Esc, KeyModifiers::NONE);
    bob.pump();
    assert_eq!(bob.app.peer(), Some(host.me), "the invite added no peer");
    assert_eq!(
        bob.app.state(),
        ConnState::Disconnected,
        "this gate is about having no session"
    );

    bob.type_str("hello");
    bob.key(KeyCode::Enter, KeyModifiers::NONE);

    // Stored. Read back through `Core::page`, which is the store and not the
    // app's copy of it.
    let stored = bob.core.page(host.me, None);
    assert_eq!(
        stored.len(),
        1,
        "the send failed and took the message with it"
    );
    assert_eq!(stored[0].body, "hello");
    assert!(stored[0].mine);
    assert_eq!(
        stored[0].status,
        DeliveryStatus::Pending,
        "a message that was never written to a socket is not sent"
    );

    // Rendered, and marked. `me.` is the pending glyph; a message that had
    // gone out would be `me>`, which is the distinction the user reads.
    let screen = drawn(&mut bob);
    assert!(
        screen.contains("me. hello"),
        "the pending message is not on the screen as pending:\n{screen}"
    );
    assert!(
        !screen.contains("me> hello"),
        "a message with no session is drawn as though it had been sent:\n{screen}"
    );
    assert!(
        screen.contains("queued"),
        "the user is not told the message has not gone out:\n{screen}"
    );
}

/// The whole screen as text, one line per row.
fn drawn(screen: &mut Screen) -> String {
    let mut terminal =
        Terminal::new(TestBackend::new(80, 24)).expect("a terminal over the test backend");
    terminal
        .draw(|frame| p2pchat_tui::view::draw(frame, &mut screen.app))
        .expect("the draw succeeds");

    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// F-25: the four words the status bar has to be able to say, each read back
/// out of the rendered buffer.
///
/// `connecting` and `failed` are the other two gates in this file. The three
/// here are the ones M10 adds a state machine for, plus the `offline` they are
/// distinguished from — a peer that is merely in the list has never been the
/// same thing as one whose session just dropped, and until M10 the screen had
/// one word for both.
///
/// The drop is made with a stalling endpoint rather than by stopping the host:
/// a dial to nothing never gets past `connecting`, and `handshaking` is by
/// definition an address that answered. This one accepts the connection and
/// then says nothing at all, which is where §6 waits.
#[test]
fn the_status_bar_says_offline_connected_reconnecting_and_handshaking() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    logs();

    let mut host = screen(&runtime, true);
    let mut caller = screen(&runtime, false);
    let blob = host.invite();

    // Imported and walked away from — F-05's preview, Esc. A peer, no request.
    caller.type_str(&blob);
    caller.key(KeyCode::Enter, KeyModifiers::NONE);
    caller.key(KeyCode::Esc, KeyModifiers::NONE);
    caller.pump();
    let bar = drawn(&mut caller);
    assert!(
        bar.contains("offline"),
        "a peer with no session is not offline on the screen:\n{bar}"
    );

    // The same blob, confirmed this time, and accepted on the other side.
    caller.type_str(&blob);
    caller.key(KeyCode::Enter, KeyModifiers::NONE);
    caller.key(KeyCode::Enter, KeyModifiers::NONE);
    until(
        &mut host,
        &mut caller,
        "the request to reach the host",
        |host| host.requests() == 1,
    );
    host.key(KeyCode::Char('r'), KeyModifiers::CONTROL);
    host.key(KeyCode::Char('a'), KeyModifiers::NONE);
    until(
        &mut caller,
        &mut host,
        "the requester's screen to say connected",
        |caller| caller.app.state() == ConnState::Established,
    );
    let bar = drawn(&mut caller);
    assert!(
        bar.contains("connected"),
        "the session is up and the screen does not say so:\n{bar}"
    );

    // Somewhere that answers a dial and never a handshake. Bound on the
    // runtime, because a quinn endpoint registers with the reactor it is
    // created on and there is none on the test thread.
    let stalled = runtime.block_on(async {
        let stall = p2pchat_net::server_endpoint(
            format!("{HOST}:0").parse().expect("a literal address"),
            p2pchat_net::NodeKind::Private,
        )
        .expect("a stalling endpoint");
        let stalled = stall.local_addr().expect("a bound address");
        tokio::spawn(async move {
            while let Some(incoming) = stall.accept().await {
                tokio::spawn(async move {
                    // Held, not dropped: a closed connection is a failed dial
                    // and the screen would go straight back to reconnecting.
                    let _connection = incoming.await;
                    std::future::pending::<()>().await;
                });
            }
        });
        stalled
    });

    // §10 redials where it last handshaked, so that is what is moved.
    runtime
        .block_on(caller.node.store.set_peer_addr(host.me, stalled))
        .expect("the store answers");
    runtime.block_on(caller.node.disconnect(host.me));

    // Both words, in the order the machine reaches them: the backoff first,
    // then the dial that got somewhere.
    let mut seen: Vec<&str> = Vec::new();
    let deadline = Instant::now() + PATIENCE;
    while seen.len() < 2 {
        caller.pump();
        host.pump();
        let bar = drawn(&mut caller);
        for word in ["reconnecting", "handshaking"] {
            if bar.contains(word) && !seen.contains(&word) {
                seen.push(word);
            }
        }
        assert!(
            Instant::now() < deadline,
            "the screen never got past {seen:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        seen,
        ["reconnecting", "handshaking"],
        "the states were reported out of order"
    );
}
