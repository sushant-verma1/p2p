//! M9's gates, everything that a `TestBackend` can decide.
//!
//! The app is driven through the same two doors the binary uses — keys in,
//! [`Core`] calls out — so what these assert is what the terminal does, minus
//! the terminal.
//!
//! # What a `TestBackend` cannot decide
//!
//! Gate 9 — `Ctrl-C` and a panic leaving the terminal usable — moved to a real
//! pty in `p2pchat/tests/terminal.rs`. What is left needs a person and a real
//! terminal:
//!
//! - **Alt-Enter inserts a newline.** A `KeyEvent` here is synthetic: it says
//!   `ALT` because the test said so. Whether the terminal *reports* `ALT` with
//!   `Enter` is the terminal's business, and it is the whole reason for the
//!   binding — most of them do not report `SHIFT` with it. Check on xterm, the
//!   GNOME and KDE terminals, Alacritty, kitty, iTerm2 and Windows Terminal:
//!   type a word, press Alt-Enter, and the caret must move to a second line in
//!   the composer without the message being sent. Note any terminal where it
//!   does not, because that terminal has no newline key.
//! - **Whether it looks right**, and whether a real tty redraws cleanly under
//!   a resize — a `TestBackend` resize is a buffer reallocation, not a
//!   `SIGWINCH` racing a draw.
//! - **Whether wide and combining characters land where the arithmetic says.**
//!   The wrapping tests in `view.rs` assert the column count; only a terminal
//!   with the right fonts shows whether the column count matches the glyphs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;

use p2pchat_core::wire::DeliveryStatus;
use p2pchat_core::{MessageId, MsgSeq, UserId};
use p2pchat_tui::{App, ConnState, Conversation, Core, Cursor, Line, Notice, Pending, Preview};

/// What the store hands back per page — `p2pchat_store::PAGE_SIZE`, which this
/// crate may not name (§2). The fake obeys it so the gate can watch it.
const PAGE: usize = 50;

// ---------------------------------------------------------------------------
// A core that is not a node
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Call {
    Conversations,
    Pending,
    Page(UserId, Option<Cursor>),
    Send(UserId, String),
    Decide(UserId, bool),
    Verify(UserId),
    Import(String),
    Connect(UserId),
}

#[derive(Default)]
struct Fake {
    conversations: Vec<Conversation>,
    pending: Vec<Pending>,
    /// The whole stored history per peer, oldest first. Only ever served a
    /// page at a time — the point of gate 4 is that the app cannot ask for
    /// more.
    rows: BTreeMap<UserId, Vec<Line>>,
    invite: Option<Preview>,
    calls: Vec<Call>,
}

impl Fake {
    fn pages(&self) -> Vec<&Call> {
        self.calls
            .iter()
            .filter(|call| matches!(call, Call::Page(..)))
            .collect()
    }

    fn did(&self, call: &Call) -> bool {
        self.calls.contains(call)
    }
}

impl Core for Fake {
    fn me(&mut self) -> UserId {
        me()
    }

    fn conversations(&mut self) -> Vec<Conversation> {
        self.calls.push(Call::Conversations);
        self.conversations.clone()
    }

    fn pending(&mut self) -> Vec<Pending> {
        self.calls.push(Call::Pending);
        self.pending.clone()
    }

    fn page(&mut self, peer: UserId, before: Option<Cursor>) -> Vec<Line> {
        self.calls.push(Call::Page(peer, before));

        let rows = self.rows.get(&peer).cloned().unwrap_or_default();
        let end = match before {
            None => rows.len(),
            Some(cursor) => rows
                .iter()
                .position(|line| line.message_id == cursor.message_id)
                .unwrap_or(0),
        };
        rows[end.saturating_sub(PAGE)..end].to_vec()
    }

    fn send(&mut self, peer: UserId, body: String) {
        self.calls.push(Call::Send(peer, body.clone()));
        self.rows.entry(peer).or_default().push(line(&body, true));
    }

    fn decide(&mut self, from: UserId, accept: bool) {
        self.calls.push(Call::Decide(from, accept));
        self.pending.retain(|request| request.from != from);
    }

    fn verify(&mut self, peer: UserId) {
        self.calls.push(Call::Verify(peer));
        for conversation in &mut self.conversations {
            if conversation.peer == peer {
                conversation.verified = true;
            }
        }
    }

    fn import(&mut self, blob: &str) -> Result<Preview, String> {
        self.calls.push(Call::Import(blob.to_owned()));
        self.invite
            .clone()
            .ok_or_else(|| "not an invite".to_owned())
    }

    fn connect(&mut self, peer: UserId) {
        self.calls.push(Call::Connect(peer));
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Us. A byte no peer fixture uses, so a match on screen is ours.
fn me() -> UserId {
    UserId::from_bytes([0xa5; 32])
}

fn peer(byte: u8) -> UserId {
    UserId::from_bytes([byte; 32])
}

fn conversation(byte: u8, name: &str, verified: bool) -> Conversation {
    Conversation {
        peer: peer(byte),
        display_name: Some(name.to_owned()),
        verified,
        state: ConnState::Established,
        failure: None,
    }
}

fn line(body: &str, mine: bool) -> Line {
    Line {
        message_id: MessageId::now_v7(),
        msg_seq: MsgSeq::new(1),
        mine,
        body: body.to_owned(),
        status: DeliveryStatus::Delivered,
    }
}

fn history(count: usize) -> Vec<Line> {
    (0..count)
        .map(|i| Line {
            message_id: MessageId::now_v7(),
            msg_seq: MsgSeq::new(i as u64 + 1),
            mine: i % 2 == 0,
            body: format!("message {i}"),
            status: DeliveryStatus::Delivered,
        })
        .collect()
}

/// One conversation, verified, with `count` messages in it.
fn one(count: usize) -> Fake {
    let mut fake = Fake {
        conversations: vec![conversation(1, "alice", true)],
        ..Fake::default()
    };
    fake.rows.insert(peer(1), history(count));
    fake
}

fn terminal(width: u16, height: u16) -> Terminal<TestBackend> {
    Terminal::new(TestBackend::new(width, height)).expect("a test terminal")
}

/// Draws, and returns the screen as one string per row.
fn screen(terminal: &mut Terminal<TestBackend>, app: &mut App) -> Vec<String> {
    terminal
        .draw(|frame| p2pchat_tui::view::draw(frame, app))
        .expect("the draw succeeds");

    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect()
        })
        .collect()
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

fn type_text(app: &mut App, core: &mut Fake, text: &str) {
    for c in text.chars() {
        app.on_key(key(KeyCode::Char(c)), core);
    }
}

// ---------------------------------------------------------------------------
// Gate 1
// ---------------------------------------------------------------------------

/// Every pane present at the size F-21 promises, and nothing written outside
/// the pane it belongs to.
#[test]
fn the_whole_layout_fits_in_eighty_by_twenty_four() {
    let mut core = one(3);
    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);
    let rows = screen(&mut term, &mut app);

    assert_eq!(rows.len(), 24);
    assert!(rows.iter().all(|row| row.chars().count() == 80));

    let all = rows.join("\n");
    assert!(all.contains("p2pchat"), "no status bar:\n{all}");
    assert!(all.contains("peers"), "no conversation list:\n{all}");
    assert!(all.contains("alice"), "the peer is not listed:\n{all}");
    assert!(
        all.contains(&peer(1).fingerprint()),
        "F-02: the header must carry the fingerprint:\n{all}"
    );
    assert!(all.contains("message 2"), "no history:\n{all}");
    assert!(all.contains("Enter sends"), "no composer:\n{all}");

    // The borders are where the layout says, on every row between the status
    // bar and the composer — which is how "nothing overflows" is visible in a
    // buffer: content in the wrong pane would have eaten one of these.
    for (y, row) in rows.iter().enumerate().take(20).skip(2) {
        let chars: Vec<char> = row.chars().collect();
        assert_eq!(chars[23], '│', "row {y} lost the list's right border");
        assert_eq!(chars[24], '│', "row {y} lost the history's left border");
        assert_eq!(chars[79], '│', "row {y} lost the right edge");
    }
    assert!(rows[23].starts_with('└'), "the composer is not closed");

    // And the corners, where the panes meet.
    assert_eq!(rows[1].chars().nth(23), Some('┐'));
    assert_eq!(rows[1].chars().nth(24), Some('┌'));
    assert_eq!(rows[20].chars().nth(23), Some('┘'));
}

/// A message wider than the pane wraps onto the next row rather than running
/// past the border or being cut off.
#[test]
fn a_long_message_wraps_inside_its_pane() {
    let mut core = one(0);
    let tail = "endoftheline";
    core.rows.insert(
        peer(1),
        vec![line(&format!("{} {tail}", "word ".repeat(30)), false)],
    );

    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);
    let rows = screen(&mut term, &mut app);

    assert!(
        rows.join("\n").contains(tail),
        "the end of the message was dropped rather than wrapped"
    );
    for (y, row) in rows.iter().enumerate().take(20).skip(2) {
        assert_eq!(
            row.chars().nth(79),
            Some('│'),
            "row {y} wrote over the right border"
        );
    }
}

// ---------------------------------------------------------------------------
// Gate 2
// ---------------------------------------------------------------------------

#[test]
fn resizing_up_and_back_neither_panics_nor_corrupts_the_layout() {
    let mut core = one(60);
    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);

    let before = screen(&mut term, &mut app);

    term.backend_mut().resize(200, 60);
    let wide = screen(&mut term, &mut app);
    assert_eq!(wide.len(), 60);
    assert!(wide.iter().all(|row| row.chars().count() == 200));
    assert!(wide.join("\n").contains("peers"));

    term.backend_mut().resize(80, 24);
    let after = screen(&mut term, &mut app);

    assert_eq!(
        before, after,
        "the layout did not come back the way it went"
    );
}

// ---------------------------------------------------------------------------
// Gate 4
// ---------------------------------------------------------------------------

/// Scrollback pages. There is no call on [`Core`] that reads a whole
/// conversation, and the app never asks for more than it is about to show.
#[test]
fn scrollback_pages_and_never_reads_the_whole_conversation() {
    let mut core = one(130);
    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);
    screen(&mut term, &mut app);

    assert_eq!(
        core.pages(),
        vec![&Call::Page(peer(1), None)],
        "opening a conversation is one page, from the newest end"
    );

    // Up to the top, a screenful at a time. No one keypress may fetch more
    // than a page: that is what "never the whole conversation" means once the
    // first page is on screen.
    for _ in 0..8 {
        let before = core.pages().len();
        app.on_key(key(KeyCode::PageUp), &mut core);
        screen(&mut term, &mut app);
        let fetched = core.pages().len() - before;
        assert!(
            fetched <= 1,
            "one keypress fetched {fetched} pages, which is a bulk read"
        );
    }

    let pages = core.pages().len();
    assert!(
        (2..=5).contains(&pages),
        "130 rows is three pages and a probe past the end, not {pages} calls"
    );
    for call in core.pages().iter().skip(1) {
        assert!(
            matches!(call, Call::Page(_, Some(_))),
            "every page after the first carries a cursor: {call:?}"
        );
    }

    // The oldest message is reachable, so the paging actually walked back.
    assert!(screen(&mut term, &mut app).join("\n").contains("message 0"));
}

/// The second query starts exactly where the first page ended.
#[test]
fn the_next_page_starts_at_the_oldest_row_already_held() {
    let mut core = one(130);
    let oldest_on_screen = core.rows[&peer(1)][130 - PAGE].clone();

    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);
    screen(&mut term, &mut app);

    for _ in 0..3 {
        app.on_key(key(KeyCode::PageUp), &mut core);
        screen(&mut term, &mut app);
    }

    let second = core
        .pages()
        .get(1)
        .cloned()
        .cloned()
        .expect("a second page was fetched");
    assert_eq!(
        second,
        Call::Page(
            peer(1),
            Some(Cursor {
                msg_seq: oldest_on_screen.msg_seq,
                message_id: oldest_on_screen.message_id,
            })
        )
    );
}

// ---------------------------------------------------------------------------
// Gate 5
// ---------------------------------------------------------------------------

#[test]
fn a_new_message_follows_the_view_only_when_it_is_at_the_bottom() {
    let mut core = one(60);
    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);
    screen(&mut term, &mut app);

    // At the bottom: the arrival is shown.
    core.rows
        .get_mut(&peer(1))
        .expect("the conversation")
        .push(line("while watching", false));
    app.on_notice(Notice::Changed(peer(1)), &mut core);
    assert!(
        screen(&mut term, &mut app)
            .join("\n")
            .contains("while watching"),
        "at the bottom, a new message must appear"
    );

    // Scrolled up: the view stays exactly where the user put it.
    app.on_key(key(KeyCode::PageUp), &mut core);
    let parked = screen(&mut term, &mut app);

    core.rows
        .get_mut(&peer(1))
        .expect("the conversation")
        .push(line("while reading history", false));
    app.on_notice(Notice::Changed(peer(1)), &mut core);
    let after = screen(&mut term, &mut app);

    assert_eq!(
        parked[1..20],
        after[1..20],
        "a message arriving must not move a view the user scrolled"
    );
    assert!(
        !after.join("\n").contains("while reading history"),
        "the view jumped to the bottom"
    );
    assert!(
        after[0].contains("new below"),
        "the arrival must still be announced: {}",
        after[0]
    );

    // Back at the bottom, it catches up.
    app.on_key(key(KeyCode::End), &mut core);
    assert!(screen(&mut term, &mut app)
        .join("\n")
        .contains("while reading history"));
}

// ---------------------------------------------------------------------------
// Gate 6
// ---------------------------------------------------------------------------

#[test]
fn a_draft_survives_switching_conversations_and_back() {
    let mut core = Fake {
        conversations: vec![conversation(1, "alice", true), conversation(2, "bob", true)],
        ..Fake::default()
    };
    core.rows.insert(peer(1), history(2));
    core.rows.insert(peer(2), history(2));

    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);

    type_text(&mut app, &mut core, "half a thought");
    assert!(screen(&mut term, &mut app)
        .join("\n")
        .contains("half a thought"));

    app.on_key(key(KeyCode::Tab), &mut core);
    let elsewhere = screen(&mut term, &mut app).join("\n");
    assert!(
        !elsewhere.contains("half a thought"),
        "the draft followed the user to another conversation"
    );

    type_text(&mut app, &mut core, "something else");
    app.on_key(key(KeyCode::BackTab), &mut core);

    assert!(
        screen(&mut term, &mut app)
            .join("\n")
            .contains("half a thought"),
        "the draft did not survive the round trip"
    );
    assert!(
        !core.did(&Call::Send(peer(1), "half a thought".to_owned())),
        "switching conversations must not send the draft"
    );
}

// ---------------------------------------------------------------------------
// Gate 7
// ---------------------------------------------------------------------------

#[test]
fn an_unverified_peer_is_marked_and_a_verified_one_is_not() {
    let mut core = Fake {
        conversations: vec![conversation(1, "alice", false)],
        ..Fake::default()
    };
    core.rows.insert(peer(1), history(2));

    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);
    let before = screen(&mut term, &mut app).join("\n");
    assert!(
        before.contains("unverified"),
        "F-02: an unverified peer must be marked:\n{before}"
    );

    // F-03, and the same screen afterwards: the marker is gone.
    app.on_key(ctrl('t'), &mut core);
    let after = screen(&mut term, &mut app).join("\n");
    assert!(core.did(&Call::Verify(peer(1))));
    assert!(
        !after.contains("unverified") && after.contains("verified"),
        "a verified peer must stop being marked unverified:\n{after}"
    );
}

/// M12: a failed connection says why, in full, where the user is looking —
/// the "what to check" is the useful part and it is the long part, so it has
/// to wrap rather than be clipped at 80 columns.
#[test]
fn a_failed_conversation_shows_what_to_check() {
    let mut core = one(2);
    core.conversations[0].state = ConnState::Failed;
    core.conversations[0].failure = Some(
        "no answer from 203.0.113.9:47100 after 5s. check that UDP port 47100 is open \
         inbound, and that the owner is not behind carrier-grade NAT"
            .to_owned(),
    );

    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);
    let rows = screen(&mut term, &mut app);
    let all = rows.join("\n");
    for needle in [
        "203.0.113.9:47100",
        "UDP port 47100",
        "carrier-grade",
        "NAT",
    ] {
        assert!(
            rows.iter().any(|row| row.contains(needle)),
            "the reason must be on screen, wrapped, not clipped: {needle}\n{all}"
        );
    }
}

/// F-02: our own fingerprint one keystroke from the main view, and the
/// profile screen it opens carrying the full ID — architecture.md §4. Checked
/// at 80x24, where a 64-char ID beside a label would be clipped.
#[test]
fn one_keystroke_shows_the_local_fingerprint_and_the_full_id() {
    let mut core = one(3);
    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);

    let before = screen(&mut term, &mut app).join("\n");
    assert!(
        !before.contains(&me().fingerprint()),
        "the main view already shows it, so this proves nothing:\n{before}"
    );

    app.on_key(ctrl('p'), &mut core);
    let rows = screen(&mut term, &mut app);
    let after = rows.join("\n");
    assert!(
        after.contains(&me().fingerprint()),
        "F-02: one keystroke must show the local fingerprint:\n{after}"
    );
    assert!(
        rows.iter().any(|row| row.contains(&me().to_hex())),
        "the profile screen must show the full ID, unclipped, on one row:\n{after}"
    );

    app.on_key(key(KeyCode::Esc), &mut core);
    assert!(!screen(&mut term, &mut app)
        .join("\n")
        .contains(&me().fingerprint()));
}

// ---------------------------------------------------------------------------
// Gate 8
// ---------------------------------------------------------------------------

/// F-05. The fingerprint is on the screen and `connect` has not been called.
#[test]
fn an_imported_invite_shows_its_fingerprint_before_anything_is_connected() {
    let mut core = one(0);
    core.invite = Some(Preview {
        peer: peer(9),
        display_name: "carol".to_owned(),
        addrs: 2,
    });

    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);

    type_text(&mut app, &mut core, "p2pchat:v1:AAAA");
    app.on_key(key(KeyCode::Enter), &mut core);

    let shown = screen(&mut term, &mut app).join("\n");
    assert!(
        shown.contains(&peer(9).fingerprint()),
        "the fingerprint must be on screen:\n{shown}"
    );
    assert!(
        !core.did(&Call::Connect(peer(9))),
        "nothing may be dialled before the user has seen the fingerprint"
    );
    assert!(
        !core.did(&Call::Send(peer(1), "p2pchat:v1:AAAA".to_owned())),
        "an invite must not be sent as a message"
    );

    // And only then, on the user's say-so.
    app.on_key(key(KeyCode::Enter), &mut core);
    assert!(core.did(&Call::Connect(peer(9))));
}

#[test]
fn cancelling_the_preview_connects_to_nothing() {
    let mut core = one(0);
    core.invite = Some(Preview {
        peer: peer(9),
        display_name: "carol".to_owned(),
        addrs: 1,
    });

    let mut app = App::new(&mut core);
    type_text(&mut app, &mut core, "p2pchat:v1:AAAA");
    app.on_key(key(KeyCode::Enter), &mut core);
    app.on_key(key(KeyCode::Esc), &mut core);

    assert!(!core.did(&Call::Connect(peer(9))));
}

// ---------------------------------------------------------------------------
// F-07: the badge, accept and reject
// ---------------------------------------------------------------------------

#[test]
fn a_pending_request_is_badged_and_can_be_accepted_or_rejected() {
    let mut core = one(0);
    core.pending = vec![
        Pending {
            from: peer(7),
            display_name: "claims to be dave".to_owned(),
        },
        Pending {
            from: peer(8),
            display_name: "claims to be erin".to_owned(),
        },
    ];

    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);
    assert!(
        screen(&mut term, &mut app)[0].contains("2 pending"),
        "F-07: the badge must say how many are waiting"
    );

    app.on_key(ctrl('r'), &mut core);
    let listed = screen(&mut term, &mut app).join("\n");
    assert!(
        listed.contains(&peer(7).fingerprint()),
        "F-06: a request is identified by its fingerprint, not its name:\n{listed}"
    );

    app.on_key(key(KeyCode::Char('a')), &mut core);
    assert!(core.did(&Call::Decide(peer(7), true)));

    app.on_key(key(KeyCode::Char('r')), &mut core);
    assert!(core.did(&Call::Decide(peer(8), false)));

    app.on_key(key(KeyCode::Esc), &mut core);
    assert!(
        !screen(&mut term, &mut app)[0].contains("pending"),
        "the badge must go once the queue is empty"
    );
}

// ---------------------------------------------------------------------------
// F-23, F-24: sending, the help overlay, quitting
// ---------------------------------------------------------------------------

/// Both newline bindings, and the bare Enter that sends.
///
/// Alt is the one that works: `SHIFT` with `Enter` is not in the legacy
/// encoding and most terminals never report it, which left F-23's multi-line
/// input with no reachable key. Whether a given terminal reports `ALT` is in
/// this file's manual checklist — a synthetic `KeyEvent` cannot say.
#[test]
fn enter_sends_and_neither_newline_binding_does() {
    for newline in [KeyModifiers::SHIFT, KeyModifiers::ALT] {
        let mut core = one(0);
        let mut app = App::new(&mut core);

        type_text(&mut app, &mut core, "line one");
        app.on_key(KeyEvent::new(KeyCode::Enter, newline), &mut core);
        type_text(&mut app, &mut core, "line two");
        assert!(
            !core.calls.iter().any(|c| matches!(c, Call::Send(..))),
            "{newline:?}-Enter must not send"
        );

        app.on_key(key(KeyCode::Enter), &mut core);
        assert!(
            core.did(&Call::Send(peer(1), "line one\nline two".to_owned())),
            "{newline:?}-Enter did not leave a newline behind"
        );
    }
}

/// F-24: the overlay lists the binding, or nobody finds it.
#[test]
fn the_help_overlay_names_the_newline_key() {
    let mut core = one(0);
    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);

    app.on_key(key(KeyCode::Char('?')), &mut core);
    let shown = screen(&mut term, &mut app).join("\n");
    assert!(
        shown.contains("Alt-Enter"),
        "the newline binding must be discoverable:\n{shown}"
    );
}

#[test]
fn the_help_overlay_opens_on_a_question_mark_and_closes_on_escape() {
    let mut core = one(0);
    let mut app = App::new(&mut core);
    let mut term = terminal(80, 24);

    app.on_key(key(KeyCode::Char('?')), &mut core);
    assert!(screen(&mut term, &mut app).join("\n").contains("Ctrl-C"));

    app.on_key(key(KeyCode::Esc), &mut core);
    assert!(!screen(&mut term, &mut app).join("\n").contains("Ctrl-C"));

    // With something typed, `?` is a character like any other.
    type_text(&mut app, &mut core, "what?");
    let typed = screen(&mut term, &mut app).join("\n");
    assert!(typed.contains("what?") && !typed.contains("Ctrl-C"));
}

#[test]
fn ctrl_c_asks_to_quit() {
    let mut core = one(0);
    let mut app = App::new(&mut core);
    assert!(!app.quit());

    app.on_key(ctrl('c'), &mut core);
    assert!(app.quit(), "Ctrl-C must end the loop, overlay or not");
}

// ---------------------------------------------------------------------------
// Gate 9, the half that needs no terminal
// ---------------------------------------------------------------------------
//
// The gate itself is `p2pchat/tests/terminal.rs`, on a pty. These two are the
// unit-level contract underneath it: they say which code runs, where the pty
// test says what the terminal ends up in. They fail faster and point at a
// line, which is why they are still here.

/// The panic hook and the drop both run the restore, and the hook that was
/// there before still gets its turn.
#[test]
fn the_guard_restores_on_panic_and_on_drop() {
    // The panic hook is process-wide. Nothing else in this file touches it,
    // and the lock says so out loud.
    static HOOK: Mutex<()> = Mutex::new(());
    let _serialised = HOOK.lock().unwrap_or_else(|e| e.into_inner());

    let restores = Arc::new(Mutex::new(0u32));
    let chained = Arc::new(Mutex::new(0u32));

    // A quiet previous hook, so a deliberate panic does not look like a
    // failure in the test output — and so that chaining is observable.
    let previous = Arc::clone(&chained);
    std::panic::set_hook(Box::new(move |_| {
        *previous.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    }));

    let counter = Arc::clone(&restores);
    let guard = p2pchat_tui::terminal::Guard::with(move || {
        *counter.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    });

    let panicked = std::panic::catch_unwind(|| panic!("deliberate"));
    assert!(panicked.is_err());
    assert_eq!(
        *restores.lock().unwrap_or_else(|e| e.into_inner()),
        1,
        "the panic hook must restore the terminal"
    );
    assert_eq!(
        *chained.lock().unwrap_or_else(|e| e.into_inner()),
        1,
        "the hook that was there before must still run"
    );

    drop(guard);
    assert_eq!(
        *restores.lock().unwrap_or_else(|e| e.into_inner()),
        2,
        "dropping the guard must restore the terminal too"
    );

    let _ = std::panic::take_hook();
}

/// What a real terminal would be sent: leave the alternate screen, show the
/// cursor.
#[test]
fn restore_writes_the_sequences_that_undo_the_setup() {
    let mut written = Vec::new();
    p2pchat_tui::terminal::restore(&mut written).expect("writing to a Vec cannot fail");

    let text = String::from_utf8(written).expect("escape sequences are ASCII");
    assert!(
        text.contains("\x1b[?1049l"),
        "the alternate screen must be left: {text:?}"
    );
    assert!(
        text.contains("\x1b[?25h"),
        "the cursor must be shown again: {text:?}"
    );
}
