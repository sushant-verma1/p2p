//! The screen's state, and what a keystroke does to it.
//!
//! Everything here is synchronous and owns no I/O: the app is handed a
//! [`Core`] and calls it, which is what lets the gates drive it with a fake and
//! count what it asked for. Drawing is in [`crate::view`], which only reads.

use std::collections::BTreeMap;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui_textarea::{Input, TextArea};

use p2pchat_core::UserId;

use crate::model::{ConnState, Conversation, Core, Cursor, Line, Notice, Pending, Preview};

/// Enough of the invite scheme to tell "the user pasted an invite" from "the
/// user typed a message". `p2pchat-crypto` owns the real string and does the
/// real parsing; §2 keeps it out of this crate, and a sniff is all the
/// keystroke handler needs.
const INVITE_PREFIX: &str = "p2pchat:";

/// What is covering the screen, if anything.
#[derive(Clone, Debug, PartialEq)]
pub enum Overlay {
    None,
    /// F-24.
    Help,
    /// F-02: our own fingerprint and full ID, one keystroke from anywhere.
    /// The local half of THREAT_MODEL.md §3's out-of-band comparison.
    Profile(UserId),
    /// F-07's queue, where accept and reject live.
    Requests,
    /// F-05. Holding this *is* the feature: the fingerprint is on screen and
    /// nothing has been dialled.
    Invite(Preview),
    Error(String),
}

pub struct App<'a> {
    conversations: Vec<Conversation>,
    selected: usize,

    /// Messages paged in so far, oldest first. Never the whole conversation:
    /// [`Core::page`] is the only way in and it returns one page.
    history: Vec<Line>,
    /// Display rows scrolled up from the bottom. Zero means "at the bottom",
    /// which is F-22's condition for following new arrivals.
    scroll: usize,
    /// Set when the store says there is nothing older.
    exhausted: bool,
    /// Something arrived while the view was scrolled up. Said in the status
    /// bar rather than by yanking the view.
    more_below: bool,
    /// The history pane's height as of the last draw, so a page key moves by
    /// a screenful.
    viewport: usize,

    /// F-23: one per conversation, kept while the user is elsewhere.
    drafts: BTreeMap<UserId, String>,
    input: TextArea<'a>,

    overlay: Overlay,
    pending: Vec<Pending>,
    request: usize,

    status: String,
    quit: bool,
}

impl<'a> App<'a> {
    pub fn new(core: &mut impl Core) -> Self {
        let mut app = App {
            conversations: Vec::new(),
            selected: 0,
            history: Vec::new(),
            scroll: 0,
            exhausted: false,
            more_below: false,
            viewport: 10,
            drafts: BTreeMap::new(),
            input: textarea(),
            overlay: Overlay::None,
            pending: Vec::new(),
            request: 0,
            status: "? for help".to_owned(),
            quit: false,
        };
        app.conversations = core.conversations();
        app.pending = core.pending();
        app.reload(core);
        app
    }

    pub fn quit(&self) -> bool {
        self.quit
    }

    pub fn peer(&self) -> Option<UserId> {
        self.conversations.get(self.selected).map(|c| c.peer)
    }

    pub fn selected(&self) -> Option<&Conversation> {
        self.conversations.get(self.selected)
    }

    // -----------------------------------------------------------------------
    // Reading from the store
    // -----------------------------------------------------------------------

    /// The newest page of the selected conversation.
    fn reload(&mut self, core: &mut impl Core) {
        self.history = match self.peer() {
            Some(peer) => core.page(peer, None),
            None => Vec::new(),
        };
        self.scroll = 0;
        self.exhausted = self.history.is_empty();
        self.more_below = false;
    }

    /// One page older, if there is one.
    fn older(&mut self, core: &mut impl Core) {
        let (Some(peer), Some(oldest)) = (self.peer(), self.history.first()) else {
            return;
        };
        let before = Cursor {
            msg_seq: oldest.msg_seq,
            message_id: oldest.message_id,
        };
        let mut page = core.page(peer, Some(before));
        if page.is_empty() {
            self.exhausted = true;
            return;
        }
        page.append(&mut self.history);
        self.history = page;
    }

    // -----------------------------------------------------------------------
    // Notices from the core
    // -----------------------------------------------------------------------

    pub fn on_notice(&mut self, notice: Notice, core: &mut impl Core) {
        match notice {
            Notice::Changed(peer) if Some(peer) == self.peer() => {
                // F-22: follow the conversation only if the user is already at
                // the bottom. Scrolled up, the arrival is noted and the view
                // left exactly where it was — re-reading the newest page here
                // would also throw away the older pages under the cursor.
                if self.scroll == 0 {
                    self.reload(core);
                } else {
                    self.more_below = true;
                }
            }
            Notice::Changed(_) => {}
            Notice::Peers => self.refresh_peers(core),
            Notice::Requests => {
                self.pending = core.pending();
                self.request = self.request.min(self.pending.len().saturating_sub(1));
            }
        }
    }

    /// Re-reads the peer list, keeping the cursor on whoever it was on.
    fn refresh_peers(&mut self, core: &mut impl Core) {
        let was = self.peer();
        self.conversations = core.conversations();
        self.selected = was
            .and_then(|peer| self.conversations.iter().position(|c| c.peer == peer))
            .unwrap_or(0)
            .min(self.conversations.len().saturating_sub(1));
    }

    // -----------------------------------------------------------------------
    // Keys
    // -----------------------------------------------------------------------

    pub fn on_key(&mut self, key: KeyEvent, core: &mut impl Core) {
        // Windows reports press *and* release; acting on both types everything
        // twice.
        if key.kind == KeyEventKind::Release {
            return;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        if ctrl && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.overlay != Overlay::None {
            self.overlay_key(key, core);
            return;
        }

        match (key.code, ctrl) {
            (KeyCode::Tab, _) => self.switch(1, core),
            (KeyCode::BackTab, _) => self.switch(-1, core),

            (KeyCode::PageUp, _) => self.scroll_up(self.viewport, core),
            (KeyCode::PageDown, _) => self.scroll_down(self.viewport, core),
            (KeyCode::Up, true) => self.scroll_up(1, core),
            (KeyCode::Down, true) => self.scroll_down(1, core),
            (KeyCode::Home, _) => self.scroll_up(usize::MAX / 2, core),
            (KeyCode::End, _) => self.scroll_down(usize::MAX / 2, core),

            (KeyCode::Char('t'), true) => self.verify(core),
            (KeyCode::Char('p'), true) => self.overlay = Overlay::Profile(core.me()),
            (KeyCode::Char('r'), true) => {
                self.pending = core.pending();
                self.request = 0;
                self.overlay = Overlay::Requests;
            }

            // Enter sends; Shift-Enter is F-23's newline, and Alt-Enter is
            // the one that works. Most terminals do not report Shift with
            // Enter at all — the key arrives bare and sends the message —
            // which leaves multi-line input with no binding on them. Alt sets
            // the eighth bit or prefixes ESC, and is reported.
            (KeyCode::Enter, _)
                if key
                    .modifiers
                    .intersects(KeyModifiers::SHIFT | KeyModifiers::ALT) =>
            {
                self.input.insert_newline()
            }
            (KeyCode::Enter, _) => self.submit(core),

            // F-24 asks for `?`, which is also a character someone may want to
            // type. It opens help while the draft is empty and types itself
            // once there is something to type it into.
            (KeyCode::Char('?'), false) if self.draft().is_empty() => self.overlay = Overlay::Help,

            _ => {
                self.input.input(Input::from(key));
            }
        }
    }

    fn overlay_key(&mut self, key: KeyEvent, core: &mut impl Core) {
        let overlay = std::mem::replace(&mut self.overlay, Overlay::None);
        match (overlay, key.code) {
            // F-05: the only path from an invite to a connection, and it runs
            // after the fingerprint has been on screen.
            (Overlay::Invite(preview), KeyCode::Enter) => {
                core.connect(preview.peer);
                self.status = format!("connecting to {}", preview.peer.fingerprint());
                self.refresh_peers(core);
            }
            (Overlay::Requests, KeyCode::Char(c @ ('a' | 'r'))) => {
                if let Some(request) = self.pending.get(self.request) {
                    let accept = c == 'a';
                    core.decide(request.from, accept);
                    self.status = format!(
                        "{} {}",
                        if accept { "accepted" } else { "rejected" },
                        request.from.fingerprint()
                    );
                    self.pending = core.pending();
                    self.request = self.request.min(self.pending.len().saturating_sub(1));
                    self.refresh_peers(core);
                }
                if !self.pending.is_empty() {
                    self.overlay = Overlay::Requests;
                }
            }
            (Overlay::Requests, KeyCode::Up) => {
                self.request = self.request.saturating_sub(1);
                self.overlay = Overlay::Requests;
            }
            (Overlay::Requests, KeyCode::Down) => {
                self.request = (self.request + 1).min(self.pending.len().saturating_sub(1));
                self.overlay = Overlay::Requests;
            }
            // Escape closes whatever it was. Anything else is left alone, so a
            // stray key cannot dismiss a fingerprint the user is reading.
            (_, KeyCode::Esc) => {}
            (kept, _) => self.overlay = kept,
        }
    }

    fn draft(&self) -> String {
        self.input.lines().join("\n")
    }

    /// Enter. An invite is imported and previewed; anything else is a message.
    fn submit(&mut self, core: &mut impl Core) {
        let draft = self.draft();
        let text = draft.trim();
        if text.is_empty() {
            return;
        }

        if text.starts_with(INVITE_PREFIX) {
            match core.import(text) {
                Ok(preview) => {
                    self.input = textarea();
                    self.overlay = Overlay::Invite(preview);
                }
                Err(why) => self.overlay = Overlay::Error(why),
            }
            return;
        }

        let Some(peer) = self.peer() else {
            self.status = "no conversation selected".to_owned();
            return;
        };
        core.send(peer, text.to_owned());
        // F-18: it is stored either way, so the composer clears either way.
        // What changes is what the user is told — with no session the message
        // is on disk and not on its way, and the `.` beside it in the history
        // says so too.
        if self.state() != ConnState::Established {
            self.status = "not connected: the message is queued".to_owned();
        }
        self.input = textarea();
        self.reload(core);
    }

    fn verify(&mut self, core: &mut impl Core) {
        let Some(peer) = self.peer() else { return };
        core.verify(peer);
        self.status = format!("marked {} verified", peer.fingerprint());
        self.refresh_peers(core);
    }

    /// F-23: the draft belongs to the conversation, not to the input box.
    fn switch(&mut self, by: isize, core: &mut impl Core) {
        if self.conversations.len() < 2 {
            return;
        }
        if let Some(peer) = self.peer() {
            self.drafts.insert(peer, self.draft());
        }

        let count = self.conversations.len() as isize;
        self.selected = (self.selected as isize + by).rem_euclid(count) as usize;

        self.input = textarea();
        if let Some(draft) = self.peer().and_then(|peer| self.drafts.get(&peer)) {
            self.input.insert_str(draft.clone());
        }
        self.reload(core);
    }

    // -----------------------------------------------------------------------
    // Scrollback
    // -----------------------------------------------------------------------

    fn scroll_up(&mut self, rows: usize, core: &mut impl Core) {
        self.scroll = self.scroll.saturating_add(rows);

        // One page per pass until the loaded history can cover where the view
        // now is. Message count is a lower bound on display rows — a wrapped
        // message is more than one row, never fewer — so this may fetch a page
        // earlier than strictly needed and never later. The alternative is
        // wrapping the whole history here, at a width this function does not
        // know.
        while !self.exhausted && self.history.len() < self.scroll.saturating_add(self.viewport) {
            let before = self.history.len();
            self.older(core);
            if self.history.len() == before {
                break;
            }
        }
    }

    fn scroll_down(&mut self, rows: usize, core: &mut impl Core) {
        self.scroll = self.scroll.saturating_sub(rows);
        if self.scroll == 0 && self.more_below {
            // Back at the bottom, so catch up with what arrived while we were
            // not looking.
            self.reload(core);
        }
    }

    // -----------------------------------------------------------------------
    // What the view reads
    // -----------------------------------------------------------------------

    pub(crate) fn history(&self) -> &[Line] {
        &self.history
    }

    pub(crate) fn conversations(&self) -> &[Conversation] {
        &self.conversations
    }

    pub(crate) fn selected_index(&self) -> usize {
        self.selected
    }

    pub fn overlay_ref(&self) -> &Overlay {
        &self.overlay
    }

    pub(crate) fn pending_list(&self) -> (&[Pending], usize) {
        (&self.pending, self.request)
    }

    pub(crate) fn status_text(&self) -> &str {
        &self.status
    }

    pub(crate) fn more_below(&self) -> bool {
        self.more_below
    }

    pub(crate) fn input_widget(&self) -> &TextArea<'a> {
        &self.input
    }

    pub fn state(&self) -> ConnState {
        self.selected().map(|c| c.state).unwrap_or_default()
    }

    /// Clamps and reports the scroll offset, now that the draw knows how tall
    /// the pane is and how many rows the text wrapped to.
    pub(crate) fn clamp_scroll(&mut self, rows: usize, height: usize) -> usize {
        self.viewport = height.max(1);
        self.scroll = self.scroll.min(rows.saturating_sub(height));
        self.scroll
    }
}

fn textarea<'a>() -> TextArea<'a> {
    let mut input = TextArea::default();
    // The default underlines the line the cursor is on, which on a one-line
    // composer underlines everything the user types.
    input.set_cursor_line_style(ratatui::style::Style::default());
    input
}
