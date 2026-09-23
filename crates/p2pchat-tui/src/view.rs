//! Drawing. Reads the app, writes the frame, decides nothing.
//!
//! The layout is fixed rather than configurable because F-21 asks for one
//! layout that works at 80x24: a status bar, a conversation list, the history,
//! and the composer. Every pane is sized in [`Constraint`]s, so a resize is
//! arithmetic rather than a special case.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line as TextLine, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::Frame;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use p2pchat_core::wire::DeliveryStatus;

use crate::app::{App, Overlay};
use crate::model::Conversation;

/// Wide enough for a fingerprint plus its marker at 80 columns, and the rest
/// goes to the history.
const LIST_WIDTH: u16 = 24;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status bar
            Constraint::Min(1),    // list + history
            Constraint::Length(3), // composer
        ])
        .split(area);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(LIST_WIDTH), Constraint::Min(1)])
        .split(rows[1]);

    status_bar(frame, app, rows[0]);
    conversation_list(frame, app, middle[0]);
    history(frame, app, middle[1]);
    composer(frame, app, rows[2]);

    match app.overlay_ref().clone() {
        Overlay::None => {}
        Overlay::Help => overlay(frame, area, "help", help_text()),
        Overlay::Profile(me) => {
            let lines = vec![
                TextLine::from(vec![
                    Span::raw("  fingerprint  "),
                    Span::styled(
                        me.fingerprint(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
                // On its own line: after the label, 64 hex chars overflow a
                // popup at 80 columns and the tail is clipped.
                TextLine::from("  id"),
                TextLine::from(format!("  {}", me.to_hex())),
                TextLine::from(""),
                TextLine::from("read the fingerprint to the person you gave your invite to."),
                TextLine::from("if theirs differs, the invite was swapped. Esc closes."),
            ];
            overlay(frame, area, "you", lines);
        }
        Overlay::Requests => {
            let (pending, selected) = app.pending_list();
            let mut lines = vec![TextLine::from(
                "up/down to choose, a to accept, r to reject, Esc to close",
            )];
            if pending.is_empty() {
                lines.push(TextLine::from(""));
                lines.push(TextLine::from("nothing waiting"));
            }
            for (i, request) in pending.iter().enumerate() {
                let marker = if i == selected { ">" } else { " " };
                // F-06: the fingerprint, always. The name is the caller's own
                // claim and is shown beside it, never instead of it.
                lines.push(TextLine::from(format!(
                    "{marker} {}  {}",
                    request.from.fingerprint(),
                    request.display_name
                )));
                lines.push(TextLine::from(format!("    id {}", request.from.to_hex())));
            }
            overlay(frame, area, "connection requests", lines);
        }
        Overlay::Invite(preview) => {
            // F-05. Nothing has been dialled at the point this is drawn.
            let lines = vec![
                TextLine::from("this invite claims to be:"),
                TextLine::from(""),
                TextLine::from(vec![
                    Span::raw("  fingerprint  "),
                    Span::styled(
                        preview.peer.fingerprint(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
                TextLine::from(format!("  name         {}", preview.display_name)),
                TextLine::from(format!("  id           {}", preview.peer.to_hex())),
                TextLine::from(format!("  addresses    {}", preview.addrs)),
                TextLine::from(""),
                TextLine::from("compare the fingerprint with the person who sent it."),
                TextLine::from("Enter connects, Esc cancels. Nothing is connected yet."),
            ];
            overlay(frame, area, "invite", lines);
        }
        Overlay::Error(why) => overlay(
            frame,
            area,
            "that did not work",
            vec![TextLine::from(why), TextLine::from("Esc closes")],
        ),
    }
}

// ---------------------------------------------------------------------------
// Panes
// ---------------------------------------------------------------------------

fn status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let (pending, _) = app.pending_list();
    let mut spans = vec![
        Span::styled(" p2pchat ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("[{}] ", app.state().label())),
    ];

    // F-07: a badge, not a pop-up. It says how many and which key opens them.
    if !pending.is_empty() {
        spans.push(Span::styled(
            format!("[{} pending ^R] ", pending.len()),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if app.more_below() {
        spans.push(Span::styled(
            "[new below] ",
            Style::default().fg(Color::Yellow),
        ));
    }
    spans.push(Span::raw(app.status_text().to_owned()));

    frame.render_widget(
        Paragraph::new(TextLine::from(spans)).style(Style::default().bg(Color::Indexed(236))),
        area,
    );
}

fn conversation_list(frame: &mut Frame, app: &App, area: Rect) {
    let selected = app.selected_index();
    let items: Vec<ListItem> = app
        .conversations()
        .iter()
        .enumerate()
        .map(|(i, conversation)| {
            let mark = if i == selected { ">" } else { " " };
            // F-02: an unverified peer is marked everywhere it is named.
            let flag = if conversation.verified { " " } else { "!" };
            let style = if i == selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            ListItem::new(TextLine::from(vec![
                Span::raw(format!("{mark}{flag}")),
                Span::styled(conversation.title(), style),
            ]))
        })
        .collect();

    let items = if items.is_empty() {
        vec![ListItem::new("no peers yet")]
    } else {
        items
    };

    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title("peers")),
        area,
    );
}

fn history(frame: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(header(app.selected()));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let width = inner.width.max(1) as usize;
    let them = app
        .selected()
        .map(|c| shorten(&c.title(), 8))
        .unwrap_or_else(|| "them".to_owned());

    let mut rows: Vec<String> = Vec::new();
    for line in app.history() {
        let who = if line.mine {
            "me".to_owned()
        } else {
            them.clone()
        };
        let glyph = if line.mine { glyph(line.status) } else { ' ' };
        rows.extend(wrap(&format!("{who}{glyph} {}", line.body), width));
    }
    // M12: why it failed, under the history where the next message would go,
    // wrapped like one — it is long, and it is the thing to read.
    if let Some(why) = app.selected().and_then(|c| c.failure.as_ref()) {
        rows.extend(wrap(&format!("! {why}"), width));
    }

    let height = inner.height as usize;
    let scroll = app.clamp_scroll(rows.len(), height);
    let end = rows.len().saturating_sub(scroll);
    let start = end.saturating_sub(height);

    let text: Vec<TextLine> = rows[start..end]
        .iter()
        .map(|row| TextLine::from(row.clone()))
        .collect();
    frame.render_widget(Paragraph::new(text), inner);
}

/// F-02: the peer's fingerprint in the conversation header, and whether the
/// user has ever checked it.
fn header(conversation: Option<&Conversation>) -> String {
    match conversation {
        None => "no conversation".to_owned(),
        Some(c) => {
            let mark = if c.verified { "verified" } else { "unverified" };
            format!("{} - {} - {mark}", c.title(), c.peer.fingerprint())
        }
    }
}

fn composer(frame: &mut Frame, app: &App, area: Rect) {
    let mut widget = app.input_widget().clone();
    widget.set_block(
        Block::default()
            .borders(Borders::ALL)
            .title("message - Enter sends, ? for help"),
    );
    frame.render_widget(&widget, area);
}

// ---------------------------------------------------------------------------
// Overlays
// ---------------------------------------------------------------------------

fn overlay(frame: &mut Frame, area: Rect, title: &str, lines: Vec<TextLine<'static>>) {
    let height = (lines.len() as u16 + 2).min(area.height);
    let width = area.width.saturating_sub(4).clamp(1, 72);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    // Without this the pane underneath shows through the gaps.
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_owned()),
        ),
        popup,
    );
}

fn help_text() -> Vec<TextLine<'static>> {
    [
        "Tab / Shift-Tab    next / previous conversation",
        "Enter              send      (Alt-Enter or Shift-Enter: newline)",
        "PgUp / PgDn        scroll    (Home / End: the ends)",
        "Ctrl-P             your own fingerprint and full ID",
        "Ctrl-T             mark the selected peer verified",
        "Ctrl-R             connection requests: a accept, r reject",
        "Ctrl-C             quit",
        "?                  this help, on an empty input. Esc closes.",
        "",
        "paste an invite into the input and press Enter: its fingerprint",
        "is shown before anything is connected.",
        "",
        "sent messages:  . queued   > sent   v delivered   V read   ! failed",
    ]
    .into_iter()
    .map(TextLine::from)
    .collect()
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

fn glyph(status: DeliveryStatus) -> char {
    match status {
        DeliveryStatus::Pending => '.',
        DeliveryStatus::Sent => '>',
        DeliveryStatus::Delivered => 'v',
        DeliveryStatus::Read => 'V',
        DeliveryStatus::Failed => '!',
    }
}

/// The longest prefix of `text` that fits in `width` columns.
///
/// Columns, not chars: a name of four emoji is eight columns wide, and cutting
/// it after four chars leaves a prefix twice as wide as the caller asked for.
fn shorten(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut len = 0;
    for c in text.chars() {
        let c_width = c.width().unwrap_or(0);
        if len + c_width > width {
            break;
        }
        out.push(c);
        len += c_width;
    }
    out
}

/// Breaks `text` into rows no wider than `width` columns, at spaces where it
/// can and mid-word where it cannot.
///
/// Columns, not chars. An emoji is two columns and a combining mark is none,
/// so counting chars would wrap an emoji-heavy line a screenful early and a
/// Devanagari one late — the second case past the border. `unicode-width`
/// answers the only question this needs: how many cells does a char take.
///
/// Still not a Unicode line-breaking algorithm — it breaks at spaces, not at
/// break opportunities, so a CJK run with no spaces in it is broken by the
/// pane edge rather than between words. Chat bodies are short and this is a
/// terminal. One row can exceed `width` by a column: a two-column char in a
/// one-column pane, where there is no row it would fit on and ratatui clips.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut rows = Vec::new();
    for paragraph in text.split('\n') {
        let mut row = String::new();
        let mut len = 0;
        for word in paragraph.split(' ') {
            let word_len = word.width();
            if len > 0 && len + 1 + word_len > width {
                rows.push(std::mem::take(&mut row));
                len = 0;
            }
            if word_len > width {
                // Longer than the pane: break it wherever the edge falls.
                for c in word.chars() {
                    let c_width = c.width().unwrap_or(0);
                    // A zero-width char is a mark on the one before it.
                    // Starting a row with one would split the cluster across
                    // two rows and render it as a stray mark on the second.
                    if c_width > 0 && len > 0 && len + c_width > width {
                        rows.push(std::mem::take(&mut row));
                        len = 0;
                    }
                    row.push(c);
                    len += c_width;
                }
                continue;
            }
            if len > 0 {
                row.push(' ');
                len += 1;
            }
            row.push_str(word);
            len += word_len;
        }
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_never_exceeds_the_width() {
        let text = "the quick brown fox jumps over the lazy dog and keeps going";
        for width in [1, 5, 12, 40] {
            for row in wrap(text, width) {
                assert!(
                    row.chars().count() <= width,
                    "{row:?} is wider than {width}"
                );
            }
        }
    }

    #[test]
    fn wrapping_keeps_every_word() {
        let rows = wrap("one two three", 7);
        assert_eq!(rows.join(" ").split_whitespace().count(), 3);
    }

    #[test]
    fn a_word_longer_than_the_pane_is_broken_rather_than_dropped() {
        let rows = wrap("aaaaaaaaaa", 4);
        assert_eq!(rows, vec!["aaaa", "aaaa", "aa"]);
    }

    /// An emoji is two columns wide. Counting chars puts twice as many on a
    /// row as the pane has cells, and the overflow lands on the border.
    #[test]
    fn emoji_wrap_at_the_column_not_at_the_char() {
        // Ten emoji: ten chars, twenty columns, in a pane ten columns wide.
        let rows = wrap(&"\u{1f600}".repeat(10), 10);

        assert_eq!(rows.len(), 2, "twenty columns is two rows of ten: {rows:?}");
        for row in &rows {
            assert_eq!(row.width(), 10, "{row:?} is not ten columns");
            assert_eq!(row.chars().count(), 5, "{row:?} is not five emoji");
        }
        assert_eq!(rows.concat().chars().count(), 10, "an emoji was dropped");
    }

    /// Emoji in words, broken at the spaces rather than mid-word.
    #[test]
    fn a_line_of_emoji_words_never_overflows_the_pane() {
        let text = "\u{1f600}\u{1f600} \u{1f680}\u{1f680}\u{1f680} ok \u{1f9ea}\u{1f9ea}";
        for width in [4, 6, 9, 20] {
            for row in wrap(text, width) {
                assert!(row.width() <= width, "{row:?} is wider than {width}");
            }
        }
    }

    /// Devanagari, including a conjunct. The virama and the vowel signs are
    /// zero-width marks on the consonant before them, so a char count reads
    /// this as nearly twice as wide as it is and wraps early — and a break
    /// between a consonant and its mark renders as a stray mark on the next
    /// row.
    #[test]
    fn devanagari_wraps_on_columns_and_never_splits_a_mark_from_its_base() {
        // परीक्षा, where क्ष is the conjunct: seven chars, fewer columns.
        let word = "\u{92a}\u{930}\u{940}\u{915}\u{94d}\u{937}\u{93e}";
        let columns = word.width();
        assert_eq!(word.chars().count(), 7);
        assert!(
            columns < 7,
            "the virama is a zero-width mark, so this is under seven columns"
        );

        // In a pane exactly its own width it stays whole. This is the
        // assertion a char count fails: by chars the word is wider than the
        // pane, so it goes down the mid-word path and comes apart.
        assert_eq!(
            wrap(word, columns),
            vec![word],
            "wrapped at the wrong column"
        );

        // One more column is still not room for two of them and a space.
        let rows = wrap(&format!("{word} {word}"), columns + 1);
        assert_eq!(rows, vec![word, word], "wrapped at the wrong column");

        // Nothing here has a space in it, so every row is a mid-word break.
        for width in 1..=7 {
            let rows = wrap(&word.repeat(3), width);
            for row in &rows {
                assert!(row.width() <= width, "{row:?} is wider than {width}");
                let first = row.chars().next().expect("no empty rows");
                assert_ne!(
                    first.width().unwrap_or(0),
                    0,
                    "{row:?} starts with a mark torn off the char before it"
                );
            }
            assert_eq!(
                rows.concat(),
                word.repeat(3),
                "breaking the word changed it"
            );
        }
    }

    #[test]
    fn truncation_counts_columns_too() {
        assert_eq!(
            shorten("\u{1f600}\u{1f600}\u{1f600}\u{1f600}", 4).width(),
            4
        );
        assert_eq!(shorten("abcdefgh", 4), "abcd");
    }
}
