//! ratatui rendering and input.
//!
//! Nothing in the workspace depends on this crate except the binary — see
//! `architecture.md` §2. It reaches the rest of the application through
//! [`Core`], a trait the binary implements over channels, and hears about
//! changes through [`Notice`], which carries no payload.
//!
//! [`run`] blocks the thread it is called on. That thread is a plain OS
//! thread, never a tokio task: `crossterm`'s reader blocks, and a blocking
//! read on a runtime thread starves everything sharing it.

#![forbid(unsafe_code)]

use std::io;
use std::time::Duration;

use ratatui::crossterm::event::{self, Event};
use ratatui::prelude::CrosstermBackend;
use ratatui::Terminal;
use thiserror::Error;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::Receiver;

pub mod app;
pub mod model;
pub mod terminal;
pub mod view;

pub use app::{App, Overlay};
pub use model::{ConnState, Conversation, Core, Cursor, Line, Notice, Pending, Preview};

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal I/O failed")]
    Terminal(#[source] std::io::Error),

    #[error(transparent)]
    Core(#[from] p2pchat_core::CoreError),
}

impl From<io::Error> for TuiError {
    fn from(error: io::Error) -> Self {
        TuiError::Terminal(error)
    }
}

/// Set to any value, the next keystroke panics.
///
/// M9's gate asks for proof that a *deliberate* panic leaves the terminal
/// usable, and the only honest way to show it is to panic the shipped binary
/// on a real pty — a panic staged anywhere else proves that the staging
/// restores the terminal. Nothing reads this unless someone set it.
const PANIC_ON_KEY: &str = "P2PCHAT_PANIC_ON_KEY";

/// How long a pass waits for a key before going round again. It is not a frame
/// rate: the screen is redrawn when something changed, and this only bounds
/// how long a notice can sit unnoticed.
const TICK: Duration = Duration::from_millis(50);

/// Draws until the user quits.
pub fn run(core: &mut impl Core, notices: &mut Receiver<Notice>) -> Result<(), TuiError> {
    // First, so it is dropped last: the terminal is restored after the
    // backend has stopped writing to it.
    let _guard = terminal::Guard::new()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut app = App::new(core);

    terminal.draw(|frame| view::draw(frame, &mut app))?;
    while !app.quit() {
        let mut dirty = false;

        if event::poll(TICK)? {
            match event::read()? {
                Event::Key(key) => {
                    assert!(
                        std::env::var_os(PANIC_ON_KEY).is_none(),
                        "deliberate panic: {PANIC_ON_KEY} is set"
                    );
                    app.on_key(key, core);
                    dirty = true;
                }
                // ratatui rebuilds the buffer from the new size on the next
                // draw; there is nothing to recompute here.
                Event::Resize(..) => dirty = true,
                _ => {}
            }
        }

        loop {
            match notices.try_recv() {
                Ok(notice) => {
                    app.on_notice(notice, core);
                    dirty = true;
                }
                Err(TryRecvError::Empty) => break,
                // The core is gone. Staying up would show a screen that can
                // never change again.
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        if dirty {
            terminal.draw(|frame| view::draw(frame, &mut app))?;
        }
    }
    Ok(())
}
