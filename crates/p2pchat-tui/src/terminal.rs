//! Putting the terminal into raw mode, and — the part that matters — getting
//! it back out.
//!
//! A terminal left in raw mode on the alternate screen with the cursor hidden
//! is a shell the user has to `reset` blind. So restoring is tied to a guard's
//! lifetime rather than to a line at the end of `run`: the only way to skip it
//! is to leak the guard. The panic hook lives here for the same reason — F-24
//! wants the terminal back *before* the panic message is printed, and a hook
//! installed somewhere else is a hook someone can forget to install.

use std::io::{self, Write};
use std::panic::PanicHookInfo;
use std::sync::Arc;

use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

/// Undoes what [`Guard::new`] did, on any writer.
///
/// Generic over the writer so a test can hand it a `Vec<u8>` and read back the
/// sequences a real terminal would have been sent.
pub fn restore(out: &mut impl Write) -> io::Result<()> {
    // Raw mode is process-wide, not a property of `out`; a test passing a
    // buffer was never in raw mode and the error is not interesting.
    let _ = disable_raw_mode();
    execute!(out, LeaveAlternateScreen, Show)
}

/// Owns the terminal's raw/alternate-screen state and the panic hook.
pub struct Guard {
    restore: Arc<dyn Fn() + Send + Sync>,
    previous: Arc<dyn Fn(&PanicHookInfo<'_>) + Send + Sync>,
}

impl Guard {
    /// Takes the real terminal: raw mode, alternate screen, panic hook.
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self::with(|| {
            let _ = restore(&mut io::stdout());
        }))
    }

    /// The same guard around an arbitrary restore action, which is how the
    /// gate tests reach this code without a terminal to break.
    pub fn with(restore: impl Fn() + Send + Sync + 'static) -> Self {
        let restore: Arc<dyn Fn() + Send + Sync> = Arc::new(restore);

        let previous: Arc<dyn Fn(&PanicHookInfo<'_>) + Send + Sync> =
            Arc::from(std::panic::take_hook());
        let hook = (Arc::clone(&restore), Arc::clone(&previous));
        std::panic::set_hook(Box::new(move |info| {
            // Terminal first: the default hook's message is unreadable on the
            // alternate screen, and it goes with the screen when it is torn
            // down.
            (hook.0)();
            (hook.1)(info);
        }));

        Guard { restore, previous }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        (self.restore)();
        // Not while unwinding: `set_hook` refuses on a panicking thread, and a
        // panic in a destructor during cleanup aborts the process. The hook is
        // about to become irrelevant anyway.
        if !std::thread::panicking() {
            let previous = Arc::clone(&self.previous);
            std::panic::set_hook(Box::new(move |info| previous(info)));
        }
    }
}
