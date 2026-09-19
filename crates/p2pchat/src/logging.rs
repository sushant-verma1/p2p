//! File-only logging.
//!
//! Nothing in this process may write to stdout or stderr outside a CLI
//! subcommand's own output: the TUI owns the terminal, and a stray line
//! corrupts the display. Logs go to a daily-rotated file under the data
//! directory, at the level given by `RUST_LOG`.

use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

const LOG_PREFIX: &str = "p2pchat";
const LOG_SUFFIX: &str = "log";

/// Installs the global subscriber.
///
/// The returned guard flushes the non-blocking writer when dropped; hold it for
/// the lifetime of the process or the tail of the log is lost.
pub fn init() -> Result<WorkerGuard> {
    let dir = crate::paths::data_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create log directory {}", dir.display()))?;

    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(LOG_PREFIX)
        .filename_suffix(LOG_SUFFIX)
        .build(&dir)
        .with_context(|| format!("open log file in {}", dir.display()))?;
    let (writer, guard) = tracing_appender::non_blocking(appender);

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(writer)
        .init();

    Ok(guard)
}
