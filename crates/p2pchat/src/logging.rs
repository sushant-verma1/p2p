//! File-only logging.
//!
//! Nothing in this process may write to stdout or stderr: the TUI owns the
//! terminal, and a stray line corrupts the display. Logs go to a daily-rotated
//! file under the platform data directory (`~/.local/share/p2pchat` on Linux),
//! at the level given by `RUST_LOG`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Overrides the data directory. Exists so tests can point the log somewhere
/// disposable; `directories` resolves platform paths that no env var reaches.
pub const DATA_DIR_ENV: &str = "P2PCHAT_DATA_DIR";

const LOG_PREFIX: &str = "p2pchat";
const LOG_SUFFIX: &str = "log";

pub fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(DATA_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    Ok(ProjectDirs::from("", "", "p2pchat")
        .context("no home directory for the platform data path")?
        .data_dir()
        .to_path_buf())
}

/// Installs the global subscriber.
///
/// The returned guard flushes the non-blocking writer when dropped; hold it for
/// the lifetime of the process or the tail of the log is lost.
pub fn init() -> Result<WorkerGuard> {
    let dir = data_dir()?;
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
