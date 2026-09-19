#![forbid(unsafe_code)]

mod logging;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    // Held until the process exits so the appender flushes.
    let _log_guard = logging::init().context("initialise logging")?;

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "p2pchat starting");

    Ok(())
}
