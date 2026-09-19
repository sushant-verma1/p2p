#![forbid(unsafe_code)]

mod logging;
mod paths;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use p2pchat_crypto::keystore;

#[derive(Parser)]
#[command(version, about = "Decentralized peer-to-peer terminal chat")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Print this node's user ID and fingerprint.
    Whoami,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Held until the process exits so the appender flushes.
    let _log_guard = logging::init().context("initialise logging")?;

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "p2pchat starting");

    match cli.command {
        Some(Command::Whoami) => whoami(),
        // The TUI arrives in M9. Until then the default invocation is silent,
        // which is also what the M0 gate asserts.
        None => Ok(()),
    }
}

/// The one place allowed to write to stdout: a CLI subcommand whose entire
/// purpose is to print a value the user has to read and compare. The TUI is not
/// running, so there is no display to corrupt.
fn whoami() -> Result<()> {
    let path = keystore::key_path(&paths::config_dir()?);
    let identity = keystore::load_or_create(&path)?;

    tracing::info!(user = %identity.user_id(), "loaded identity");

    println!("user id     {}", identity.user_id().to_hex());
    println!("fingerprint {}", identity.user_id());

    if !keystore::PERMISSIONS_ENFORCED {
        tracing::warn!(
            path = %path.display(),
            "key file permissions are not verified on this platform"
        );
        println!(
            "warning     key file permissions are not verified on this platform; \
             {} is protected only by the account it lives under",
            path.display()
        );
    }

    Ok(())
}
