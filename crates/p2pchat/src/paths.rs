//! Config and data directories, and the environment overrides for them.
//!
//! `directories` resolves platform paths that no environment variable reaches,
//! so the overrides have to be ours. They are not a convenience: from M3 the
//! integration tests run two nodes on one machine. See `techstack.md`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;

pub const CONFIG_DIR_ENV: &str = "P2PCHAT_CONFIG_DIR";
pub const DATA_DIR_ENV: &str = "P2PCHAT_DATA_DIR";

/// Holds `identity.key`. `~/.config/p2pchat` on Linux.
pub fn config_dir() -> Result<PathBuf> {
    resolve(CONFIG_DIR_ENV, |dirs| dirs.config_dir().to_path_buf())
}

/// Holds the log and the database. `~/.local/share/p2pchat` on Linux.
pub fn data_dir() -> Result<PathBuf> {
    resolve(DATA_DIR_ENV, |dirs| dirs.data_dir().to_path_buf())
}

fn resolve(env: &str, default: impl FnOnce(&ProjectDirs) -> PathBuf) -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(env) {
        return Ok(PathBuf::from(dir));
    }
    let dirs =
        ProjectDirs::from("", "", "p2pchat").context("no home directory for the platform paths")?;
    Ok(default(&dirs))
}
