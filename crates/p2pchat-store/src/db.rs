//! Opening the database file — `architecture.md` §8.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::{schema, StoreError};

/// `~/.local/share/p2pchat/p2pchat.db` on Linux — F-17.
pub const FILE_NAME: &str = "p2pchat.db";

/// Group and other permissions, in any combination, disqualify the file.
const FORBIDDEN_BITS: u32 = 0o077;

/// Whether this platform can verify the database file's permissions.
///
/// False on Windows, for the same reason as the key file: the equivalent check
/// is an ACL walk, which needs a platform API crate that is not in
/// `techstack.md`. Message bodies are stored as plaintext (OD-1), so the caller
/// must say out loud that no check happened rather than let the user believe
/// one did.
pub const PERMISSIONS_ENFORCED: bool = cfg!(unix);

pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Opens (creating if absent) a database at `path`, applies the pragmas §8
/// requires, and migrates it to [`schema::SCHEMA_VERSION`].
///
/// Public because the actor is not the only reasonable caller: a test or a
/// one-shot tool wanting several statements in one transaction is better served
/// by the connection than by a channel.
pub fn open(path: &Path) -> Result<Connection, StoreError> {
    create_private(path)?;

    let mut conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    schema::migrate(&mut conn)?;
    Ok(conn)
}

/// The three pragmas §8 requires, applied to an open connection.
///
/// WAL so the scrollback reader is never blocked by the writer; NORMAL because
/// under WAL a crash then costs at most the tail of the last transaction, not
/// the database. All three are per-connection, which is why they are set here
/// and not in a migration.
///
/// Split out of [`open`] so that a test can force the opposite state and watch
/// this put it right, which is the only way to observe the `foreign_keys` line
/// at all: `libsqlite3-sys` compiles the bundled SQLite with
/// `-DSQLITE_DEFAULT_FOREIGN_KEYS=1`, so on a fresh connection they are already
/// on and deleting the line below changes nothing any behavioural test can see.
/// The guarantee would then rest on a dependency's build flag rather than on
/// this file, and would go quiet the day `bundled` is swapped for a system
/// SQLite.
pub(crate) fn apply_pragmas(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA synchronous = NORMAL;",
    )?;
    Ok(())
}

/// Creates the file with the right permissions from the moment it exists.
///
/// SQLite would create it itself, at 0666 minus the umask; fixing that
/// afterwards leaves a window in which the file is readable. An empty file is a
/// valid empty database, so pre-creating one costs nothing. Same approach as
/// `p2pchat_crypto::keystore::save`, and the same reason.
fn create_private(path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|source| io_err(parent, source))?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => check_permissions(path),
        Err(source) => Err(io_err(path, source)),
    }
}

/// `true` if a Unix mode denies all access to group and other.
pub(crate) fn mode_is_private(mode: u32) -> bool {
    mode & FORBIDDEN_BITS == 0
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).map_err(|source| io_err(path, source))?;
    let mode = metadata.permissions().mode() & 0o7777;
    if mode_is_private(mode) {
        Ok(())
    } else {
        Err(StoreError::FilePermissions {
            path: path.to_path_buf(),
            mode,
        })
    }
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), StoreError> {
    // See PERMISSIONS_ENFORCED. The caller warns; this is not a silent pass.
    Ok(())
}

fn io_err(path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_owner_only_modes_are_private() {
        assert!(mode_is_private(0o600));
        for mode in [0o644, 0o660, 0o606, 0o666, 0o777] {
            assert!(!mode_is_private(mode), "{mode:o} should be rejected");
        }
    }

    fn pragma<T: rusqlite::types::FromSql>(conn: &Connection, name: &str) -> T {
        conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
            .unwrap()
    }

    fn assert_section_8_pragmas(conn: &Connection) {
        assert_eq!(pragma::<String>(conn, "journal_mode"), "wal");
        assert_eq!(
            pragma::<i64>(conn, "foreign_keys"),
            1,
            "foreign_keys is off"
        );
        assert_eq!(
            pragma::<i64>(conn, "synchronous"),
            1,
            "synchronous is not NORMAL"
        );
    }

    /// The three pragmas §8 names, read back from the connection that is
    /// actually going to be used.
    #[test]
    fn the_pragmas_are_set() {
        let dir = tempfile::tempdir().unwrap();
        assert_section_8_pragmas(&open(&db_path(dir.path())).unwrap());
    }

    /// The test above passes with `PRAGMA foreign_keys = ON` deleted, because
    /// the bundled SQLite defaults it on — see `apply_pragmas`. Starting from
    /// the opposite state is what makes each line observable: whichever one is
    /// dropped, the adverse setting survives and this fails.
    #[test]
    fn each_pragma_is_applied_over_its_opposite() {
        let dir = tempfile::tempdir().unwrap();
        let path = db_path(dir.path());
        drop(open(&path).unwrap());

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA foreign_keys = OFF;
             PRAGMA synchronous = FULL;",
        )
        .unwrap();
        assert_eq!(
            pragma::<i64>(&conn, "foreign_keys"),
            0,
            "the adverse state did not take, so this test proves nothing"
        );

        apply_pragmas(&conn).unwrap();
        assert_section_8_pragmas(&conn);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_database_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = db_path(dir.path());
        drop(open(&path).unwrap());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = open(&path).unwrap_err();
        assert!(
            matches!(err, StoreError::FilePermissions { mode: 0o644, .. }),
            "{err:?}"
        );
    }
}
