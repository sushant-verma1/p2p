//! Loading and saving the identity key — `architecture.md` §4.
//!
//! The file holds the raw 32-byte Ed25519 seed and nothing else. It is not
//! encrypted (OD-2, resolved in `project.md` §5), so its permissions are the
//! only thing protecting it and they are checked on every load.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::{
    identity::{Identity, SEED_LEN},
    CryptoError,
};

/// Group and other permissions, in any combination, disqualify the key file.
const FORBIDDEN_BITS: u32 = 0o077;

/// Whether this platform can verify the key file's permissions.
///
/// False on Windows: the equivalent check is an ACL walk, which needs a
/// platform API crate that is not in `techstack.md`. The caller must say so out
/// loud rather than let the user believe a check happened — OD-2.
pub const PERMISSIONS_ENFORCED: bool = cfg!(unix);

/// `true` if a Unix mode denies all access to group and other.
pub fn mode_is_private(mode: u32) -> bool {
    mode & FORBIDDEN_BITS == 0
}

/// Loads the identity, generating and saving one on first launch.
pub fn load_or_create(path: &Path) -> Result<Identity, CryptoError> {
    match load(path) {
        Err(CryptoError::KeyFileIo { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            let identity = Identity::generate();
            save(path, &identity)?;
            Ok(identity)
        }
        other => other,
    }
}

pub fn load(path: &Path) -> Result<Identity, CryptoError> {
    let metadata = std::fs::metadata(path).map_err(|source| io_err(path, source))?;
    check_permissions(path, &metadata)?;

    let seed = Zeroizing::new(std::fs::read(path).map_err(|source| io_err(path, source))?);
    let seed: Zeroizing<[u8; SEED_LEN]> = Zeroizing::new(seed.as_slice().try_into().map_err(
        |_| CryptoError::MalformedKeyFile {
            path: path.to_path_buf(),
            found: seed.len(),
        },
    )?);

    Ok(Identity::from_seed(&seed))
}

/// Writes the seed with the right permissions from the moment the file exists —
/// creating it world-readable and fixing it afterwards leaves a window.
pub fn save(path: &Path, identity: &Identity) -> Result<(), CryptoError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| io_err(parent, source))?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    use std::io::Write;
    let mut file = options.open(path).map_err(|source| io_err(path, source))?;
    file.write_all(identity.seed().as_slice())
        .map_err(|source| io_err(path, source))?;
    file.sync_all().map_err(|source| io_err(path, source))
}

#[cfg(unix)]
fn check_permissions(path: &Path, metadata: &std::fs::Metadata) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o7777;
    if mode_is_private(mode) {
        Ok(())
    } else {
        Err(CryptoError::KeyFilePermissions {
            path: path.to_path_buf(),
            mode,
        })
    }
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _metadata: &std::fs::Metadata) -> Result<(), CryptoError> {
    // See PERMISSIONS_ENFORCED. The caller warns; this is not a silent pass.
    Ok(())
}

fn io_err(path: &Path, source: std::io::Error) -> CryptoError {
    CryptoError::KeyFileIo {
        path: path.to_path_buf(),
        source,
    }
}

/// Where the keystore lives, given a config directory.
pub fn key_path(config_dir: &Path) -> PathBuf {
    config_dir.join("identity.key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_owner_only_modes_are_private() {
        assert!(mode_is_private(0o600));
        assert!(mode_is_private(0o400));
        for mode in [0o644, 0o660, 0o606, 0o666, 0o601, 0o610, 0o777] {
            assert!(!mode_is_private(mode), "{mode:o} should be rejected");
        }
    }

    #[test]
    fn first_launch_creates_and_second_launch_loads_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());

        let first = load_or_create(&path).unwrap();
        assert!(path.exists());
        let second = load_or_create(&path).unwrap();

        assert_eq!(first.user_id(), second.user_id());
        assert_eq!(first.identity_pk(), second.identity_pk());
    }

    #[test]
    fn the_key_file_is_exactly_the_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());
        load_or_create(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), SEED_LEN as u64);
    }

    /// Writes a key file the permission check will accept, so that tests of
    /// other failures are not shadowed by it.
    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn a_truncated_key_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());
        write_private(&path, &[7u8; 16]);

        let err = load(&path).unwrap_err();
        assert!(
            matches!(err, CryptoError::MalformedKeyFile { found: 16, .. }),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());
        load_or_create(&path).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = load(&path).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyFilePermissions { mode: 0o644, .. }),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_created_key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());
        load_or_create(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "created with mode {mode:o}");
    }
}
