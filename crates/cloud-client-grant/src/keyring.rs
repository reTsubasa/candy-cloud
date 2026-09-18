//! Signing-key loading for the terminal Client Grant trust domain.
//!
//! Terminal grants intentionally do **not** reuse the Node Grant signing key, so
//! this loader mirrors the Cloud key-file convention (32-byte Ed25519 seed, owner
//! readable only) inside the crate that owns the terminal wire contract.

use std::{fs, io, path::Path};

/// Loads a 32-byte Ed25519 seed from a deployment-private file.
///
/// On Unix the file must not be group- or world-accessible, matching every other
/// Cloud signing key so a misconfigured secret cannot silently become readable.
pub fn load_signing_seed(path: &Path) -> io::Result<[u8; 32]> {
    let metadata = fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client grant signing key must not be accessible by group or others",
            ));
        }
    }
    let bytes = fs::read(path)?;
    bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "client grant signing key must contain exactly 32 bytes",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn seed_file(seed: &[u8], mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "candy-client-grant-key-{}",
            uuid::Uuid::new_v4()
        ));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(seed).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn loader_accepts_owner_only_seed_and_rejects_shared_permissions() {
        let path = seed_file(&[9_u8; 32], 0o600);
        assert_eq!(load_signing_seed(&path).unwrap(), [9_u8; 32]);
        fs::remove_file(&path).unwrap();

        let path = seed_file(&[9_u8; 32], 0o644);
        assert_eq!(
            load_signing_seed(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn loader_rejects_wrong_seed_length() {
        let path = seed_file(&[1_u8; 31], 0o600);
        assert_eq!(
            load_signing_seed(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_file(&path).unwrap();
    }
}
