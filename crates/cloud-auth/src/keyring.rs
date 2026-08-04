use std::{fmt, fs, io, path::Path};

#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

pub fn load_signing_key(path: &Path) -> io::Result<SecretBytes> {
    let metadata = fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "signing key must not be accessible by group or others",
            ));
        }
    }
    let bytes = fs::read(path)?;
    if bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "signing key must contain exactly 32 bytes",
        ));
    }
    Ok(SecretBytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretBytes(vec![1, 2, 3]);
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[cfg(unix)]
    #[test]
    fn loader_rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("candy-cloud-key-{}", uuid::Uuid::new_v4()));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&[7u8; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_signing_key(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn loader_accepts_owner_only_ed25519_seed() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("candy-cloud-key-{}", uuid::Uuid::new_v4()));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&[9u8; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_signing_key(&path).unwrap().expose(), &[9u8; 32]);
        fs::remove_file(path).unwrap();
    }
}
