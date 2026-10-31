//! Opaque objects in a caller-chosen directory.
//!
//! Each id is a 32-byte value. The file name is its lowercase hex encoding,
//! 64 characters, so the id's own bytes never become path separators.
//! Writes use [`std::fs::write`]. This module does not claim that a crash
//! leaves a complete object, and it does not claim an atomic replace.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::{PutOutcome, StoreError, immutable_put_decision};

/// Directory of opaque objects. Not a durable vault and not a cloud provider.
#[derive(Debug, Clone)]
pub struct TempDirStore {
    root: PathBuf,
}

impl TempDirStore {
    /// Use `root` as the directory. It is created if it is missing.
    pub fn create(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|_| StoreError::Io)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Store opaque bytes. An identical retry returns [`PutOutcome::IdenticalRetry`]
    /// and leaves the file unchanged. Different bytes at the same id are rejected.
    pub fn put_immutable(
        &self,
        object_id: [u8; 32],
        bytes: &[u8],
    ) -> Result<PutOutcome, StoreError> {
        let path = self.path_for(&object_id);
        match fs::read(&path) {
            Ok(existing) => immutable_put_decision(Some(&existing), bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                fs::write(&path, bytes).map_err(|_| StoreError::Io)?;
                Ok(PutOutcome::Created)
            }
            Err(_) => Err(StoreError::Io),
        }
    }

    /// Read one object. `Ok(None)` means the id is absent.
    pub fn get(&self, object_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        match fs::read(self.path_for(object_id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StoreError::Io),
        }
    }

    fn path_for(&self, object_id: &[u8; 32]) -> PathBuf {
        self.root.join(hex_name(object_id))
    }
}

fn hex_name(object_id: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(64);
    for byte in object_id {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "eidoron-m6-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            Self { path }
        }

        fn store(&self) -> TempDirStore {
            TempDirStore::create(&self.path).expect("scratch directory")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn identical_retry_keeps_the_first_bytes() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let id = [0x2f; 32];
        assert_eq!(store.get(&id).expect("get missing"), None);
        assert_eq!(
            store.put_immutable(id, b"synthetic-a").expect("create"),
            PutOutcome::Created
        );
        assert_eq!(
            store.put_immutable(id, b"synthetic-a").expect("retry"),
            PutOutcome::IdenticalRetry
        );
        assert_eq!(
            store.put_immutable(id, b"synthetic-b"),
            Err(StoreError::ExistingObjectDiffers)
        );
        assert_eq!(
            store.get(&id).expect("get").as_deref(),
            Some(b"synthetic-a".as_slice())
        );
        let rendered = StoreError::ExistingObjectDiffers.to_string();
        assert_eq!(rendered, "existing object differs");
        assert!(!rendered.contains("synthetic"));
    }

    #[test]
    fn empty_payload_and_distinct_ids() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let empty_id = [0u8; 32];
        let other = [0xff; 32];
        assert_eq!(
            store.put_immutable(empty_id, b"").expect("empty"),
            PutOutcome::Created
        );
        assert_eq!(
            store.put_immutable(other, b"other").expect("other"),
            PutOutcome::Created
        );
        assert_eq!(
            store.get(&empty_id).expect("empty get").as_deref(),
            Some(b"".as_slice())
        );
        assert_eq!(
            store.get(&other).expect("other get").as_deref(),
            Some(b"other".as_slice())
        );
    }

    #[test]
    fn file_name_is_lowercase_hex_inside_the_root() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let mut id = [0u8; 32];
        id[0] = 0x00;
        id[1] = 0x2f;
        id[31] = 0xff;
        store.put_immutable(id, b"opaque").expect("put");
        let name = hex_name(&id);
        assert_eq!(name.len(), 64);
        assert!(
            name.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert!(name.starts_with("002f"));
        assert!(name.ends_with("ff"));
        let path = store.path_for(&id);
        assert_eq!(path.parent(), Some(store.root()));
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(name.as_str())
        );
        let entries = fs::read_dir(store.root()).expect("list").count();
        assert_eq!(entries, 1);
    }

    #[test]
    fn a_directory_where_the_object_should_be_is_an_io_error() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let id = [0x11; 32];
        fs::create_dir(store.path_for(&id)).expect("block the path");
        assert_eq!(store.get(&id), Err(StoreError::Io));
        assert_eq!(store.put_immutable(id, b"bytes"), Err(StoreError::Io));
        assert_eq!(StoreError::Io.to_string(), "io error");
    }
}
