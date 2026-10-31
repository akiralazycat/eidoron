//! Opaque objects in a caller-chosen directory.
//!
//! Each id is a 32-byte value. The file name is its lowercase hex encoding,
//! 64 characters, so the id's own bytes never become path separators.
//! A new object is written to a `.eidoron-tmp-` file in the same directory,
//! `sync_all` is called on that file, then the file is renamed onto the hex
//! name. [`TempDirStore::create`] removes leftover temp names. A temp file is
//! never a valid object name, so `get` does not return its bytes. Directory
//! `sync_all` is attempted and ignored if the platform refuses it. This is
//! not a claim that every crash leaves a consistent directory.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{PutOutcome, StoreError, immutable_put_decision};

const TEMP_PREFIX: &str = ".eidoron-tmp-";

/// What one directory entry is. Only [`FolderEntry::Object`] is an object id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderEntry {
    Object([u8; 32]),
    /// A sync tool's conflict copy, such as `name (1)` or `name (conflicted copy)`.
    /// Not read as an object and not deleted by this store.
    ConflictCopy(String),
    LeftoverTemp(String),
    /// Any other name. Ignored: not an object, not deleted.
    Foreign(String),
}

/// Directory of opaque objects. The product vault is a folder the user's own
/// sync tool copies. This store does not call a cloud API.
#[derive(Debug, Clone)]
pub struct TempDirStore {
    root: PathBuf,
}

impl TempDirStore {
    /// Use `root` as the directory. It is created if it is missing.
    /// Leftover `.eidoron-tmp-` files in that directory are removed.
    pub fn create(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|_| StoreError::Io)?;
        cleanup_temps(&root)?;
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
                write_via_temp(&self.root, &path, &object_id, bytes)?;
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

    /// Classify names in the directory. Conflict copies and foreign files stay
    /// on disk. Temp leftovers are reported and are not objects.
    pub fn scan(&self) -> Result<Vec<FolderEntry>, StoreError> {
        let mut found = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| StoreError::Io)? {
            let entry = entry.map_err(|_| StoreError::Io)?;
            let Some(name) = entry.file_name().into_string().ok() else {
                found.push(FolderEntry::Foreign(String::new()));
                continue;
            };
            found.push(classify_file_name(&name));
        }
        found.sort_by_key(entry_sort_key);
        Ok(found)
    }

    fn path_for(&self, object_id: &[u8; 32]) -> PathBuf {
        self.root.join(hex_name(object_id))
    }
}

fn write_via_temp(
    root: &Path,
    final_path: &Path,
    object_id: &[u8; 32],
    bytes: &[u8],
) -> Result<(), StoreError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp_name = format!(
        "{TEMP_PREFIX}{}-{}-{}",
        hex_name(object_id),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let tmp = root.join(tmp_name);
    let write_result = (|| -> Result<(), StoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| StoreError::Io)?;
        file.write_all(bytes).map_err(|_| StoreError::Io)?;
        file.sync_all().map_err(|_| StoreError::Io)?;
        fs::rename(&tmp, final_path).map_err(|_| StoreError::Io)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
        return write_result;
    }
    if let Ok(dir) = File::open(root) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn cleanup_temps(root: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(root).map_err(|_| StoreError::Io)? {
        let entry = entry.map_err(|_| StoreError::Io)?;
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        if name.starts_with(TEMP_PREFIX) {
            fs::remove_file(entry.path()).map_err(|_| StoreError::Io)?;
        }
    }
    Ok(())
}

/// Classify one file name. Exact 64-character lowercase hex is an object.
/// Anything else is not read as an object.
pub fn classify_file_name(name: &str) -> FolderEntry {
    if name.starts_with(TEMP_PREFIX) {
        return FolderEntry::LeftoverTemp(name.to_string());
    }
    if let Some(id) = parse_hex_id(name) {
        return FolderEntry::Object(id);
    }
    if is_conflict_copy(name) {
        return FolderEntry::ConflictCopy(name.to_string());
    }
    FolderEntry::Foreign(name.to_string())
}

fn parse_hex_id(name: &str) -> Option<[u8; 32]> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let mut id = [0u8; 32];
    let bytes = name.as_bytes();
    for (index, slot) in id.iter_mut().enumerate() {
        let hi = hex_value(bytes[index * 2])?;
        let lo = hex_value(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(id)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn is_conflict_copy(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.contains("conflicted copy") {
        return true;
    }
    let bytes = name.as_bytes();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index] == b' ' && bytes[index + 1] == b'(' {
            let mut cursor = index + 2;
            let start = cursor;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                cursor += 1;
            }
            if cursor > start && cursor < bytes.len() && bytes[cursor] == b')' {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn entry_sort_key(entry: &FolderEntry) -> String {
    match entry {
        FolderEntry::Object(id) => format!("0:{}", hex_name(id)),
        FolderEntry::ConflictCopy(name)
        | FolderEntry::LeftoverTemp(name)
        | FolderEntry::Foreign(name) => format!("1:{name}"),
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

    #[test]
    fn leftover_temp_files_are_removed_and_never_read_as_objects() {
        let scratch = Scratch::new();
        fs::create_dir_all(&scratch.path).expect("dir");
        let partial = scratch.path.join(".eidoron-tmp-partial");
        fs::write(&partial, b"partial-not-an-object").expect("plant temp");
        let store = scratch.store();
        assert!(!partial.exists());
        assert_eq!(store.get(&[0u8; 32]).expect("get"), None);
        let planted = store.root().join(".eidoron-tmp-later");
        fs::write(&planted, b"still-partial").expect("plant later");
        assert_eq!(store.get(&[9u8; 32]).expect("get later"), None);
        let scan = store.scan().expect("scan");
        assert_eq!(
            scan,
            vec![FolderEntry::LeftoverTemp(".eidoron-tmp-later".to_string())]
        );
    }

    #[test]
    fn sync_conflict_copies_are_not_objects() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let id_a = [0x0a; 32];
        let id_b = [0x0b; 32];
        store.put_immutable(id_a, b"device-a").expect("a");
        let second = TempDirStore::create(store.root()).expect("same folder");
        second.put_immutable(id_b, b"device-b").expect("b");
        let hex_a = hex_name(&id_a);
        fs::write(store.root().join(format!("{hex_a} (1)")), b"drive-copy").expect("drive");
        fs::write(
            store.root().join(format!("{hex_a} (conflicted copy)")),
            b"dropbox-copy",
        )
        .expect("dropbox");
        fs::write(store.root().join("README"), b"foreign").expect("foreign");
        assert_eq!(
            store.get(&id_a).expect("a").as_deref(),
            Some(b"device-a".as_slice())
        );
        assert_eq!(
            second.get(&id_b).expect("b").as_deref(),
            Some(b"device-b".as_slice())
        );
        let scan = store.scan().expect("scan");
        let objects: Vec<[u8; 32]> = scan
            .iter()
            .filter_map(|entry| match entry {
                FolderEntry::Object(id) => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(objects, vec![id_a, id_b]);
        assert!(scan.iter().any(|entry| matches!(
            entry,
            FolderEntry::ConflictCopy(name) if name.ends_with(" (1)")
        )));
        assert!(scan.iter().any(|entry| matches!(
            entry,
            FolderEntry::ConflictCopy(name) if name.contains("conflicted copy")
        )));
        assert!(
            scan.iter()
                .any(|entry| matches!(entry, FolderEntry::Foreign(name) if name == "README"))
        );
        let names: Vec<&str> = scan
            .iter()
            .filter_map(|entry| match entry {
                FolderEntry::ConflictCopy(name) | FolderEntry::Foreign(name) => Some(name.as_str()),
                FolderEntry::Object(_) | FolderEntry::LeftoverTemp(_) => None,
            })
            .collect();
        assert!(names.iter().all(|name| parse_hex_id(name).is_none()));
    }
}
