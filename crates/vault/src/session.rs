//! A sync-folder vault session.
//!
//! Create writes `vault.header` and one genesis commit through the temp-file
//! store. Open unwraps the root with Argon2id and the password. A wrong
//! password, a bad tag, and a corrupt header all return [`VaultError::Unavailable`].
//! That is the same error variant, not a measured timing property.
//! Heads come from [`crate::classify_heads`]. This session does not merge them
//! and does not delete sync-tool conflict copies.
//!
//! [`Session::write_commit`] appends one commit under the parent the caller
//! names. During a conflict the caller is choosing that parent. The function
//! does not pick a head. A child's generation is the parent's generation plus
//! one. `TempDirStore::create` removes leftover temp names at create and open.
//! A later [`Session::status`] does not.

use std::path::{Path, PathBuf};

use eidoron_crypto::{
    KdfParams, RootSecret, decrypt_authenticated, derive_object_key, derive_raw_pwd_key,
    derive_wrap_key, open_root, seal_authenticated, seal_root,
};
use eidoron_format::{
    HEADER_LEN, OBJECT_PREFIX_LEN, inspect_untrusted_header, inspect_untrusted_object,
};
use eidoron_provider_local::{FolderEntry, TempDirStore};

use crate::commit_check::{read_commit_generation, read_commit_parent};
use crate::{HistoryStatus, LocalCommit, VaultError, classify_heads};

const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const LANES: u32 = 4;
const COMMIT_KIND: u8 = 0x01;
const BODY_SCHEMA: u8 = 0x00;

/// What an unlocked session sees in the folder. Conflicting heads are all listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultStatus {
    Ok,
    Conflict(Vec<[u8; 32]>),
    Incomplete,
    Locked,
}

/// Unlocked access to one sync folder. Drop and [`Session::lock`] zeroize the root.
pub struct Session {
    folder: PathBuf,
    vault_id: [u8; 16],
    root: Option<RootSecret>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.lock();
    }
}

impl Session {
    pub fn lock(&mut self) {
        self.root.take();
    }

    pub fn vault_id(&self) -> Result<[u8; 16], VaultError> {
        self.ensure_unlocked()?;
        Ok(self.vault_id)
    }

    /// `Ok` is one complete head. `Conflict` lists every head. `Incomplete`
    /// means a parent commit is not in the folder yet. `Locked` means the
    /// root secret is gone.
    pub fn status(&self) -> Result<VaultStatus, VaultError> {
        if self.root.is_none() {
            return Ok(VaultStatus::Locked);
        }
        let commits = self.load_commits()?;
        let view = classify_heads(&commits).map_err(|_| VaultError::Unavailable)?;
        Ok(match view.status {
            HistoryStatus::Empty | HistoryStatus::Incomplete { .. } => VaultStatus::Incomplete,
            HistoryStatus::Single { .. } => VaultStatus::Ok,
            HistoryStatus::Conflict { heads } => VaultStatus::Conflict(heads),
        })
    }

    /// Append a commit whose parent is `parent`.
    ///
    /// This does not delete any other commit and does not choose among
    /// conflicting heads. `parent == None` is another genesis.
    pub fn write_commit(&mut self, parent: Option<[u8; 32]>) -> Result<[u8; 32], VaultError> {
        self.ensure_unlocked()?;
        let generation = match parent {
            None => 0,
            Some(id) => self
                .generation_of(id)?
                .checked_add(1)
                .ok_or(VaultError::Unavailable)?,
        };
        let root = self.root.as_ref().ok_or(VaultError::Locked)?;
        let object_id = random_array()?;
        let directory_id = random_array()?;
        let logical_id = random_array::<16>()?;
        let plaintext = encode_commit(generation, parent, directory_id, logical_id);
        let stored = seal_commit_object(root, &self.vault_id, &object_id, &plaintext)?;
        let store = TempDirStore::open(&self.folder).map_err(store_error)?;
        store
            .put_immutable(object_id, &stored)
            .map_err(store_error)?;
        Ok(object_id)
    }

    fn ensure_unlocked(&self) -> Result<(), VaultError> {
        if self.root.is_none() {
            Err(VaultError::Locked)
        } else {
            Ok(())
        }
    }

    fn generation_of(&self, object_id: [u8; 32]) -> Result<u64, VaultError> {
        let plain = self.read_commit(object_id)?;
        read_commit_generation(&plain).map_err(|_| VaultError::Unavailable)
    }

    fn load_commits(&self) -> Result<Vec<LocalCommit>, VaultError> {
        let store = TempDirStore::open(&self.folder).map_err(store_error)?;
        let mut commits = Vec::new();
        for entry in store.scan().map_err(store_error)? {
            let FolderEntry::Object(object_id) = entry else {
                continue;
            };
            let plain = self.read_commit(object_id)?;
            let parent = read_commit_parent(&plain).map_err(|_| VaultError::Unavailable)?;
            commits.push(LocalCommit {
                id: object_id,
                parent,
            });
        }
        Ok(commits)
    }

    fn read_commit(&self, object_id: [u8; 32]) -> Result<Vec<u8>, VaultError> {
        let root = self.root.as_ref().ok_or(VaultError::Locked)?;
        let store = TempDirStore::open(&self.folder).map_err(store_error)?;
        let Some(bytes) = store.get(&object_id).map_err(store_error)? else {
            return Err(VaultError::Unavailable);
        };
        open_commit_object(root, &self.vault_id, &object_id, &bytes)
    }
}

/// Create a vault in `folder`. The directory must be missing or empty.
pub fn create_vault(folder: &Path, password: &str) -> Result<Session, VaultError> {
    if folder_is_non_empty(folder)? {
        return Err(VaultError::DirectoryNotEmpty);
    }
    let store = TempDirStore::create(folder).map_err(store_error)?;
    let vault_id = random_array()?;
    let salt = random_array()?;
    let wrap_nonce = random_array()?;
    let root = RootSecret::from_bytes(random_array()?);
    let params = KdfParams {
        memory_kib: MEMORY_KIB,
        iterations: ITERATIONS,
        lanes: LANES,
    };
    let raw = derive_raw_pwd_key(password, &salt, params).map_err(|_| VaultError::Unavailable)?;
    let wrap = derive_wrap_key(&raw, &vault_id);
    let mut header = [0u8; HEADER_LEN];
    write_header_prefix(&mut header, &vault_id, &salt, &wrap_nonce);
    let wrapped = seal_root(&wrap, &wrap_nonce, &root, &header[..88]);
    header[88..].copy_from_slice(&wrapped);
    inspect_untrusted_header(&header).map_err(|_| VaultError::Unavailable)?;
    store.write_vault_header(&header).map_err(store_error)?;
    let mut session = Session {
        folder: folder.to_path_buf(),
        vault_id,
        root: Some(root),
    };
    session.write_commit(None)?;
    Ok(session)
}

/// Open a vault. Password failure and header failure use the same error.
pub fn open_vault(folder: &Path, password: &str) -> Result<Session, VaultError> {
    let store = TempDirStore::create(folder).map_err(store_error)?;
    let Some(header_bytes) = store.read_vault_header().map_err(store_error)? else {
        return Err(VaultError::Unavailable);
    };
    if header_bytes.len() != HEADER_LEN {
        return Err(VaultError::Unavailable);
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&header_bytes);
    let parsed = inspect_untrusted_header(&header).map_err(|_| VaultError::Unavailable)?;
    let params = KdfParams {
        memory_kib: parsed.argon_m_cost_kib,
        iterations: parsed.argon_t_cost,
        lanes: parsed.argon_lanes,
    };
    let salt = header_salt(&header);
    let wrap_nonce = header_nonce(&header);
    let raw = derive_raw_pwd_key(password, &salt, params).map_err(|_| VaultError::Unavailable)?;
    let wrap = derive_wrap_key(&raw, &parsed.vault_id);
    let root = open_root(&wrap, &wrap_nonce, &header[88..136], &header[..88])
        .map_err(|_| VaultError::Unavailable)?;
    Ok(Session {
        folder: folder.to_path_buf(),
        vault_id: parsed.vault_id,
        root: Some(root),
    })
}

fn folder_is_non_empty(folder: &Path) -> Result<bool, VaultError> {
    if !folder.exists() {
        return Ok(false);
    }
    let mut entries = std::fs::read_dir(folder).map_err(|_| VaultError::Unavailable)?;
    Ok(entries.next().is_some())
}

fn write_header_prefix(
    header: &mut [u8; HEADER_LEN],
    vault_id: &[u8; 16],
    salt: &[u8; 16],
    nonce: &[u8; 24],
) {
    header[0..8].copy_from_slice(b"EIDORON\0");
    header[12..14].copy_from_slice(&1u16.to_be_bytes());
    header[16..32].copy_from_slice(vault_id);
    header[32..48].copy_from_slice(salt);
    header[48..52].copy_from_slice(&0x13u32.to_be_bytes());
    header[52..56].copy_from_slice(&MEMORY_KIB.to_be_bytes());
    header[56..60].copy_from_slice(&ITERATIONS.to_be_bytes());
    header[60..64].copy_from_slice(&LANES.to_be_bytes());
    header[64..88].copy_from_slice(nonce);
}

fn header_salt(header: &[u8; HEADER_LEN]) -> [u8; 16] {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&header[32..48]);
    salt
}

fn header_nonce(header: &[u8; HEADER_LEN]) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&header[64..88]);
    nonce
}

fn encode_commit(
    generation: u64,
    parent: Option<[u8; 32]>,
    directory_id: [u8; 32],
    logical_id: [u8; 16],
) -> Vec<u8> {
    let mut body = vec![COMMIT_KIND, BODY_SCHEMA, 0xa4, 0x00];
    encode_uint(&mut body, generation);
    body.push(0x01);
    match parent {
        None => body.push(0xf6),
        Some(id) => {
            body.push(0x58);
            body.push(32);
            body.extend_from_slice(&id);
        }
    }
    body.push(0x02);
    body.push(0x58);
    body.push(32);
    body.extend_from_slice(&directory_id);
    body.push(0x03);
    body.push(0x50);
    body.extend_from_slice(&logical_id);
    body
}

fn encode_uint(out: &mut Vec<u8>, value: u64) {
    if value < 24 {
        out.push(value as u8);
    } else if value < 256 {
        out.push(0x18);
        out.push(value as u8);
    } else if value < 65536 {
        out.push(0x19);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 1 << 32 {
        out.push(0x1a);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn seal_commit_object(
    root: &RootSecret,
    vault_id: &[u8; 16],
    object_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let nonce = random_array()?;
    let key = derive_object_key(root, vault_id, object_id);
    let mut prefix = [0u8; OBJECT_PREFIX_LEN];
    prefix[0..8].copy_from_slice(b"EIDOBJ\0\0");
    prefix[10..12].copy_from_slice(&1u16.to_be_bytes());
    prefix[12..28].copy_from_slice(vault_id);
    prefix[28..60].copy_from_slice(object_id);
    prefix[60..84].copy_from_slice(&nonce);
    let ct_len = u32::try_from(plaintext.len() + 16).map_err(|_| VaultError::Unavailable)?;
    prefix[84..88].copy_from_slice(&ct_len.to_be_bytes());
    let sealed = seal_authenticated(&key, &nonce, &prefix, plaintext)
        .map_err(|_| VaultError::Unavailable)?;
    let mut stored = prefix.to_vec();
    stored.extend_from_slice(&sealed.ciphertext_and_tag);
    Ok(stored)
}

fn open_commit_object(
    root: &RootSecret,
    vault_id: &[u8; 16],
    object_id: &[u8; 32],
    stored: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let parsed = inspect_untrusted_object(stored).map_err(|_| VaultError::Unavailable)?;
    if parsed.vault_id != *vault_id || parsed.object_id != *object_id {
        return Err(VaultError::Unavailable);
    }
    let nonce = stored[60..84]
        .try_into()
        .map_err(|_| VaultError::Unavailable)?;
    let key = derive_object_key(root, vault_id, object_id);
    decrypt_authenticated(
        &key,
        &nonce,
        &stored[..OBJECT_PREFIX_LEN],
        &stored[OBJECT_PREFIX_LEN..],
    )
    .map_err(|_| VaultError::Unavailable)
}

fn random_array<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut bytes = [0u8; N];
    if getrandom::fill(&mut bytes).is_err() {
        return Err(VaultError::Unavailable);
    }
    Ok(bytes)
}

fn store_error(_error: eidoron_provider_local::StoreError) -> VaultError {
    VaultError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use eidoron_provider_local::VAULT_HEADER_NAME;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "eidoron-vault-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hex_id(id: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(64);
        for byte in id {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        name
    }

    #[test]
    fn create_open_and_lock_roundtrip() {
        let scratch = Scratch::new();
        let mut created = create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        let created_id = created.vault_id().expect("id");
        assert_eq!(created.status().expect("status"), VaultStatus::Ok);
        created.lock();
        assert_eq!(created.status().expect("locked"), VaultStatus::Locked);
        assert_eq!(created.vault_id().err(), Some(VaultError::Locked));
        drop(created);
        let opened = open_vault(&scratch.0, "synthetic-vault-pass").expect("open");
        assert_eq!(opened.vault_id().expect("reopen id"), created_id);
        assert_eq!(opened.status().expect("open status"), VaultStatus::Ok);
    }

    #[test]
    fn wrong_password_is_unavailable() {
        let scratch = Scratch::new();
        create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        assert_eq!(
            open_vault(&scratch.0, "synthetic-other-pass").err(),
            Some(VaultError::Unavailable)
        );
        assert_eq!(VaultError::Unavailable.to_string(), "unavailable");
    }

    #[test]
    fn reopen_after_writing_a_child_commit() {
        let scratch = Scratch::new();
        let mut session = create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        let commits_before = session.load_commits().expect("commits");
        let genesis = commits_before[0].id;
        let child = session.write_commit(Some(genesis)).expect("child");
        assert_eq!(session.status().expect("after write"), VaultStatus::Ok);
        drop(session);
        let opened = open_vault(&scratch.0, "synthetic-vault-pass").expect("reopen");
        assert_eq!(opened.status().expect("reopen status"), VaultStatus::Ok);
        let commits = opened.load_commits().expect("loaded");
        assert!(commits.iter().any(|commit| commit.id == child));
        assert!(
            commits
                .iter()
                .any(|commit| commit.id == genesis && commit.parent.is_none())
        );
    }

    #[test]
    fn a_fork_is_surfaced_and_conflict_copies_stay_untouched() {
        let scratch = Scratch::new();
        let mut session = create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        let genesis = session.load_commits().expect("genesis")[0].id;
        let left = session.write_commit(Some(genesis)).expect("left");
        let right = session.write_commit(Some(genesis)).expect("right");
        let status = session.status().expect("conflict");
        match status {
            VaultStatus::Conflict(heads) => {
                assert!(heads.contains(&left) && heads.contains(&right));
                assert!(!heads.contains(&genesis));
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        let copy_path = scratch.0.join("notes (1)");
        let conflicted_path = scratch.0.join("notes (conflicted copy)");
        fs::write(&copy_path, b"drive-copy").expect("copy");
        fs::write(&conflicted_path, b"dropbox-copy").expect("conflicted");
        drop(session);
        let opened = open_vault(&scratch.0, "synthetic-vault-pass").expect("open");
        match opened.status().expect("still conflict") {
            VaultStatus::Conflict(heads) => {
                assert!(heads.contains(&left) && heads.contains(&right));
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        assert_eq!(fs::read(&copy_path).expect("copy remains"), b"drive-copy");
        assert_eq!(
            fs::read(&conflicted_path).expect("conflicted remains"),
            b"dropbox-copy"
        );
    }

    #[test]
    fn a_missing_parent_is_incomplete() {
        let scratch = Scratch::new();
        let mut session = create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        let genesis = session.load_commits().expect("genesis")[0].id;
        let child = session.write_commit(Some(genesis)).expect("child");
        fs::remove_file(scratch.0.join(hex_id(&genesis))).expect("remove parent");
        assert_eq!(
            session.status().expect("incomplete"),
            VaultStatus::Incomplete
        );
        assert!(scratch.0.join(hex_id(&child)).is_file());
    }

    #[test]
    fn create_refuses_a_non_empty_directory() {
        let scratch = Scratch::new();
        fs::create_dir_all(&scratch.0).expect("dir");
        fs::write(scratch.0.join("already"), b"x").expect("file");
        assert_eq!(
            create_vault(&scratch.0, "synthetic-vault-pass").err(),
            Some(VaultError::DirectoryNotEmpty)
        );
        assert!(!scratch.0.join(VAULT_HEADER_NAME).exists());
    }
}
