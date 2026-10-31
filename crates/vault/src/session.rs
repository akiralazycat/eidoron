//! A sync-folder vault session.
//!
//! Create writes `vault.header` and one genesis commit through the temp-file
//! store. Open unwraps the root with Argon2id and the password. A wrong
//! password, a bad tag, and a corrupt header all return [`VaultError::Unavailable`].
//! That is the same error variant, not a measured timing property.
//! Heads come from [`crate::classify_heads`]. This session does not merge them
//! and does not delete sync-tool conflict copies.
//!
//! Appends require [`Session::select_head`]. The selected id has to be a
//! current head, and the new commit is parented only on that head. Other heads
//! stay on disk. Selection is kept in memory for this session, not in the
//! folder. A child's generation is the parent's generation plus one.
//! `TempDirStore::create` removes leftover temp names at create and open.
//! A later [`Session::status`] does not.
//!
//! A 64-character hex file that does not decrypt, or a decrypted commit body
//! that cannot be read, makes `status` return [`VaultError::Unavailable`].
//! Those files are not skipped. A directory, file, or chunk that does decrypt
//! is not a commit, so it is left out of the history.

use std::path::{Path, PathBuf};

use eidoron_crypto::{
    KdfParams, RootSecret, decrypt_authenticated, derive_object_key, derive_raw_pwd_key,
    derive_wrap_key, open_root, seal_authenticated, seal_root,
};
use eidoron_format::{
    HEADER_LEN, OBJECT_PREFIX_LEN, inspect_untrusted_header, inspect_untrusted_object,
};
use eidoron_provider_local::{FolderEntry, TempDirStore};

use crate::commit_check::{read_commit_generation, read_commit_parent, read_commit_root};
use crate::directory_body::{
    ChildKind, DecodedDirectory, DirectoryBodyError, DirectoryEntry, decode_directory,
    encode_directory,
};
use crate::file_body::{
    chunk_payload, decode_file_descriptor, encode_chunk, encode_file_descriptor,
};
use crate::{HistoryStatus, LocalCommit, VaultError, check_directory_name, classify_heads};

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
    selected: Option<[u8; 32]>,
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

    /// Current heads. Empty when the history is empty. This does not choose one.
    pub fn heads(&self) -> Result<Vec<[u8; 32]>, VaultError> {
        self.ensure_unlocked()?;
        let commits = self.load_commits()?;
        let view = classify_heads(&commits).map_err(|_| VaultError::Unavailable)?;
        Ok(match view.status {
            HistoryStatus::Empty => Vec::new(),
            HistoryStatus::Single { head } | HistoryStatus::Incomplete { head } => vec![head],
            HistoryStatus::Conflict { heads } => heads,
        })
    }

    /// Remember `head` as the only parent later appends may use.
    ///
    /// `head` must be a current head. This does not write, merge, or delete.
    pub fn select_head(&mut self, head: [u8; 32]) -> Result<(), VaultError> {
        if !self.heads()?.contains(&head) {
            return Err(VaultError::WrongHead);
        }
        self.selected = Some(head);
        Ok(())
    }

    pub fn selected_head(&self) -> Result<Option<[u8; 32]>, VaultError> {
        self.ensure_unlocked()?;
        Ok(self.selected)
    }

    /// Write a directory object and a child commit under the selected `head`.
    ///
    /// Names are stored in NFC. The same name twice, including NFC and NFD
    /// spellings, is [`VaultError::DuplicateName`] and writes nothing. Other
    /// heads are not modified. On success the selection moves to the new commit.
    pub fn append_directory(
        &mut self,
        head: [u8; 32],
        entries: &[(&str, ChildKind)],
    ) -> Result<[u8; 32], VaultError> {
        self.require_head(head)?;
        let mut stored = Vec::with_capacity(entries.len());
        for (name, kind) in entries {
            stored.push(DirectoryEntry {
                name: (*name).to_string(),
                kind: *kind,
                object_id: random_array()?,
            });
        }
        let dir_id: [u8; 16] = random_array()?;
        let plaintext = encode_directory(&dir_id, None, &stored).map_err(directory_error)?;
        let directory_object: [u8; 32] = random_array()?;
        self.put_plaintext(directory_object, &plaintext)?;
        let commit = self.write_child_commit(head, directory_object)?;
        self.selected = Some(commit);
        Ok(commit)
    }

    /// Entries in the selected head's root directory, in stored name order.
    pub fn list_directory(&self) -> Result<Vec<DirectoryEntry>, VaultError> {
        let head = self.selected_id()?;
        Ok(self.decoded_directory(head)?.entries)
    }

    /// Add one small file under the selected head and commit that directory.
    ///
    /// A non-empty payload is one chunk. [`crate::check_chunk_identity`] runs
    /// before the chunk is stored and again when [`Session::read_file`] opens it.
    /// The previous directory's other names are kept. Other heads are not modified.
    pub fn write_file(
        &mut self,
        head: [u8; 32],
        name: &str,
        bytes: &[u8],
    ) -> Result<[u8; 32], VaultError> {
        self.require_head(head)?;
        let name = check_directory_name(name).map_err(|_| VaultError::RejectedName)?;
        let mut loaded = self.loaded_directory(head)?;
        if loaded.entries.iter().any(|entry| entry.name == name) {
            return Err(VaultError::DuplicateName);
        }
        let file_id: [u8; 16] = random_array()?;
        let mut chunks = Vec::new();
        if !bytes.is_empty() {
            let chunk_id: [u8; 32] = random_array()?;
            let plain = encode_chunk(&file_id, 0, bytes).map_err(|_| VaultError::Unavailable)?;
            self.put_plaintext(chunk_id, &plain)?;
            chunks.push(chunk_id);
        }
        let descriptor_id: [u8; 32] = random_array()?;
        let size = u64::try_from(bytes.len()).map_err(|_| VaultError::Unavailable)?;
        let descriptor = encode_file_descriptor(&file_id, &loaded.dir_id, size, &chunks)
            .map_err(|_| VaultError::Unavailable)?;
        self.put_plaintext(descriptor_id, &descriptor)?;
        loaded.entries.push(DirectoryEntry {
            name,
            kind: ChildKind::File,
            object_id: descriptor_id,
        });
        let directory_object: [u8; 32] = random_array()?;
        let directory =
            encode_directory(&loaded.dir_id, None, &loaded.entries).map_err(directory_error)?;
        self.put_plaintext(directory_object, &directory)?;
        let commit = self.write_child_commit(head, directory_object)?;
        self.selected = Some(commit);
        Ok(commit)
    }

    /// Bytes of one file in the selected head's directory.
    ///
    /// `name` is normalized to NFC before the lookup. Each chunk must match the
    /// descriptor's `file_id` and its ordinal.
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        let head = self.selected_id()?;
        let stored = check_directory_name(name).map_err(|_| VaultError::RejectedName)?;
        let directory = self.decoded_directory(head)?;
        let entry = directory
            .entries
            .iter()
            .find(|entry| entry.name == stored)
            .ok_or(VaultError::Unavailable)?;
        if entry.kind != ChildKind::File {
            return Err(VaultError::Unavailable);
        }
        let descriptor = decode_file_descriptor(&self.read_object(entry.object_id)?)
            .map_err(|_| VaultError::Unavailable)?;
        if descriptor.parent_dir_id != directory.dir_id {
            return Err(VaultError::Unavailable);
        }
        let mut payload = Vec::new();
        for (index, chunk_id) in descriptor.chunks.iter().enumerate() {
            let ordinal = u32::try_from(index).map_err(|_| VaultError::Unavailable)?;
            let plain = self.read_object(*chunk_id)?;
            let piece = chunk_payload(&plain, &descriptor.file_id, ordinal)
                .map_err(|_| VaultError::Unavailable)?;
            payload.extend_from_slice(piece);
        }
        let size = u64::try_from(payload.len()).map_err(|_| VaultError::Unavailable)?;
        if size != descriptor.size {
            return Err(VaultError::Unavailable);
        }
        Ok(payload)
    }

    fn ensure_unlocked(&self) -> Result<(), VaultError> {
        if self.root.is_none() {
            Err(VaultError::Locked)
        } else {
            Ok(())
        }
    }

    fn require_head(&self, head: [u8; 32]) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        match self.selected {
            Some(selected) if selected == head => {}
            Some(_) => return Err(VaultError::WrongHead),
            None => return Err(VaultError::HeadNotSelected),
        }
        if !self.heads()?.contains(&head) {
            return Err(VaultError::WrongHead);
        }
        Ok(())
    }

    fn selected_id(&self) -> Result<[u8; 32], VaultError> {
        self.ensure_unlocked()?;
        let head = self.selected.ok_or(VaultError::HeadNotSelected)?;
        if !self.heads()?.contains(&head) {
            return Err(VaultError::WrongHead);
        }
        Ok(head)
    }

    fn write_genesis(&mut self) -> Result<[u8; 32], VaultError> {
        let directory_object = random_array()?;
        self.write_commit(None, directory_object)
    }

    fn write_child_commit(
        &mut self,
        parent: [u8; 32],
        directory_object: [u8; 32],
    ) -> Result<[u8; 32], VaultError> {
        self.write_commit(Some(parent), directory_object)
    }

    fn write_commit(
        &mut self,
        parent: Option<[u8; 32]>,
        directory_object: [u8; 32],
    ) -> Result<[u8; 32], VaultError> {
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
        let logical_id = random_array::<16>()?;
        let plaintext = encode_commit(generation, parent, directory_object, logical_id);
        let stored = seal_object(root, &self.vault_id, &object_id, &plaintext)?;
        let store = TempDirStore::open(&self.folder).map_err(store_error)?;
        store
            .put_immutable(object_id, &stored)
            .map_err(store_error)?;
        Ok(object_id)
    }

    fn generation_of(&self, object_id: [u8; 32]) -> Result<u64, VaultError> {
        let plain = self.read_object(object_id)?;
        read_commit_generation(&plain).map_err(|_| VaultError::Unavailable)
    }

    fn loaded_directory(&self, commit: [u8; 32]) -> Result<LoadedDirectory, VaultError> {
        let commit_plain = self.read_object(commit)?;
        let root_id = read_commit_root(&commit_plain).map_err(|_| VaultError::Unavailable)?;
        match self.read_object_optional(root_id)? {
            None => Ok(LoadedDirectory {
                dir_id: random_array()?,
                entries: Vec::new(),
            }),
            Some(plain) => {
                let decoded = decode_directory(&plain).map_err(|_| VaultError::Unavailable)?;
                Ok(LoadedDirectory {
                    dir_id: decoded.dir_id,
                    entries: decoded.entries,
                })
            }
        }
    }

    fn decoded_directory(&self, commit: [u8; 32]) -> Result<DecodedDirectory, VaultError> {
        let commit_plain = self.read_object(commit)?;
        let root_id = read_commit_root(&commit_plain).map_err(|_| VaultError::Unavailable)?;
        let plain = self.read_object(root_id)?;
        decode_directory(&plain).map_err(|_| VaultError::Unavailable)
    }

    fn load_commits(&self) -> Result<Vec<LocalCommit>, VaultError> {
        let store = TempDirStore::open(&self.folder).map_err(store_error)?;
        let mut commits = Vec::new();
        for entry in store.scan().map_err(store_error)? {
            let FolderEntry::Object(object_id) = entry else {
                continue;
            };
            let plain = self.read_object(object_id)?;
            if plain.first().copied() != Some(COMMIT_KIND) {
                continue;
            }
            let parent = read_commit_parent(&plain).map_err(|_| VaultError::Unavailable)?;
            commits.push(LocalCommit {
                id: object_id,
                parent,
            });
        }
        Ok(commits)
    }

    fn put_plaintext(&self, object_id: [u8; 32], plaintext: &[u8]) -> Result<(), VaultError> {
        let root = self.root.as_ref().ok_or(VaultError::Locked)?;
        let stored = seal_object(root, &self.vault_id, &object_id, plaintext)?;
        let store = TempDirStore::open(&self.folder).map_err(store_error)?;
        store
            .put_immutable(object_id, &stored)
            .map_err(store_error)?;
        Ok(())
    }

    fn read_object(&self, object_id: [u8; 32]) -> Result<Vec<u8>, VaultError> {
        self.read_object_optional(object_id)?
            .ok_or(VaultError::Unavailable)
    }

    fn read_object_optional(&self, object_id: [u8; 32]) -> Result<Option<Vec<u8>>, VaultError> {
        let root = self.root.as_ref().ok_or(VaultError::Locked)?;
        let store = TempDirStore::open(&self.folder).map_err(store_error)?;
        let Some(bytes) = store.get(&object_id).map_err(store_error)? else {
            return Ok(None);
        };
        Ok(Some(open_object(root, &self.vault_id, &object_id, &bytes)?))
    }
}

struct LoadedDirectory {
    dir_id: [u8; 16],
    entries: Vec<DirectoryEntry>,
}

fn directory_error(error: DirectoryBodyError) -> VaultError {
    match error {
        DirectoryBodyError::RejectedName => VaultError::RejectedName,
        DirectoryBodyError::DuplicateName => VaultError::DuplicateName,
        DirectoryBodyError::Unreadable | DirectoryBodyError::TooMany => VaultError::Unavailable,
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
        selected: None,
    };
    session.write_genesis()?;
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
        selected: None,
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

fn seal_object(
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

fn open_object(
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
    use crate::ChildKind;
    use crate::commit_check::read_commit_parent;
    use eidoron_provider_local::VAULT_HEADER_NAME;
    use std::collections::BTreeMap;
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

    fn only_head(session: &Session) -> [u8; 32] {
        let heads = session.heads().expect("heads");
        assert_eq!(heads.len(), 1);
        heads[0]
    }

    fn listed_names(session: &Session) -> Vec<String> {
        session
            .list_directory()
            .expect("list")
            .into_iter()
            .map(|entry| entry.name)
            .collect()
    }

    fn copy_files(from: &Path, to: &Path) {
        fs::create_dir_all(to).expect("dest");
        for entry in fs::read_dir(from).expect("read") {
            let entry = entry.expect("entry");
            if entry.path().is_file() {
                fs::copy(entry.path(), to.join(entry.file_name())).expect("copy");
            }
        }
    }

    fn copy_missing(from: &Path, to: &Path) {
        for entry in fs::read_dir(from).expect("read") {
            let entry = entry.expect("entry");
            let dest = to.join(entry.file_name());
            if entry.path().is_file() && !dest.exists() {
                fs::copy(entry.path(), dest).expect("copy missing");
            }
        }
    }

    fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(dir).expect("read") {
            let entry = entry.expect("entry");
            if entry.path().is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                files.insert(name, fs::read(entry.path()).expect("bytes"));
            }
        }
        files
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
        let garbage = scratch.0.join("ab".repeat(32));
        fs::write(&garbage, b"not-a-commit").expect("plant");
        assert_eq!(created.status().err(), Some(VaultError::Unavailable));
        fs::remove_file(&garbage).expect("remove plant");
        assert_eq!(
            created.status().expect("status after remove"),
            VaultStatus::Ok
        );
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
    fn write_reopen_list_and_read_a_file() {
        let scratch = Scratch::new();
        let mut session = create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        let genesis = only_head(&session);
        assert_eq!(
            session
                .append_directory(genesis, &[("a", ChildKind::File)])
                .err(),
            Some(VaultError::HeadNotSelected)
        );
        session.select_head(genesis).expect("select");
        assert_eq!(
            session
                .append_directory(
                    genesis,
                    &[("é", ChildKind::File), ("e\u{0301}", ChildKind::File)]
                )
                .err(),
            Some(VaultError::DuplicateName)
        );
        assert_eq!(
            session
                .append_directory(genesis, &[(".", ChildKind::File)])
                .err(),
            Some(VaultError::RejectedName)
        );
        assert_eq!(VaultError::DuplicateName.to_string(), "duplicate name");
        assert_eq!(VaultError::RejectedName.to_string(), "rejected name");
        assert!(!VaultError::DuplicateName.to_string().contains('é'));
        assert_eq!(session.heads().expect("still genesis"), vec![genesis]);
        let child = session
            .append_directory(
                genesis,
                &[("b", ChildKind::File), ("notes", ChildKind::Directory)],
            )
            .expect("directory");
        assert_eq!(
            listed_names(&session),
            vec!["b".to_string(), "notes".to_string()]
        );
        let file_commit = session
            .write_file(child, "e\u{0301}", b"synthetic-file")
            .expect("file");
        assert_eq!(
            listed_names(&session),
            vec!["b".to_string(), "notes".to_string(), "é".to_string()]
        );
        assert_eq!(session.read_file("é").expect("nfc"), b"synthetic-file");
        assert_eq!(
            session.read_file("e\u{0301}").expect("nfd"),
            b"synthetic-file"
        );
        assert_eq!(session.read_file("b").err(), Some(VaultError::Unavailable));
        assert_eq!(session.status().expect("ok"), VaultStatus::Ok);
        drop(session);
        let mut opened = open_vault(&scratch.0, "synthetic-vault-pass").expect("reopen");
        assert_eq!(
            opened.list_directory().err(),
            Some(VaultError::HeadNotSelected)
        );
        assert_eq!(opened.heads().expect("one head"), vec![file_commit]);
        opened.select_head(file_commit).expect("select file head");
        assert_eq!(
            listed_names(&opened),
            vec!["b".to_string(), "notes".to_string(), "é".to_string()]
        );
        assert_eq!(
            opened.read_file("e\u{0301}").expect("reopen file"),
            b"synthetic-file"
        );
    }

    #[test]
    fn conflict_appends_only_under_the_selected_head() {
        let left_dir = Scratch::new();
        let mut left = create_vault(&left_dir.0, "synthetic-vault-pass").expect("create");
        let genesis = only_head(&left);
        let right_dir = Scratch::new();
        copy_files(&left_dir.0, &right_dir.0);
        let mut right = open_vault(&right_dir.0, "synthetic-vault-pass").expect("other device");
        left.select_head(genesis).expect("left select");
        right.select_head(genesis).expect("right select");
        let left_head = left
            .append_directory(genesis, &[("left", ChildKind::File)])
            .expect("left dir");
        let right_head = right
            .append_directory(genesis, &[("right", ChildKind::File)])
            .expect("right dir");
        drop(right);
        copy_missing(&right_dir.0, &left_dir.0);
        match left.status().expect("conflict") {
            VaultStatus::Conflict(heads) => {
                assert!(heads.contains(&left_head) && heads.contains(&right_head));
                assert!(!heads.contains(&genesis));
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        assert_eq!(left.select_head(genesis).err(), Some(VaultError::WrongHead));
        assert_eq!(
            left.append_directory(right_head, &[("nope", ChildKind::File)])
                .err(),
            Some(VaultError::WrongHead)
        );
        let before = snapshot(&left_dir.0);
        let child = left
            .append_directory(left_head, &[("more", ChildKind::File)])
            .expect("append on the selected line");
        let after = snapshot(&left_dir.0);
        for (name, bytes) in &before {
            assert_eq!(
                after.get(name).map(Vec::as_slice),
                Some(bytes.as_slice()),
                "{name}"
            );
        }
        let child_plain = left.read_object(child).expect("child commit");
        assert_eq!(
            read_commit_parent(&child_plain).expect("parent"),
            Some(left_head)
        );
        let heads = left.heads().expect("heads after append");
        assert!(heads.contains(&child) && heads.contains(&right_head));
        assert!(!heads.contains(&left_head));
        left.select_head(right_head)
            .expect("look at the other head");
        assert_eq!(listed_names(&left), vec!["right".to_string()]);
        let copy_path = left_dir.0.join("notes (1)");
        let conflicted_path = left_dir.0.join("notes (conflicted copy)");
        fs::write(&copy_path, b"drive-copy").expect("copy");
        fs::write(&conflicted_path, b"dropbox-copy").expect("conflicted");
        drop(left);
        let mut opened = open_vault(&left_dir.0, "synthetic-vault-pass").expect("reopen");
        match opened.status().expect("still conflict") {
            VaultStatus::Conflict(heads) => {
                assert!(heads.contains(&child) && heads.contains(&right_head));
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        assert_eq!(
            opened
                .append_directory(right_head, &[("x", ChildKind::File)])
                .err(),
            Some(VaultError::HeadNotSelected)
        );
        assert_eq!(fs::read(&copy_path).expect("copy remains"), b"drive-copy");
        assert_eq!(
            fs::read(&conflicted_path).expect("conflicted remains"),
            b"dropbox-copy"
        );
        opened.select_head(right_head).expect("select right");
        assert_eq!(listed_names(&opened), vec!["right".to_string()]);
    }

    #[test]
    fn a_missing_parent_is_incomplete() {
        let scratch = Scratch::new();
        let mut session = create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        let genesis = only_head(&session);
        session.select_head(genesis).expect("select");
        let child = session
            .append_directory(genesis, &[("kept", ChildKind::File)])
            .expect("child");
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
