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
    chunk_count, chunk_payload, decode_file_descriptor, encode_chunk, encode_file_descriptor,
};
use crate::{HistoryStatus, LocalCommit, VaultError, check_directory_name, classify_heads};

const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const LANES: u32 = 4;
const COMMIT_KIND: u8 = 0x01;
const BODY_SCHEMA: u8 = 0x00;

/// What an unlocked session sees in the folder. Conflicting heads are all listed.
///
/// [`VaultStatus::Incomplete`] is a parent commit that has not arrived, or a
/// file under the head being reported whose descriptor or chunk is not in the
/// folder yet. `entries` names those files. An empty list means the missing
/// piece is a commit parent or the root directory object, not a named file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultStatus {
    Ok,
    Conflict(Vec<[u8; 32]>),
    Incomplete { entries: Vec<String> },
    Locked,
}

/// One file read chunk by chunk.
///
/// [`FileChunks::next_chunk`] returns payload bytes only after that chunk's
/// ciphertext opens and [`crate::check_chunk_identity`] accepts its ordinal.
/// A missing, reordered, duplicated, or truncated chunk is
/// [`VaultError::Unavailable`] and that chunk's bytes are not returned.
pub struct FileChunks<'a> {
    session: &'a Session,
    file_id: [u8; 16],
    chunks: Vec<[u8; 32]>,
    size: u64,
    index: usize,
    total: u64,
    seen: Vec<[u8; 32]>,
    failed: bool,
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

    /// `Ok` is one complete head whose reachable files are in the folder.
    /// `Conflict` lists every head when the selected head is not waiting on a
    /// file. `Incomplete` names files whose chunk or descriptor is absent.
    /// A present object that does not decrypt is [`VaultError::Unavailable`].
    /// `Locked` means the root secret is gone.
    pub fn status(&self) -> Result<VaultStatus, VaultError> {
        if self.root.is_none() {
            return Ok(VaultStatus::Locked);
        }
        let commits = self.load_commits()?;
        let view = classify_heads(&commits).map_err(|_| VaultError::Unavailable)?;
        match view.status {
            HistoryStatus::Empty => Ok(VaultStatus::Incomplete {
                entries: Vec::new(),
            }),
            HistoryStatus::Incomplete { head } => {
                let waiting = self.waiting_entries(head)?;
                Ok(VaultStatus::Incomplete {
                    entries: waiting.entries,
                })
            }
            HistoryStatus::Single { head } => Ok(self.file_gap_status(head)?),
            HistoryStatus::Conflict { heads } => {
                if let Some(selected) = self.selected
                    && heads.contains(&selected)
                {
                    let waiting = self.waiting_entries(selected)?;
                    if waiting.blocked {
                        return Ok(VaultStatus::Incomplete {
                            entries: waiting.entries,
                        });
                    }
                }
                Ok(VaultStatus::Conflict(heads))
            }
        }
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
    /// Each entry is an empty subdirectory, and that subdirectory object is
    /// written before it is linked. A file entry is rejected and nothing is
    /// written: files are added with [`Session::write_file`]. Names are stored
    /// in NFC. The same name twice, including NFC and NFD spellings, is
    /// [`VaultError::DuplicateName`] and writes nothing. Other heads are not
    /// modified. On success the selection moves to the new commit. The
    /// selection is not written into the folder.
    pub fn append_directory(
        &mut self,
        head: [u8; 32],
        entries: &[(&str, ChildKind)],
    ) -> Result<[u8; 32], VaultError> {
        self.require_head(head)?;
        let planned = plan_directory_entries(entries)?;
        if planned
            .iter()
            .any(|(_, kind)| *kind != ChildKind::Directory)
        {
            return Err(VaultError::Unavailable);
        }
        let dir_id: [u8; 16] = random_array()?;
        let mut stored = Vec::with_capacity(planned.len());
        for (name, _) in planned {
            let child_logical: [u8; 16] = random_array()?;
            let child_object: [u8; 32] = random_array()?;
            let child =
                encode_directory(&child_logical, Some(&dir_id), &[]).map_err(directory_error)?;
            self.put_plaintext(child_object, &child)?;
            stored.push(DirectoryEntry {
                name,
                kind: ChildKind::Directory,
                object_id: child_object,
            });
        }
        self.commit_entries(head, dir_id, &stored)
    }

    /// Entries in the selected head's root directory, in stored name order.
    pub fn list_directory(&self) -> Result<Vec<DirectoryEntry>, VaultError> {
        let head = self.selected_id()?;
        Ok(self.decoded_directory(head)?.entries)
    }

    /// Add one file under the selected head and commit that directory.
    ///
    /// An empty payload stores no chunks. Any other payload is split into
    /// chunks of at most [`crate::file_body::MAX_CHUNK_PAYLOAD`] bytes, each
    /// checked with [`crate::check_chunk_identity`] before it is stored.
    /// [`Session::read_file`] checks every chunk again and returns nothing if
    /// one is missing or fails to open. An existing name is
    /// [`VaultError::DuplicateName`] and writes nothing. Other heads are not
    /// modified. On success the selection moves to the new commit.
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
        let object_id = self.store_new_file(&loaded.dir_id, bytes)?;
        loaded.entries.push(DirectoryEntry {
            name,
            kind: ChildKind::File,
            object_id,
        });
        self.commit_entries(head, loaded.dir_id, &loaded.entries)
    }

    /// Replace one file under the selected head with a new file object.
    ///
    /// The new commit points at the new descriptor. Previous descriptor and
    /// chunk objects stay on disk. [`Session::write_file`] on that name still
    /// returns [`VaultError::DuplicateName`]. A missing name writes nothing.
    pub fn replace_file(
        &mut self,
        head: [u8; 32],
        name: &str,
        bytes: &[u8],
    ) -> Result<[u8; 32], VaultError> {
        self.require_head(head)?;
        let name = check_directory_name(name).map_err(|_| VaultError::RejectedName)?;
        let mut loaded = self.loaded_directory(head)?;
        let Some(index) = loaded.entries.iter().position(|entry| entry.name == name) else {
            return Err(VaultError::Unavailable);
        };
        if loaded.entries[index].kind != ChildKind::File {
            return Err(VaultError::Unavailable);
        }
        let object_id = self.store_new_file(&loaded.dir_id, bytes)?;
        loaded.entries[index].object_id = object_id;
        self.commit_entries(head, loaded.dir_id, &loaded.entries)
    }

    /// Unlink one name in a new commit. The named object is left on disk.
    ///
    /// A missing name writes nothing.
    pub fn delete_entry(&mut self, head: [u8; 32], name: &str) -> Result<[u8; 32], VaultError> {
        self.require_head(head)?;
        let name = check_directory_name(name).map_err(|_| VaultError::RejectedName)?;
        let mut loaded = self.loaded_directory(head)?;
        let before = loaded.entries.len();
        loaded.entries.retain(|entry| entry.name != name);
        if loaded.entries.len() == before {
            return Err(VaultError::Unavailable);
        }
        self.commit_entries(head, loaded.dir_id, &loaded.entries)
    }

    /// Bytes of one file in the selected head's directory.
    ///
    /// This collects [`Session::read_file_chunks`]. A failure clears the buffer
    /// and returns [`VaultError::Unavailable`] with no partial plaintext.
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        let mut stream = self.read_file_chunks(name)?;
        let mut payload = Vec::new();
        loop {
            match stream.next_chunk() {
                Ok(Some(chunk)) => payload.extend(chunk),
                Ok(None) => return Ok(payload),
                Err(error) => {
                    payload.clear();
                    return Err(error);
                }
            }
        }
    }

    /// Open a chunk-by-chunk read of one file under the selected head.
    ///
    /// Each [`FileChunks::next_chunk`] call checks the AEAD, the manifest
    /// index, and `check_chunk_identity` before returning that chunk. The call
    /// that follows the last chunk checks that the byte count matches the
    /// descriptor.
    pub fn read_file_chunks<'a>(&'a self, name: &str) -> Result<FileChunks<'a>, VaultError> {
        let descriptor = self.open_file_descriptor(name)?;
        Ok(FileChunks {
            session: self,
            file_id: descriptor.file_id,
            chunks: descriptor.chunks,
            size: descriptor.size,
            index: 0,
            total: 0,
            seen: Vec::new(),
            failed: false,
        })
    }

    fn open_file_descriptor(
        &self,
        name: &str,
    ) -> Result<crate::file_body::FileDescriptor, VaultError> {
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
        Ok(descriptor)
    }

    fn file_gap_status(&self, head: [u8; 32]) -> Result<VaultStatus, VaultError> {
        let waiting = self.waiting_entries(head)?;
        if waiting.blocked {
            Ok(VaultStatus::Incomplete {
                entries: waiting.entries,
            })
        } else {
            Ok(VaultStatus::Ok)
        }
    }

    fn waiting_entries(&self, commit: [u8; 32]) -> Result<WaitingEntries, VaultError> {
        let commit_plain = self.read_object(commit)?;
        let root_id = read_commit_root(&commit_plain).map_err(|_| VaultError::Unavailable)?;
        let mut entries = Vec::new();
        let blocked = match self.read_object_optional(root_id)? {
            None => true,
            Some(plain) => {
                let directory = decode_directory(&plain).map_err(|_| VaultError::Unavailable)?;
                self.collect_waiting(&directory, "", 0, &mut entries)?;
                !entries.is_empty()
            }
        };
        entries.sort();
        entries.dedup();
        Ok(WaitingEntries { blocked, entries })
    }

    fn collect_waiting(
        &self,
        directory: &DecodedDirectory,
        prefix: &str,
        depth: usize,
        entries: &mut Vec<String>,
    ) -> Result<(), VaultError> {
        if depth > 64 {
            return Err(VaultError::Unavailable);
        }
        for entry in &directory.entries {
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{prefix}/{}", entry.name)
            };
            match entry.kind {
                ChildKind::File => {
                    if self.file_is_waiting(entry, &directory.dir_id)? {
                        entries.push(path);
                    }
                }
                ChildKind::Directory => match self.read_object_optional(entry.object_id)? {
                    None => entries.push(path),
                    Some(plain) => {
                        let child =
                            decode_directory(&plain).map_err(|_| VaultError::Unavailable)?;
                        self.collect_waiting(&child, &path, depth + 1, entries)?;
                    }
                },
            }
        }
        Ok(())
    }

    fn file_is_waiting(
        &self,
        entry: &DirectoryEntry,
        parent_dir: &[u8; 16],
    ) -> Result<bool, VaultError> {
        let Some(plain) = self.read_object_optional(entry.object_id)? else {
            return Ok(true);
        };
        let descriptor = decode_file_descriptor(&plain).map_err(|_| VaultError::Unavailable)?;
        if descriptor.parent_dir_id != *parent_dir {
            return Err(VaultError::Unavailable);
        }
        for chunk_id in descriptor.chunks {
            if self.read_object_optional(chunk_id)?.is_none() {
                return Ok(true);
            }
        }
        Ok(false)
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

    fn store_new_file(&self, dir_id: &[u8; 16], bytes: &[u8]) -> Result<[u8; 32], VaultError> {
        let count = chunk_count(bytes.len()).map_err(|_| VaultError::Unavailable)?;
        let file_id: [u8; 16] = random_array()?;
        let mut chunks = Vec::with_capacity(count);
        for (index, piece) in bytes
            .chunks(crate::file_body::MAX_CHUNK_PAYLOAD)
            .enumerate()
        {
            let ordinal = u32::try_from(index).map_err(|_| VaultError::Unavailable)?;
            let chunk_id: [u8; 32] = random_array()?;
            let plain =
                encode_chunk(&file_id, ordinal, piece).map_err(|_| VaultError::Unavailable)?;
            self.put_plaintext(chunk_id, &plain)?;
            chunks.push(chunk_id);
        }
        if chunks.len() != count {
            return Err(VaultError::Unavailable);
        }
        let descriptor_id: [u8; 32] = random_array()?;
        let size = u64::try_from(bytes.len()).map_err(|_| VaultError::Unavailable)?;
        let descriptor = encode_file_descriptor(&file_id, dir_id, size, &chunks)
            .map_err(|_| VaultError::Unavailable)?;
        self.put_plaintext(descriptor_id, &descriptor)?;
        Ok(descriptor_id)
    }

    fn commit_entries(
        &mut self,
        head: [u8; 32],
        dir_id: [u8; 16],
        entries: &[DirectoryEntry],
    ) -> Result<[u8; 32], VaultError> {
        let directory_object: [u8; 32] = random_array()?;
        let directory = encode_directory(&dir_id, None, entries).map_err(directory_error)?;
        self.put_plaintext(directory_object, &directory)?;
        let commit = self.write_child_commit(head, directory_object)?;
        self.selected = Some(commit);
        Ok(commit)
    }

    fn write_genesis(&mut self) -> Result<[u8; 32], VaultError> {
        let dir_id: [u8; 16] = random_array()?;
        let directory_object: [u8; 32] = random_array()?;
        let directory = encode_directory(&dir_id, None, &[]).map_err(directory_error)?;
        self.put_plaintext(directory_object, &directory)?;
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

struct WaitingEntries {
    blocked: bool,
    entries: Vec<String>,
}

struct LoadedDirectory {
    dir_id: [u8; 16],
    entries: Vec<DirectoryEntry>,
}

impl FileChunks<'_> {
    /// The next verified chunk, or `Ok(None)` after the last chunk when the
    /// byte count matches the descriptor.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, VaultError> {
        if self.failed {
            return Err(VaultError::Unavailable);
        }
        if self.index == self.chunks.len() {
            if self.total != self.size {
                self.failed = true;
                return Err(VaultError::Unavailable);
            }
            return Ok(None);
        }
        let chunk_id = self.chunks[self.index];
        if self.seen.contains(&chunk_id) {
            self.failed = true;
            return Err(VaultError::Unavailable);
        }
        let plain = match self.session.read_object(chunk_id) {
            Ok(plain) => plain,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        let ordinal = match u32::try_from(self.index) {
            Ok(ordinal) => ordinal,
            Err(_) => {
                self.failed = true;
                return Err(VaultError::Unavailable);
            }
        };
        let piece = match chunk_payload(&plain, &self.file_id, ordinal) {
            Ok(piece) => piece.to_vec(),
            Err(_) => {
                self.failed = true;
                return Err(VaultError::Unavailable);
            }
        };
        let added = match u64::try_from(piece.len()) {
            Ok(added) => added,
            Err(_) => {
                self.failed = true;
                return Err(VaultError::Unavailable);
            }
        };
        let Some(total) = self.total.checked_add(added) else {
            self.failed = true;
            return Err(VaultError::Unavailable);
        };
        if total > self.size {
            self.failed = true;
            return Err(VaultError::Unavailable);
        }
        self.seen.push(chunk_id);
        self.index += 1;
        self.total = total;
        Ok(Some(piece))
    }
}

fn plan_directory_entries(
    entries: &[(&str, ChildKind)],
) -> Result<Vec<(String, ChildKind)>, VaultError> {
    if entries.len() > 4096 {
        return Err(VaultError::Unavailable);
    }
    let mut planned = Vec::with_capacity(entries.len());
    for (name, kind) in entries {
        let stored = check_directory_name(name).map_err(|_| VaultError::RejectedName)?;
        planned.push((stored, *kind));
    }
    planned.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    for pair in planned.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(VaultError::DuplicateName);
        }
    }
    Ok(planned)
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
    use crate::file_body::{MAX_CHUNK_PAYLOAD, decode_file_descriptor};
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

    fn entry_object(session: &Session, name: &str) -> [u8; 32] {
        session
            .list_directory()
            .expect("list")
            .into_iter()
            .find(|entry| entry.name == name)
            .expect(name)
            .object_id
    }

    fn read_all_chunks(session: &Session, name: &str) -> Result<Vec<u8>, VaultError> {
        let mut stream = session.read_file_chunks(name)?;
        let mut out = Vec::new();
        loop {
            match stream.next_chunk()? {
                Some(chunk) => out.extend(chunk),
                None => return Ok(out),
            }
        }
    }

    fn assert_manifest_faults(session: &Session, folder: &Path, over: &[u8]) {
        use crate::file_body::{encode_chunk, encode_file_descriptor};
        let descriptor_id = entry_object(session, "over");
        let descriptor_path = folder.join(hex_id(&descriptor_id));
        let original_descriptor = fs::read(&descriptor_path).expect("descriptor bytes");
        let plain = session
            .read_object(descriptor_id)
            .expect("descriptor plain");
        let descriptor = decode_file_descriptor(&plain).expect("descriptor");
        let root = session.root.as_ref().expect("unlocked");

        let truncated = encode_file_descriptor(
            &descriptor.file_id,
            &descriptor.parent_dir_id,
            u64::try_from(over.len()).expect("size"),
            &descriptor.chunks[..1],
        )
        .expect("truncated manifest");
        let sealed =
            seal_object(root, &session.vault_id, &descriptor_id, &truncated).expect("seal");
        fs::write(&descriptor_path, &sealed).expect("write truncated");
        let mut stream = session.read_file_chunks("over").expect("truncated stream");
        let first = stream
            .next_chunk()
            .expect("truncated first")
            .expect("chunk");
        assert_eq!(first.len(), MAX_CHUNK_PAYLOAD);
        assert_eq!(stream.next_chunk().err(), Some(VaultError::Unavailable));

        let duplicated = encode_file_descriptor(
            &descriptor.file_id,
            &descriptor.parent_dir_id,
            descriptor.size,
            &[descriptor.chunks[0], descriptor.chunks[0]],
        )
        .expect("duplicated manifest");
        let sealed =
            seal_object(root, &session.vault_id, &descriptor_id, &duplicated).expect("seal");
        fs::write(&descriptor_path, &sealed).expect("write duplicated");
        let mut stream = session.read_file_chunks("over").expect("duplicated stream");
        assert!(stream.next_chunk().expect("dup first").is_some());
        assert_eq!(stream.next_chunk().err(), Some(VaultError::Unavailable));

        fs::write(&descriptor_path, &original_descriptor).expect("restore descriptor");
        let chunk_id = descriptor.chunks[0];
        let chunk_path = folder.join(hex_id(&chunk_id));
        let original_chunk = fs::read(&chunk_path).expect("chunk bytes");
        let reordered = encode_chunk(&descriptor.file_id, 1, b"nope").expect("wrong ordinal");
        let sealed =
            seal_object(root, &session.vault_id, &chunk_id, &reordered).expect("seal chunk");
        fs::write(&chunk_path, &sealed).expect("write reordered");
        let mut stream = session.read_file_chunks("over").expect("reordered stream");
        assert_eq!(stream.next_chunk().err(), Some(VaultError::Unavailable));
        fs::write(&chunk_path, &original_chunk).expect("restore chunk");
        assert_eq!(read_all_chunks(session, "over").expect("restored"), over);
    }

    fn chunk_ids(session: &Session, name: &str) -> Vec<[u8; 32]> {
        let plain = session
            .read_object(entry_object(session, name))
            .expect("descriptor");
        decode_file_descriptor(&plain)
            .expect("decode descriptor")
            .chunks
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
        let before_files = snapshot(&scratch.0);
        assert_eq!(
            session
                .append_directory(
                    genesis,
                    &[("b", ChildKind::File), ("notes", ChildKind::Directory)]
                )
                .err(),
            Some(VaultError::Unavailable)
        );
        assert_eq!(snapshot(&scratch.0), before_files);
        let child = session
            .append_directory(genesis, &[("notes", ChildKind::Directory)])
            .expect("directory");
        assert_eq!(listed_names(&session), vec!["notes".to_string()]);
        let notes = session
            .list_directory()
            .expect("list notes")
            .into_iter()
            .find(|entry| entry.name == "notes")
            .expect("notes entry");
        let notes_plain = session.read_object(notes.object_id).expect("notes object");
        let notes_dir = crate::directory_body::decode_directory(&notes_plain).expect("empty dir");
        assert!(notes_dir.entries.is_empty());
        let file_commit = session
            .write_file(child, "e\u{0301}", b"synthetic-file")
            .expect("file");
        assert_eq!(
            listed_names(&session),
            vec!["notes".to_string(), "é".to_string()]
        );
        assert_eq!(session.read_file("é").expect("nfc"), b"synthetic-file");
        assert_eq!(
            session.read_file("e\u{0301}").expect("nfd"),
            b"synthetic-file"
        );
        assert_eq!(
            session.read_file("notes").err(),
            Some(VaultError::Unavailable)
        );
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
            vec!["notes".to_string(), "é".to_string()]
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
            .append_directory(genesis, &[("left", ChildKind::Directory)])
            .expect("left dir");
        let right_head = right
            .append_directory(genesis, &[("right", ChildKind::Directory)])
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
            .append_directory(left_head, &[("more", ChildKind::Directory)])
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
    fn multi_chunk_replace_and_a_bad_chunk_return_nothing() {
        let scratch = Scratch::new();
        let mut session = create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        let mut head = only_head(&session);
        let before_select = snapshot(&scratch.0);
        session.select_head(head).expect("select");
        assert_eq!(snapshot(&scratch.0), before_select);
        let copy_path = scratch.0.join("notes (1)");
        let conflicted_path = scratch.0.join("notes (conflicted copy)");
        fs::write(&copy_path, b"drive-copy").expect("copy");
        fs::write(&conflicted_path, b"dropbox-copy").expect("conflicted");

        head = session.write_file(head, "empty", b"").expect("empty file");
        assert_eq!(session.read_file("empty").expect("empty read"), b"");
        assert!(chunk_ids(&session, "empty").is_empty());

        let exact = vec![0x11u8; MAX_CHUNK_PAYLOAD];
        head = session.write_file(head, "exact", &exact).expect("exact");
        assert_eq!(chunk_ids(&session, "exact").len(), 1);
        assert_eq!(session.read_file("exact").expect("exact read"), exact);

        let mut over = vec![0x22u8; MAX_CHUNK_PAYLOAD];
        over.push(0x33);
        head = session.write_file(head, "over", &over).expect("over");
        assert_eq!(chunk_ids(&session, "over").len(), 2);
        assert_eq!(session.read_file("over").expect("over read"), over);
        drop(session);

        let mut opened = open_vault(&scratch.0, "synthetic-vault-pass").expect("reopen");
        opened.select_head(head).expect("select reopened");
        assert_eq!(opened.read_file("empty").expect("empty again"), b"");
        assert_eq!(opened.read_file("exact").expect("exact again"), exact);
        assert_eq!(opened.read_file("over").expect("over again"), over);
        assert_eq!(
            read_all_chunks(&opened, "empty").expect("stream empty"),
            b""
        );
        assert_eq!(
            read_all_chunks(&opened, "exact").expect("stream exact"),
            exact
        );
        let mut streamed = opened.read_file_chunks("over").expect("stream over");
        let first = streamed.next_chunk().expect("first").expect("some first");
        assert_eq!(first.len(), MAX_CHUNK_PAYLOAD);
        let second = streamed.next_chunk().expect("second").expect("some second");
        assert_eq!(second, &[0x33]);
        assert_eq!(streamed.next_chunk().expect("done"), None);
        assert_manifest_faults(&opened, &scratch.0, &over);

        let old_descriptor = entry_object(&opened, "empty");
        let old_bytes = fs::read(scratch.0.join(hex_id(&old_descriptor))).expect("old descriptor");
        head = opened
            .replace_file(head, "empty", b"replaced")
            .expect("replace");
        assert_eq!(opened.read_file("empty").expect("replaced"), b"replaced");
        assert_ne!(entry_object(&opened, "empty"), old_descriptor);
        assert_eq!(
            fs::read(scratch.0.join(hex_id(&old_descriptor))).expect("old remains"),
            old_bytes
        );
        assert_eq!(
            opened.write_file(head, "empty", b"other").err(),
            Some(VaultError::DuplicateName)
        );
        assert_eq!(
            opened.read_file("empty").expect("still replaced"),
            b"replaced"
        );
        assert_eq!(opened.heads().expect("one head"), vec![head]);

        let exact_descriptor = entry_object(&opened, "exact");
        let exact_bytes =
            fs::read(scratch.0.join(hex_id(&exact_descriptor))).expect("exact descriptor");
        head = opened.delete_entry(head, "exact").expect("unlink");
        assert!(!listed_names(&opened).iter().any(|name| name == "exact"));
        assert_eq!(
            opened.read_file("exact").err(),
            Some(VaultError::Unavailable)
        );
        assert_eq!(
            fs::read(scratch.0.join(hex_id(&exact_descriptor))).expect("exact remains"),
            exact_bytes
        );
        assert_eq!(opened.read_file("over").expect("over still"), over);
        assert_eq!(fs::read(&copy_path).expect("copy"), b"drive-copy");
        assert_eq!(
            fs::read(&conflicted_path).expect("conflicted"),
            b"dropbox-copy"
        );

        let over_chunks = chunk_ids(&opened, "over");
        let missing_path = scratch.0.join(hex_id(&over_chunks[1]));
        let missing_bytes = fs::read(&missing_path).expect("second chunk bytes");
        fs::remove_file(&missing_path).expect("drop second chunk");
        assert_eq!(
            opened.read_file("over").err(),
            Some(VaultError::Unavailable)
        );
        let mut missing_stream = opened.read_file_chunks("over").expect("open stream");
        assert!(
            missing_stream
                .next_chunk()
                .expect("verified prefix")
                .is_some()
        );
        assert_eq!(
            missing_stream.next_chunk().err(),
            Some(VaultError::Unavailable)
        );
        assert_eq!(
            opened.status().expect("missing chunk"),
            VaultStatus::Incomplete {
                entries: vec!["over".to_string()]
            }
        );
        assert_eq!(opened.read_file("empty").expect("other file"), b"replaced");
        fs::write(&missing_path, &missing_bytes).expect("chunk returns");
        assert_eq!(opened.status().expect("chunk arrived"), VaultStatus::Ok);
        assert_eq!(opened.read_file("over").expect("over restored"), over);

        let mut tampered = fs::read(scratch.0.join(hex_id(&over_chunks[0]))).expect("first chunk");
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        fs::write(scratch.0.join(hex_id(&over_chunks[0])), &tampered).expect("tamper");
        assert_eq!(opened.status().err(), Some(VaultError::Unavailable));
        assert_eq!(
            opened.read_file("over").err(),
            Some(VaultError::Unavailable)
        );
        assert_eq!(
            fs::read(&copy_path).expect("copy after tamper"),
            b"drive-copy"
        );
        assert_eq!(
            fs::read(&conflicted_path).expect("conflicted after tamper"),
            b"dropbox-copy"
        );
        let _ = head;
    }

    #[test]
    fn a_missing_parent_is_incomplete() {
        let scratch = Scratch::new();
        let mut session = create_vault(&scratch.0, "synthetic-vault-pass").expect("create");
        let genesis = only_head(&session);
        session.select_head(genesis).expect("select");
        let child = session
            .append_directory(genesis, &[("kept", ChildKind::Directory)])
            .expect("child");
        fs::remove_file(scratch.0.join(hex_id(&genesis))).expect("remove parent");
        assert_eq!(
            session.status().expect("incomplete"),
            VaultStatus::Incomplete { entries: vec![] }
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
