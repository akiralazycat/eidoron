//! Encrypted-directory plaintext: kind `0x02` and the candidate directory map.
//!
//! Names are stored in NFC. Two spellings that normalize to the same string are
//! one entry. This is not a general CBOR decoder. Entries are sorted by their
//! UTF-8 bytes. At most 4096 entries are accepted.

use crate::check_directory_name;
use crate::narrow_cbor::{self, Cursor};

const DIRECTORY_KIND: u8 = 0x02;
const BODY_SCHEMA: u8 = 0x00;
const MAX_ENTRIES: usize = 4096;

/// A child recorded in a directory. `Directory` is child kind 2. `File` is 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildKind {
    Directory,
    File,
}

impl ChildKind {
    fn from_u64(value: u64) -> Option<Self> {
        match value {
            2 => Some(Self::Directory),
            3 => Some(Self::File),
            _ => None,
        }
    }

    fn to_u64(self) -> u64 {
        match self {
            Self::Directory => 2,
            Self::File => 3,
        }
    }
}

/// One directory row after NFC normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub name: String,
    pub kind: ChildKind,
    pub object_id: [u8; 32],
}

/// A decoded directory object. `parent_dir_id` is absent for a commit root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedDirectory {
    pub dir_id: [u8; 16],
    pub parent_dir_id: Option<[u8; 16]>,
    pub entries: Vec<DirectoryEntry>,
}

/// Why a directory body was not accepted. Display text does not include a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryBodyError {
    Unreadable,
    RejectedName,
    DuplicateName,
    TooMany,
}

impl std::fmt::Display for DirectoryBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "unreadable",
            Self::RejectedName => "rejected name",
            Self::DuplicateName => "duplicate name",
            Self::TooMany => "too many directory entries",
        })
    }
}

/// Encode a directory. Names are normalized and sorted. The same NFC name twice
/// is [`DirectoryBodyError::DuplicateName`] and nothing is returned.
pub fn encode_directory(
    dir_id: &[u8; 16],
    parent_dir_id: Option<&[u8; 16]>,
    entries: &[DirectoryEntry],
) -> Result<Vec<u8>, DirectoryBodyError> {
    if entries.len() > MAX_ENTRIES {
        return Err(DirectoryBodyError::TooMany);
    }
    let mut stored = Vec::with_capacity(entries.len());
    for entry in entries {
        let name =
            check_directory_name(&entry.name).map_err(|_| DirectoryBodyError::RejectedName)?;
        stored.push(DirectoryEntry {
            name,
            kind: entry.kind,
            object_id: entry.object_id,
        });
    }
    stored.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    for pair in stored.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(DirectoryBodyError::DuplicateName);
        }
    }
    let mut body = vec![DIRECTORY_KIND, BODY_SCHEMA];
    narrow_cbor::encode_len(&mut body, 5, 3);
    narrow_cbor::encode_uint(&mut body, 0);
    narrow_cbor::encode_bstr(&mut body, dir_id);
    narrow_cbor::encode_uint(&mut body, 1);
    match parent_dir_id {
        None => body.push(0xf6),
        Some(parent) => narrow_cbor::encode_bstr(&mut body, parent),
    }
    narrow_cbor::encode_uint(&mut body, 2);
    narrow_cbor::encode_len(&mut body, 4, stored.len());
    for entry in &stored {
        narrow_cbor::encode_len(&mut body, 4, 3);
        narrow_cbor::encode_text(&mut body, &entry.name);
        narrow_cbor::encode_uint(&mut body, entry.kind.to_u64());
        narrow_cbor::encode_bstr(&mut body, &entry.object_id);
    }
    Ok(body)
}

/// Read a directory body. Entries must already be strictly sorted NFC names.
pub fn decode_directory(bytes: &[u8]) -> Result<DecodedDirectory, DirectoryBodyError> {
    if bytes.len() < 2 || bytes[0] != DIRECTORY_KIND || bytes[1] != BODY_SCHEMA {
        return Err(DirectoryBodyError::Unreadable);
    }
    let mut cursor = Cursor::new(&bytes[2..]);
    cursor
        .map_len(3)
        .map_err(|_| DirectoryBodyError::Unreadable)?;
    if cursor.uint().map_err(|_| DirectoryBodyError::Unreadable)? != 0 {
        return Err(DirectoryBodyError::Unreadable);
    }
    let dir_id = id16(&mut cursor)?;
    if cursor.uint().map_err(|_| DirectoryBodyError::Unreadable)? != 1 {
        return Err(DirectoryBodyError::Unreadable);
    }
    let parent_dir_id = optional_id16(&mut cursor)?;
    if cursor.uint().map_err(|_| DirectoryBodyError::Unreadable)? != 2 {
        return Err(DirectoryBodyError::Unreadable);
    }
    let count = cursor
        .array_len(MAX_ENTRIES)
        .map_err(|_| DirectoryBodyError::Unreadable)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(decode_entry(&mut cursor)?);
    }
    if !cursor.is_exhausted() {
        return Err(DirectoryBodyError::Unreadable);
    }
    for pair in entries.windows(2) {
        if pair[0].name.as_bytes() >= pair[1].name.as_bytes() {
            return Err(DirectoryBodyError::Unreadable);
        }
    }
    Ok(DecodedDirectory {
        dir_id,
        parent_dir_id,
        entries,
    })
}

fn decode_entry(cursor: &mut Cursor<'_>) -> Result<DirectoryEntry, DirectoryBodyError> {
    let count = cursor
        .array_len(3)
        .map_err(|_| DirectoryBodyError::Unreadable)?;
    if count != 3 {
        return Err(DirectoryBodyError::Unreadable);
    }
    let text = cursor
        .text(crate::MAX_DIRECTORY_NAME_BYTES)
        .map_err(|_| DirectoryBodyError::Unreadable)?;
    let name = check_directory_name(&text).map_err(|_| DirectoryBodyError::Unreadable)?;
    if name != text {
        return Err(DirectoryBodyError::Unreadable);
    }
    let kind = ChildKind::from_u64(cursor.uint().map_err(|_| DirectoryBodyError::Unreadable)?)
        .ok_or(DirectoryBodyError::Unreadable)?;
    let object_id = id32(cursor)?;
    Ok(DirectoryEntry {
        name,
        kind,
        object_id,
    })
}

fn id16(cursor: &mut Cursor<'_>) -> Result<[u8; 16], DirectoryBodyError> {
    let bytes = cursor
        .bytes_exact(16)
        .map_err(|_| DirectoryBodyError::Unreadable)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn id32(cursor: &mut Cursor<'_>) -> Result<[u8; 32], DirectoryBodyError> {
    let bytes = cursor
        .bytes_exact(32)
        .map_err(|_| DirectoryBodyError::Unreadable)?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn optional_id16(cursor: &mut Cursor<'_>) -> Result<Option<[u8; 16]>, DirectoryBodyError> {
    let bytes = cursor
        .null_or_bytes(16)
        .map_err(|_| DirectoryBodyError::Unreadable)?;
    Ok(bytes.map(|bytes| {
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes);
        id
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eidoron_test_vectors::directory_object::DIRECTORY_FILE_TXT;

    fn file_txt() -> DirectoryEntry {
        DirectoryEntry {
            name: "file.txt".to_string(),
            kind: ChildKind::File,
            object_id: [0x22; 32],
        }
    }

    #[test]
    fn directory_bytes_match_the_python_oracle() {
        let encoded = encode_directory(&[0x11; 16], None, &[file_txt()]).expect("encode");
        assert_eq!(encoded, DIRECTORY_FILE_TXT);
        let decoded = decode_directory(DIRECTORY_FILE_TXT).expect("decode");
        assert_eq!(decoded.dir_id, [0x11; 16]);
        assert_eq!(decoded.parent_dir_id, None);
        assert_eq!(decoded.entries, vec![file_txt()]);
        let mut trailing = DIRECTORY_FILE_TXT.to_vec();
        trailing.push(0);
        assert_eq!(
            decode_directory(&trailing),
            Err(DirectoryBodyError::Unreadable)
        );
    }

    #[test]
    fn nfc_and_nfd_spellings_are_one_name() {
        let nfd = DirectoryEntry {
            name: "e\u{0301}".to_string(),
            kind: ChildKind::File,
            object_id: [0x22; 32],
        };
        let encoded = encode_directory(&[0x11; 16], None, &[nfd]).expect("encode nfd");
        let decoded = decode_directory(&encoded).expect("decode");
        assert_eq!(decoded.entries[0].name, "é");
        let both = [
            DirectoryEntry {
                name: "é".to_string(),
                kind: ChildKind::File,
                object_id: [1; 32],
            },
            DirectoryEntry {
                name: "e\u{0301}".to_string(),
                kind: ChildKind::Directory,
                object_id: [2; 32],
            },
        ];
        assert_eq!(
            encode_directory(&[0x11; 16], None, &both),
            Err(DirectoryBodyError::DuplicateName)
        );
        assert_eq!(
            DirectoryBodyError::DuplicateName.to_string(),
            "duplicate name"
        );
    }
}
