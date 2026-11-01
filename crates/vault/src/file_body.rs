//! File descriptor and file chunks.
//!
//! A descriptor is kind `0x03`. Its chunk list is ordered: index 0 is ordinal 0.
//! A chunk is kind `0x04` followed by `file_id`, a big-endian ordinal, and the
//! file bytes. [`crate::check_chunk_identity`] accepts a chunk only when those
//! two fields match the caller. An empty file has zero chunks. A non-empty
//! file is split into pieces of at most [`MAX_CHUNK_PAYLOAD`] bytes. This is
//! not a general CBOR decoder.

use crate::check_chunk_identity;
use crate::narrow_cbor::{self, Cursor};

const FILE_KIND: u8 = 0x03;
const CHUNK_KIND: u8 = 0x04;
const BODY_SCHEMA: u8 = 0x00;
const CHUNK_PREFIX: usize = 22;
/// Largest `file_bytes` in one chunk. Plaintext cap is 1,048,576, minus the
/// 22-byte chunk prefix.
pub const MAX_CHUNK_PAYLOAD: usize = 1_048_576 - CHUNK_PREFIX;
pub const MAX_CHUNKS: usize = 8192;

/// How many chunks `len` file bytes need.
///
/// Zero is an empty file: no chunk objects. More than [`MAX_CHUNKS`] is rejected.
pub fn chunk_count(len: usize) -> Result<usize, FileBodyError> {
    if len == 0 {
        return Ok(0);
    }
    let Some(max_total) = MAX_CHUNKS.checked_mul(MAX_CHUNK_PAYLOAD) else {
        return Err(FileBodyError::Unreadable);
    };
    if len > max_total {
        return Err(FileBodyError::Unreadable);
    }
    Ok(len.div_ceil(MAX_CHUNK_PAYLOAD))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptor {
    pub file_id: [u8; 16],
    pub parent_dir_id: [u8; 16],
    pub size: u64,
    pub chunks: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBodyError {
    Unreadable,
}

pub fn encode_file_descriptor(
    file_id: &[u8; 16],
    parent_dir_id: &[u8; 16],
    size: u64,
    chunks: &[[u8; 32]],
) -> Result<Vec<u8>, FileBodyError> {
    if chunks.len() > MAX_CHUNKS {
        return Err(FileBodyError::Unreadable);
    }
    let mut body = vec![FILE_KIND, BODY_SCHEMA];
    narrow_cbor::encode_len(&mut body, 5, 4);
    narrow_cbor::encode_uint(&mut body, 0);
    narrow_cbor::encode_bstr(&mut body, file_id);
    narrow_cbor::encode_uint(&mut body, 1);
    narrow_cbor::encode_bstr(&mut body, parent_dir_id);
    narrow_cbor::encode_uint(&mut body, 2);
    narrow_cbor::encode_uint(&mut body, size);
    narrow_cbor::encode_uint(&mut body, 3);
    narrow_cbor::encode_len(&mut body, 4, chunks.len());
    for chunk in chunks {
        narrow_cbor::encode_bstr(&mut body, chunk);
    }
    Ok(body)
}

pub fn decode_file_descriptor(bytes: &[u8]) -> Result<FileDescriptor, FileBodyError> {
    if bytes.len() < 2 || bytes[0] != FILE_KIND || bytes[1] != BODY_SCHEMA {
        return Err(FileBodyError::Unreadable);
    }
    let mut cursor = Cursor::new(&bytes[2..]);
    cursor.map_len(4).map_err(|_| FileBodyError::Unreadable)?;
    if cursor.uint().map_err(|_| FileBodyError::Unreadable)? != 0 {
        return Err(FileBodyError::Unreadable);
    }
    let file_id = id16(&mut cursor)?;
    if cursor.uint().map_err(|_| FileBodyError::Unreadable)? != 1 {
        return Err(FileBodyError::Unreadable);
    }
    let parent_dir_id = id16(&mut cursor)?;
    if cursor.uint().map_err(|_| FileBodyError::Unreadable)? != 2 {
        return Err(FileBodyError::Unreadable);
    }
    let size = cursor.uint().map_err(|_| FileBodyError::Unreadable)?;
    if cursor.uint().map_err(|_| FileBodyError::Unreadable)? != 3 {
        return Err(FileBodyError::Unreadable);
    }
    let count = cursor
        .array_len(MAX_CHUNKS)
        .map_err(|_| FileBodyError::Unreadable)?;
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        chunks.push(id32(&mut cursor)?);
    }
    if !cursor.is_exhausted() {
        return Err(FileBodyError::Unreadable);
    }
    Ok(FileDescriptor {
        file_id,
        parent_dir_id,
        size,
        chunks,
    })
}

/// Build a chunk and accept it only when [`check_chunk_identity`] agrees.
pub fn encode_chunk(
    file_id: &[u8; 16],
    ordinal: u32,
    payload: &[u8],
) -> Result<Vec<u8>, FileBodyError> {
    if payload.len() > MAX_CHUNK_PAYLOAD {
        return Err(FileBodyError::Unreadable);
    }
    let mut body = Vec::with_capacity(CHUNK_PREFIX + payload.len());
    body.push(CHUNK_KIND);
    body.push(BODY_SCHEMA);
    body.extend_from_slice(file_id);
    body.extend_from_slice(&ordinal.to_be_bytes());
    body.extend_from_slice(payload);
    check_chunk_identity(&body, file_id, ordinal).map_err(|_| FileBodyError::Unreadable)?;
    Ok(body)
}

/// Payload bytes after [`check_chunk_identity`] accepts `file_id` and `ordinal`.
pub fn chunk_payload<'a>(
    decrypted: &'a [u8],
    file_id: &[u8; 16],
    ordinal: u32,
) -> Result<&'a [u8], FileBodyError> {
    check_chunk_identity(decrypted, file_id, ordinal).map_err(|_| FileBodyError::Unreadable)?;
    Ok(&decrypted[CHUNK_PREFIX..])
}

fn id16(cursor: &mut Cursor<'_>) -> Result<[u8; 16], FileBodyError> {
    let bytes = cursor
        .bytes_exact(16)
        .map_err(|_| FileBodyError::Unreadable)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn id32(cursor: &mut Cursor<'_>) -> Result<[u8; 32], FileBodyError> {
    let bytes = cursor
        .bytes_exact(32)
        .map_err(|_| FileBodyError::Unreadable)?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eidoron_test_vectors::directory_object::{CHUNK_SYNTHETIC, FILE_DESCRIPTOR_SYNTHETIC};

    #[test]
    fn descriptor_and_chunk_match_the_python_oracle() {
        let descriptor =
            encode_file_descriptor(&[0x44; 16], &[0x11; 16], 9, &[[0x55; 32]]).expect("descriptor");
        assert_eq!(descriptor, FILE_DESCRIPTOR_SYNTHETIC);
        let decoded = decode_file_descriptor(FILE_DESCRIPTOR_SYNTHETIC).expect("decode");
        assert_eq!(decoded.file_id, [0x44; 16]);
        assert_eq!(decoded.parent_dir_id, [0x11; 16]);
        assert_eq!(decoded.size, 9);
        assert_eq!(decoded.chunks, vec![[0x55; 32]]);
        let chunk = encode_chunk(&[0x44; 16], 0, b"synthetic").expect("chunk");
        assert_eq!(chunk, CHUNK_SYNTHETIC);
        assert_eq!(
            chunk_payload(CHUNK_SYNTHETIC, &[0x44; 16], 0).expect("payload"),
            b"synthetic"
        );
        assert!(chunk_payload(CHUNK_SYNTHETIC, &[0x44; 16], 1).is_err());
    }

    #[test]
    fn chunk_count_matches_the_size_limit() {
        assert_eq!(chunk_count(0).expect("empty file"), 0);
        assert_eq!(chunk_count(MAX_CHUNK_PAYLOAD).expect("exact"), 1);
        assert_eq!(chunk_count(MAX_CHUNK_PAYLOAD + 1).expect("over"), 2);
        let max_total = MAX_CHUNKS * MAX_CHUNK_PAYLOAD;
        assert_eq!(chunk_count(max_total).expect("cap"), MAX_CHUNKS);
        assert_eq!(chunk_count(max_total + 1), Err(FileBodyError::Unreadable));

        let exact = vec![0x11u8; MAX_CHUNK_PAYLOAD];
        assert_eq!(exact.chunks(MAX_CHUNK_PAYLOAD).count(), 1);
        let mut over = exact;
        over.push(0x22);
        let parts: Vec<&[u8]> = over.chunks(MAX_CHUNK_PAYLOAD).collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), MAX_CHUNK_PAYLOAD);
        assert_eq!(parts[1], &[0x22]);
        let encoded = encode_chunk(&[0x44; 16], 1, parts[1]).expect("second chunk");
        assert_eq!(
            chunk_payload(&encoded, &[0x44; 16], 1).expect("open second"),
            &[0x22]
        );
    }
}
