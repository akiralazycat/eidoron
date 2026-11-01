//! File descriptor and file chunks.
//!
//! A descriptor is kind `0x03`. Its chunk list is ordered: index 0 is ordinal 0.
//! A chunk is kind `0x04`, schema `0x01`, then `file_id`, a big-endian ordinal,
//! the unpadded payload length, the payload, and zero padding of the last
//! chunk up to a size bucket. [`crate::check_chunk_identity`] accepts a chunk
//! only when `file_id` and ordinal match. An empty file has zero chunks. A
//! non-empty file is split into pieces of at most [`MAX_CHUNK_PAYLOAD`] bytes.
//! Schema `0x00` chunks are not read. This is not a general CBOR decoder.

use crate::check_chunk_identity;
use crate::chunk_identity::CHUNK_HEADER_LEN;
use crate::narrow_cbor::{self, Cursor};

const FILE_KIND: u8 = 0x03;
const CHUNK_KIND: u8 = 0x04;
const BODY_SCHEMA: u8 = 0x00;
const CHUNK_SCHEMA: u8 = 0x01;
/// Smallest padded payload. A shorter last chunk is stored as this many bytes.
pub const PAD_FLOOR: usize = 4096;
/// Largest `file_bytes` in one chunk. Plaintext cap is 1,048,576, minus the
/// 26-byte chunk header.
pub const MAX_CHUNK_PAYLOAD: usize = 1_048_576 - CHUNK_HEADER_LEN;
pub const MAX_CHUNKS: usize = 8192;

/// Bucket for a last-chunk payload.
///
/// Lengths up to [`PAD_FLOOR`] use that floor. Larger lengths use the next
/// power of two, and anything that would pass [`MAX_CHUNK_PAYLOAD`] stays at
/// that maximum. A full chunk is already the maximum and is not extended.
/// Zero is not a chunk.
pub fn padded_payload_len(true_len: usize) -> Result<usize, FileBodyError> {
    if true_len == 0 || true_len > MAX_CHUNK_PAYLOAD {
        return Err(FileBodyError::Unreadable);
    }
    if true_len == MAX_CHUNK_PAYLOAD {
        return Ok(MAX_CHUNK_PAYLOAD);
    }
    let padded = true_len
        .next_power_of_two()
        .clamp(PAD_FLOOR, MAX_CHUNK_PAYLOAD);
    Ok(padded)
}

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
///
/// `payload` is the unpadded file bytes. The stored body pads a short chunk
/// with zeros out to [`padded_payload_len`]. The unpadded length is inside
/// the body, so the AEAD covers it.
pub fn encode_chunk(
    file_id: &[u8; 16],
    ordinal: u32,
    payload: &[u8],
) -> Result<Vec<u8>, FileBodyError> {
    let padded = padded_payload_len(payload.len())?;
    let true_len = u32::try_from(payload.len()).map_err(|_| FileBodyError::Unreadable)?;
    let mut body = Vec::with_capacity(CHUNK_HEADER_LEN + padded);
    body.push(CHUNK_KIND);
    body.push(CHUNK_SCHEMA);
    body.extend_from_slice(file_id);
    body.extend_from_slice(&ordinal.to_be_bytes());
    body.extend_from_slice(&true_len.to_be_bytes());
    body.extend_from_slice(payload);
    body.resize(CHUNK_HEADER_LEN + padded, 0);
    check_chunk_identity(&body, file_id, ordinal).map_err(|_| FileBodyError::Unreadable)?;
    Ok(body)
}

/// Unpadded payload after identity, length, and zero-padding checks.
///
/// `expected_len` is the length implied by the file descriptor. It must match
/// the length stored in the chunk. Bytes after that length are not returned.
pub fn chunk_payload<'a>(
    decrypted: &'a [u8],
    file_id: &[u8; 16],
    ordinal: u32,
    expected_len: usize,
) -> Result<&'a [u8], FileBodyError> {
    check_chunk_identity(decrypted, file_id, ordinal).map_err(|_| FileBodyError::Unreadable)?;
    let stored = u32::from_be_bytes(
        decrypted[22..26]
            .try_into()
            .map_err(|_| FileBodyError::Unreadable)?,
    );
    let stored = usize::try_from(stored).map_err(|_| FileBodyError::Unreadable)?;
    if stored != expected_len {
        return Err(FileBodyError::Unreadable);
    }
    let payload = &decrypted[CHUNK_HEADER_LEN..];
    let padded = padded_payload_len(stored)?;
    if payload.len() != padded || stored > payload.len() {
        return Err(FileBodyError::Unreadable);
    }
    if payload[stored..].iter().any(|byte| *byte != 0) {
        return Err(FileBodyError::Unreadable);
    }
    Ok(&payload[..stored])
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
    use eidoron_test_vectors::directory_object::{
        CHUNK_SYNTHETIC, CHUNK_UNPADDED_V0, FILE_DESCRIPTOR_SYNTHETIC,
    };

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
            chunk_payload(CHUNK_SYNTHETIC, &[0x44; 16], 0, 9).expect("payload"),
            b"synthetic"
        );
        assert!(chunk_payload(CHUNK_SYNTHETIC, &[0x44; 16], 1, 9).is_err());
        assert!(chunk_payload(CHUNK_SYNTHETIC, &[0x44; 16], 0, 8).is_err());
        assert!(chunk_payload(CHUNK_UNPADDED_V0, &[0x44; 16], 0, 9).is_err());
    }

    #[test]
    fn last_chunk_buckets_and_padding_checks() {
        assert_eq!(padded_payload_len(1).expect("one"), PAD_FLOOR);
        assert_eq!(
            padded_payload_len(PAD_FLOOR).expect("exact floor"),
            PAD_FLOOR
        );
        assert_eq!(
            padded_payload_len(PAD_FLOOR + 1).expect("next"),
            PAD_FLOOR * 2
        );
        assert_eq!(
            padded_payload_len(PAD_FLOOR * 2).expect("exact pow"),
            PAD_FLOOR * 2
        );
        assert_eq!(
            padded_payload_len(MAX_CHUNK_PAYLOAD).expect("full"),
            MAX_CHUNK_PAYLOAD
        );
        assert_eq!(
            padded_payload_len(MAX_CHUNK_PAYLOAD - 1).expect("almost full"),
            MAX_CHUNK_PAYLOAD
        );
        assert_eq!(padded_payload_len(524_288).expect("512k"), 524_288);
        assert_eq!(
            padded_payload_len(524_289).expect("above 512k"),
            MAX_CHUNK_PAYLOAD
        );
        assert!(padded_payload_len(0).is_err());

        let one = encode_chunk(&[0x44; 16], 0, &[0x61]).expect("one byte");
        assert_eq!(one.len(), CHUNK_HEADER_LEN + PAD_FLOOR);
        assert_eq!(
            chunk_payload(&one, &[0x44; 16], 0, 1).expect("open"),
            &[0x61]
        );
        let mut dirty = one.clone();
        dirty[CHUNK_HEADER_LEN + 1] = 0x01;
        assert!(chunk_payload(&dirty, &[0x44; 16], 0, 1).is_err());

        let exact = encode_chunk(&[0x44; 16], 0, &[0x62; PAD_FLOOR]).expect("exact");
        assert_eq!(exact.len(), CHUNK_HEADER_LEN + PAD_FLOOR);
        assert_eq!(
            chunk_payload(&exact, &[0x44; 16], 0, PAD_FLOOR)
                .expect("exact open")
                .len(),
            PAD_FLOOR
        );
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
            chunk_payload(&encoded, &[0x44; 16], 1, 1).expect("open second"),
            &[0x22]
        );
    }
}
