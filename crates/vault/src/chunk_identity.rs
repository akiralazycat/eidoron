//! File-chunk identity, compared with the caller's expectation.
//!
//! The decrypted body is `kind || schema || file_id:16 || ordinal:u32be || file_bytes`.
//! Only `file_id` and `ordinal` are compared. `file_bytes` are not hashed or scanned,
//! and no object store is consulted.

use std::fmt;

const CHUNK_KIND: u8 = 0x04;
const BODY_SCHEMA: u8 = 0x00;
const FILE_ID_LEN: usize = 16;
const ORDINAL_LEN: usize = 4;
const PREFIX_LEN: usize = 2 + FILE_ID_LEN + ORDINAL_LEN;

/// The chunk's `file_id` or `ordinal` does not match, or the body cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkIdentityError {
    /// Shorter than the fixed prefix, or schema is not `0x00`.
    Unreadable,
    /// `kind` is not the file-chunk kind `0x04`.
    NotAChunk,
    /// `file_id` or `ordinal` differs from the caller's expectation.
    Mismatch,
}

impl fmt::Display for ChunkIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "unreadable",
            Self::NotAChunk => "not a chunk",
            Self::Mismatch => "chunk identity mismatch",
        })
    }
}

/// Reject a decrypted chunk whose `file_id` or `ordinal` differs from `expected_file_id`
/// and `expected_ordinal`.
///
/// The error text does not include either identifier. Payload bytes after the
/// 22-byte prefix are ignored.
pub fn check_chunk_identity(
    decrypted: &[u8],
    expected_file_id: &[u8; FILE_ID_LEN],
    expected_ordinal: u32,
) -> Result<(), ChunkIdentityError> {
    if decrypted.is_empty() {
        return Err(ChunkIdentityError::Unreadable);
    }
    if decrypted[0] != CHUNK_KIND {
        return Err(ChunkIdentityError::NotAChunk);
    }
    if decrypted.len() < PREFIX_LEN || decrypted[1] != BODY_SCHEMA {
        return Err(ChunkIdentityError::Unreadable);
    }
    let file_id = &decrypted[2..2 + FILE_ID_LEN];
    let ordinal = u32::from_be_bytes(
        decrypted[2 + FILE_ID_LEN..PREFIX_LEN]
            .try_into()
            .expect("ordinal is 4 bytes"),
    );
    if file_id != expected_file_id || ordinal != expected_ordinal {
        return Err(ChunkIdentityError::Mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(file_id: &[u8; 16], ordinal: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREFIX_LEN + payload.len());
        out.push(CHUNK_KIND);
        out.push(BODY_SCHEMA);
        out.extend_from_slice(file_id);
        out.extend_from_slice(&ordinal);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn matching_identity_ignores_payload() {
        let file_id = [0x44; 16];
        let empty = body(&file_id, [0x00, 0x00, 0x00, 0x00], b"");
        let with_bytes = body(&file_id, [0x00, 0x00, 0x00, 0x00], b"synthetic-bytes");
        assert_eq!(check_chunk_identity(&empty, &file_id, 0), Ok(()));
        assert_eq!(check_chunk_identity(&with_bytes, &file_id, 0), Ok(()));
        let max_ordinal = body(&file_id, [0xff, 0xff, 0xff, 0xff], b"x");
        assert_eq!(
            check_chunk_identity(&max_ordinal, &file_id, u32::MAX),
            Ok(())
        );
        let one = body(&file_id, [0x00, 0x00, 0x00, 0x01], b"");
        assert_eq!(check_chunk_identity(&one, &file_id, 1), Ok(()));
    }

    #[test]
    fn file_id_or_ordinal_mismatch_is_the_same_error() {
        let file_id = [0x44; 16];
        let chunk = body(&file_id, [0x00, 0x00, 0x00, 0x02], b"synthetic");
        let mut other_id = file_id;
        other_id[15] ^= 0x01;
        let wrong_id = check_chunk_identity(&chunk, &other_id, 2).unwrap_err();
        let wrong_ordinal = check_chunk_identity(&chunk, &file_id, 3).unwrap_err();
        let both = check_chunk_identity(&chunk, &other_id, 0).unwrap_err();
        assert_eq!(wrong_id, ChunkIdentityError::Mismatch);
        assert_eq!(wrong_id, wrong_ordinal);
        assert_eq!(wrong_id, both);
        let rendered = wrong_id.to_string();
        assert_eq!(rendered, "chunk identity mismatch");
        assert!(!rendered.contains("synthetic"));
        assert!(!rendered.contains("44"));
    }

    #[test]
    fn little_endian_ordinal_bytes_do_not_match_one() {
        let file_id = [0x11; 16];
        let little = body(&file_id, [0x01, 0x00, 0x00, 0x00], b"");
        assert_eq!(
            check_chunk_identity(&little, &file_id, 1),
            Err(ChunkIdentityError::Mismatch)
        );
        assert_eq!(check_chunk_identity(&little, &file_id, 0x0100_0000), Ok(()));
    }

    #[test]
    fn short_wrong_kind_and_wrong_schema() {
        let file_id = [0x44; 16];
        assert_eq!(
            check_chunk_identity(&[], &file_id, 0),
            Err(ChunkIdentityError::Unreadable)
        );
        assert_eq!(
            check_chunk_identity(&[0x02], &file_id, 0),
            Err(ChunkIdentityError::NotAChunk)
        );
        assert_eq!(
            check_chunk_identity(&[CHUNK_KIND], &file_id, 0),
            Err(ChunkIdentityError::Unreadable)
        );
        let mut short = body(&file_id, [0, 0, 0, 0], b"");
        short.pop();
        assert_eq!(
            check_chunk_identity(&short, &file_id, 0),
            Err(ChunkIdentityError::Unreadable)
        );
        let mut bad_schema = body(&file_id, [0, 0, 0, 0], b"");
        bad_schema[1] = 0x01;
        assert_eq!(
            check_chunk_identity(&bad_schema, &file_id, 0),
            Err(ChunkIdentityError::Unreadable)
        );
    }
}
