#![forbid(unsafe_code)]
//! Shape validation for UNTRUSTED public v0 bytes only.
//!
//! A correct magic, version, length or key-derivation parameter is NOT
//! evidence of authentication, integrity, freshness or a decrypted file.
//! No cryptographic or CBOR parsing is implemented in P2.1.

pub const HEADER_LEN: usize = 136;
pub const OBJECT_PREFIX_LEN: usize = 88;
pub const HEAD_LEN: usize = 66;
pub const MIN_OBJECT_LEN: usize = 106;
pub const MAX_OBJECT_LEN: usize = 1_048_680;
pub const MIN_CIPHERTEXT_LEN: usize = 18;
pub const MAX_CIPHERTEXT_LEN: usize = 1_048_592;
const HEADER_MAGIC: &[u8; 8] = b"EIDORON\0";
const OBJECT_MAGIC: &[u8; 8] = b"EIDOBJ\0\0";
const HEAD_MAGIC: &[u8; 8] = b"EIDHEAD\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeError {
    WrongLength,
    BadMagic,
    UnsupportedVersion,
    UnsupportedSuite,
    UnsupportedFlags,
    UnsupportedKdf,
    ResourcePolicy,
}

/// Parsed bytes supplied by an untrusted storage provider.
/// This struct is NOT authenticated and MUST NOT be interpreted as a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntrustedHeader {
    pub vault_id: [u8; 16],
    pub argon_m_cost_kib: u32,
    pub argon_t_cost: u32,
    pub argon_lanes: u32,
}

/// Parsed bytes supplied by an untrusted storage provider.
/// Referencing this HEAD does not establish freshness or object authenticity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntrustedHead {
    pub vault_id: [u8; 16],
    pub generation: u64,
    pub object_id: [u8; 32],
}

/// Parsed public object envelope; ciphertext and tag are NOT authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntrustedObject {
    pub vault_id: [u8; 16],
    pub object_id: [u8; 32],
    pub ciphertext_len: usize,
}

fn uint16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn uint32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn copy_id<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut result = [0u8; N];
    result.copy_from_slice(slice);
    result
}

pub fn inspect_untrusted_header(bytes: &[u8]) -> Result<UntrustedHeader, ShapeError> {
    if bytes.len() != HEADER_LEN {
        return Err(ShapeError::WrongLength);
    }
    if &bytes[0..8] != HEADER_MAGIC {
        return Err(ShapeError::BadMagic);
    }
    if uint16(&bytes[8..10]) != 0 || uint16(&bytes[10..12]) != 0 {
        return Err(ShapeError::UnsupportedVersion);
    }
    if uint16(&bytes[12..14]) != 1 {
        return Err(ShapeError::UnsupportedSuite);
    }
    if uint16(&bytes[14..16]) != 0 {
        return Err(ShapeError::UnsupportedFlags);
    }
    if uint32(&bytes[48..52]) != 0x13 {
        return Err(ShapeError::UnsupportedKdf);
    }
    let m = uint32(&bytes[52..56]);
    let t = uint32(&bytes[56..60]);
    let lanes = uint32(&bytes[60..64]);
    // Only P1.3's candidate resource policy; benchmark/review still pending.
    if !(65_536..=262_144).contains(&m)
        || !(1..=10).contains(&t)
        || !(1..=4).contains(&lanes)
        || m < 8 * lanes
    {
        return Err(ShapeError::ResourcePolicy);
    }
    Ok(UntrustedHeader {
        vault_id: copy_id(&bytes[16..32]),
        argon_m_cost_kib: m,
        argon_t_cost: t,
        argon_lanes: lanes,
    })
}

pub fn inspect_untrusted_object(bytes: &[u8]) -> Result<UntrustedObject, ShapeError> {
    if !(MIN_OBJECT_LEN..=MAX_OBJECT_LEN).contains(&bytes.len()) {
        return Err(ShapeError::WrongLength);
    }
    if &bytes[0..8] != OBJECT_MAGIC {
        return Err(ShapeError::BadMagic);
    }
    if uint16(&bytes[8..10]) != 0 {
        return Err(ShapeError::UnsupportedVersion);
    }
    if uint16(&bytes[10..12]) != 1 {
        return Err(ShapeError::UnsupportedSuite);
    }
    let ct_len = uint32(&bytes[84..88]) as usize;
    if !(MIN_CIPHERTEXT_LEN..=MAX_CIPHERTEXT_LEN).contains(&ct_len)
        || bytes.len() != OBJECT_PREFIX_LEN + ct_len
    {
        return Err(ShapeError::WrongLength);
    }
    Ok(UntrustedObject {
        vault_id: copy_id(&bytes[12..28]),
        object_id: copy_id(&bytes[28..60]),
        ciphertext_len: ct_len,
    })
}

pub fn inspect_untrusted_head(bytes: &[u8]) -> Result<UntrustedHead, ShapeError> {
    if bytes.len() != HEAD_LEN {
        return Err(ShapeError::WrongLength);
    }
    if &bytes[0..8] != HEAD_MAGIC {
        return Err(ShapeError::BadMagic);
    }
    if uint16(&bytes[8..10]) != 0 {
        return Err(ShapeError::UnsupportedVersion);
    }
    Ok(UntrustedHead {
        vault_id: copy_id(&bytes[10..26]),
        generation: u64::from_be_bytes(copy_id(&bytes[26..34])),
        object_id: copy_id(&bytes[34..66]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_lengths_match_candidate_spec() {
        assert_eq!(HEADER_LEN, 136);
        assert_eq!(HEAD_LEN, 66);
        assert_eq!(OBJECT_PREFIX_LEN + MIN_CIPHERTEXT_LEN, MIN_OBJECT_LEN);
        assert_eq!(OBJECT_PREFIX_LEN + MAX_CIPHERTEXT_LEN, MAX_OBJECT_LEN);
    }

    #[test]
    fn malformed_header_does_not_enter_crypto() {
        assert_eq!(
            inspect_untrusted_header(&[0u8; HEADER_LEN - 1]),
            Err(ShapeError::WrongLength)
        );
        assert_eq!(
            inspect_untrusted_header(&[0u8; HEADER_LEN]),
            Err(ShapeError::BadMagic)
        );
    }

    #[test]
    fn malformed_head_rejected() {
        assert_eq!(
            inspect_untrusted_head(&[0u8; HEAD_LEN]),
            Err(ShapeError::BadMagic)
        );
    }

    #[test]
    fn object_bounds_enforced_before_crypto() {
        assert_eq!(
            inspect_untrusted_object(&[0u8; MIN_OBJECT_LEN - 1]),
            Err(ShapeError::WrongLength)
        );
        assert_eq!(
            inspect_untrusted_object(&[0u8; MAX_OBJECT_LEN + 1]),
            Err(ShapeError::WrongLength)
        );
    }
}
