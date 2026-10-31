#![forbid(unsafe_code)]
//! Synthetic UNAUTHENTICATED shape fixtures for parser-only P2.1 tests.
//! Not ciphertext, not known-answer cryptographic vectors, never user data.

use eidoron_format::{HEADER_LEN, HEAD_LEN, MIN_OBJECT_LEN};

/// Header with a fabricated, deliberately invalid wrapped-root tag.
pub fn synthetic_untrusted_header() -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..8].copy_from_slice(b"EIDORON\0");
    out[12..14].copy_from_slice(&1u16.to_be_bytes());
    out[16..32].fill(0x11);
    out[32..48].fill(0x22);
    out[48..52].copy_from_slice(&0x13u32.to_be_bytes());
    out[52..56].copy_from_slice(&65_536u32.to_be_bytes());
    out[56..60].copy_from_slice(&3u32.to_be_bytes());
    out[60..64].copy_from_slice(&4u32.to_be_bytes());
    out[64..88].fill(0x33);
    out
}

pub fn synthetic_untrusted_head() -> [u8; HEAD_LEN] {
    let mut out = [0u8; HEAD_LEN];
    out[0..8].copy_from_slice(b"EIDHEAD\0");
    out[10..26].fill(0x11);
    out[26..34].copy_from_slice(&0u64.to_be_bytes());
    out[34..66].fill(0x55);
    out
}

pub fn synthetic_untrusted_object() -> [u8; MIN_OBJECT_LEN] {
    let mut out = [0u8; MIN_OBJECT_LEN];
    out[0..8].copy_from_slice(b"EIDOBJ\0\0");
    out[10..12].copy_from_slice(&1u16.to_be_bytes());
    out[12..28].fill(0x11);
    out[28..60].fill(0x55);
    out[60..84].fill(0x66);
    out[84..88].copy_from_slice(&18u32.to_be_bytes());
    // The body is all zero bytes; AEAD tag is intentionally NOT valid.
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use eidoron_format::{
        inspect_untrusted_header, inspect_untrusted_head, inspect_untrusted_object,
        ShapeError,
    };

    #[test]
    fn fixtures_have_only_valid_untrusted_shapes() {
        let header = inspect_untrusted_header(&synthetic_untrusted_header())
            .expect("synthetic untrusted header shape");
        assert_eq!(header.vault_id, [0x11; 16]);
        assert_eq!(header.argon_m_cost_kib, 65_536);

        let head = inspect_untrusted_head(&synthetic_untrusted_head())
            .expect("synthetic untrusted HEAD shape");
        assert_eq!(head.object_id, [0x55; 32]);

        let object = inspect_untrusted_object(&synthetic_untrusted_object())
            .expect("synthetic untrusted object shape");
        assert_eq!(object.ciphertext_len, 18);
        assert_eq!(object.object_id, [0x55; 32]);
    }

    #[test]
    fn kdf_budget_cannot_be_requested_unbounded() {
        let mut malicious = synthetic_untrusted_header();
        malicious[52..56].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            inspect_untrusted_header(&malicious),
            Err(ShapeError::ResourcePolicy)
        );
    }

    #[test]
    fn untrusted_object_length_mismatch_is_rejected() {
        let mut invalid = synthetic_untrusted_object().to_vec();
        invalid[84..88].copy_from_slice(&19u32.to_be_bytes());
        assert_eq!(
            inspect_untrusted_object(&invalid),
            Err(ShapeError::WrongLength)
        );
    }
}
