#![forbid(unsafe_code)]
//! Synthetic fixtures. Shape helpers are unauthenticated bytes.
//! [`key_schedule`] holds the M2 expected key bytes from an independent script.

pub mod commit_genesis;
pub mod key_schedule;
pub mod object_aead;

use eidoron_format::{HEAD_LEN, HEADER_LEN, MIN_OBJECT_LEN};

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
        ShapeError, inspect_untrusted_head, inspect_untrusted_header, inspect_untrusted_object,
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

    #[test]
    fn header_length_and_magic_matrix() {
        assert_eq!(inspect_untrusted_header(&[]), Err(ShapeError::WrongLength));
        assert_eq!(
            inspect_untrusted_header(&synthetic_untrusted_header()[..HEADER_LEN - 1]),
            Err(ShapeError::WrongLength)
        );
        let mut extra = synthetic_untrusted_header().to_vec();
        extra.push(0);
        assert_eq!(
            inspect_untrusted_header(&extra),
            Err(ShapeError::WrongLength)
        );
        let mut bad_magic = synthetic_untrusted_header();
        bad_magic[0] = b'X';
        assert_eq!(
            inspect_untrusted_header(&bad_magic),
            Err(ShapeError::BadMagic)
        );
        assert!(inspect_untrusted_header(&synthetic_untrusted_header()).is_ok());
    }

    #[test]
    fn header_version_suite_flags_and_kdf_are_rejected() {
        let mut major = synthetic_untrusted_header();
        major[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            inspect_untrusted_header(&major),
            Err(ShapeError::UnsupportedVersion)
        );

        let mut minor = synthetic_untrusted_header();
        minor[10..12].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            inspect_untrusted_header(&minor),
            Err(ShapeError::UnsupportedVersion)
        );

        let mut suite = synthetic_untrusted_header();
        suite[12..14].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            inspect_untrusted_header(&suite),
            Err(ShapeError::UnsupportedSuite)
        );

        let mut flags = synthetic_untrusted_header();
        flags[14..16].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            inspect_untrusted_header(&flags),
            Err(ShapeError::UnsupportedFlags)
        );

        let mut kdf = synthetic_untrusted_header();
        kdf[48..52].copy_from_slice(&0x10u32.to_be_bytes());
        assert_eq!(
            inspect_untrusted_header(&kdf),
            Err(ShapeError::UnsupportedKdf)
        );
    }

    #[test]
    fn argon2_resource_bounds() {
        // With m >= 65536 and lanes <= 4, `m < 8 * lanes` cannot occur
        // (65536 >= 32). The range checks are what reject the rows below.
        let cases = [
            (65_535u32, 3u32, 4u32, false),
            (65_536, 3, 4, true),
            (262_144, 3, 4, true),
            (262_145, 3, 4, false),
            (65_536, 0, 4, false),
            (65_536, 1, 4, true),
            (65_536, 10, 4, true),
            (65_536, 11, 4, false),
            (65_536, 3, 0, false),
            (65_536, 3, 1, true),
            (65_536, 3, 5, false),
        ];
        for (memory, time, lanes, accepted) in cases {
            let mut header = synthetic_untrusted_header();
            header[52..56].copy_from_slice(&memory.to_be_bytes());
            header[56..60].copy_from_slice(&time.to_be_bytes());
            header[60..64].copy_from_slice(&lanes.to_be_bytes());
            let result = inspect_untrusted_header(&header);
            if accepted {
                let parsed = result.expect("in-range argon2 parameters");
                assert_eq!(parsed.argon_m_cost_kib, memory);
                assert_eq!(parsed.argon_t_cost, time);
                assert_eq!(parsed.argon_lanes, lanes);
            } else {
                assert_eq!(result, Err(ShapeError::ResourcePolicy));
            }
        }
    }

    #[test]
    fn object_and_head_length_matrix() {
        use eidoron_format::{
            MAX_CIPHERTEXT_LEN, MAX_OBJECT_LEN, MIN_OBJECT_LEN, OBJECT_PREFIX_LEN,
        };

        assert_eq!(
            inspect_untrusted_object(&[0u8; MIN_OBJECT_LEN - 1]),
            Err(ShapeError::WrongLength)
        );
        assert!(inspect_untrusted_object(&synthetic_untrusted_object()).is_ok());

        let mut declared_mismatch = synthetic_untrusted_object().to_vec();
        declared_mismatch[84..88].copy_from_slice(&19u32.to_be_bytes());
        assert_eq!(
            inspect_untrusted_object(&declared_mismatch),
            Err(ShapeError::WrongLength)
        );

        let mut maximum = vec![0u8; MAX_OBJECT_LEN];
        maximum[..OBJECT_PREFIX_LEN]
            .copy_from_slice(&synthetic_untrusted_object()[..OBJECT_PREFIX_LEN]);
        maximum[84..88].copy_from_slice(&(MAX_CIPHERTEXT_LEN as u32).to_be_bytes());
        let parsed = inspect_untrusted_object(&maximum).expect("maximum object shape");
        assert_eq!(parsed.ciphertext_len, MAX_CIPHERTEXT_LEN);

        assert_eq!(
            inspect_untrusted_object(&vec![0u8; MAX_OBJECT_LEN + 1]),
            Err(ShapeError::WrongLength)
        );

        assert_eq!(
            inspect_untrusted_head(&synthetic_untrusted_head()[..HEAD_LEN - 1]),
            Err(ShapeError::WrongLength)
        );
        let mut long_head = synthetic_untrusted_head().to_vec();
        long_head.push(0);
        assert_eq!(
            inspect_untrusted_head(&long_head),
            Err(ShapeError::WrongLength)
        );
        let mut bad_head_magic = synthetic_untrusted_head();
        bad_head_magic[0] = b'X';
        assert_eq!(
            inspect_untrusted_head(&bad_head_magic),
            Err(ShapeError::BadMagic)
        );
        let head = inspect_untrusted_head(&synthetic_untrusted_head()).expect("head shape");
        assert_eq!(head.generation, 0);
        assert_eq!(head.object_id, [0x55; 32]);
    }
}
