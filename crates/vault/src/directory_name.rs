//! Directory-entry names, stored in Unicode NFC.
//!
//! The input is normalized with `unicode-normalization` before the checks.
//! Two spellings that normalize to the same NFC string are the same stored
//! name. This module does not parse CBOR, trim, or case-fold. `.` and `..`
//! are rejected only when they are the whole name after normalization.
//! A slash or U+0000 anywhere in the stored name is rejected.

use std::fmt;

use unicode_normalization::UnicodeNormalization;

/// Longest directory name, in UTF-8 bytes. The candidate envelope allows 1..=255.
pub const MAX_DIRECTORY_NAME_BYTES: usize = 255;

/// Why a directory name was rejected. The error text does not include the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryNameError {
    Empty,
    TooLong,
    /// Whole name is `.` or `..`, or the name contains `/` or U+0000.
    Forbidden,
}

impl fmt::Display for DirectoryNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty directory name",
            Self::TooLong => "directory name too long",
            Self::Forbidden => "forbidden directory name",
        })
    }
}

/// Normalize `name` to NFC and accept that stored form, or reject it.
///
/// Callers that key a directory by the returned string treat NFC and NFD
/// spellings of the same name as one entry.
pub fn check_directory_name(name: &str) -> Result<String, DirectoryNameError> {
    let stored: String = name.nfc().collect();
    let bytes = stored.as_bytes();
    if bytes.is_empty() {
        return Err(DirectoryNameError::Empty);
    }
    if bytes.len() > MAX_DIRECTORY_NAME_BYTES {
        return Err(DirectoryNameError::TooLong);
    }
    if bytes.contains(&b'/') || bytes.contains(&0) {
        return Err(DirectoryNameError::Forbidden);
    }
    if stored == "." || stored == ".." {
        return Err(DirectoryNameError::Forbidden);
    }
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names_that_are_already_nfc() {
        for name in [
            "a", "file.txt", ".hidden", "...", " ..", ".. ", " ", "\\", "é",
        ] {
            assert_eq!(check_directory_name(name), Ok(name.to_string()), "{name:?}");
        }
    }

    #[test]
    fn nfc_and_nfd_e_acute_store_as_the_same_name() {
        let nfc = "é";
        let nfd = "e\u{0301}";
        assert_ne!(nfc, nfd);
        let stored_nfc = check_directory_name(nfc).expect("nfc");
        let stored_nfd = check_directory_name(nfd).expect("nfd");
        assert_eq!(stored_nfc, stored_nfd);
        assert_eq!(stored_nfc, "é");
    }

    #[test]
    fn rejects_empty_dot_dotdot_slash_and_nul() {
        assert_eq!(check_directory_name(""), Err(DirectoryNameError::Empty));
        assert_eq!(
            check_directory_name("."),
            Err(DirectoryNameError::Forbidden)
        );
        assert_eq!(
            check_directory_name(".."),
            Err(DirectoryNameError::Forbidden)
        );
        for name in ["/", "a/b", "/a", "a/", "\0", "a\0b", "\0a", "a\0"] {
            assert_eq!(
                check_directory_name(name),
                Err(DirectoryNameError::Forbidden),
                "{name:?}"
            );
        }
        assert!(
            !check_directory_name(".")
                .unwrap_err()
                .to_string()
                .contains('.')
        );
    }

    #[test]
    fn length_is_counted_in_utf8_bytes() {
        let max_ascii = "a".repeat(MAX_DIRECTORY_NAME_BYTES);
        assert_eq!(check_directory_name(&max_ascii), Ok(max_ascii.clone()));
        let too_long_ascii = "a".repeat(MAX_DIRECTORY_NAME_BYTES + 1);
        assert_eq!(
            check_directory_name(&too_long_ascii),
            Err(DirectoryNameError::TooLong)
        );
        let mut exactly = "a".repeat(MAX_DIRECTORY_NAME_BYTES - 2);
        exactly.push('é');
        assert_eq!(exactly.len(), MAX_DIRECTORY_NAME_BYTES);
        assert_eq!(check_directory_name(&exactly), Ok(exactly.clone()));
        let mut nfd_fits_after_nfc = "a".repeat(MAX_DIRECTORY_NAME_BYTES - 2);
        nfd_fits_after_nfc.push_str("e\u{0301}");
        assert_eq!(nfd_fits_after_nfc.len(), MAX_DIRECTORY_NAME_BYTES + 1);
        let stored = check_directory_name(&nfd_fits_after_nfc).expect("nfc shrinks to the cap");
        assert_eq!(stored.len(), MAX_DIRECTORY_NAME_BYTES);
        let mut over = "a".repeat(MAX_DIRECTORY_NAME_BYTES - 1);
        over.push('é');
        assert_eq!(over.len(), MAX_DIRECTORY_NAME_BYTES + 1);
        assert_eq!(
            check_directory_name(&over),
            Err(DirectoryNameError::TooLong)
        );
    }
}
