//! Directory-entry names, without CBOR and without Unicode normalization.
//!
//! A name is the exact UTF-8 string. This check does not trim, case-fold, or
//! convert to NFC. `.` and `..` are rejected only when they are the whole
//! name. A slash or U+0000 anywhere in the name is rejected.

use std::fmt;

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

/// Accept a directory entry name, or reject it for the rules above.
pub fn check_directory_name(name: &str) -> Result<(), DirectoryNameError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(DirectoryNameError::Empty);
    }
    if bytes.len() > MAX_DIRECTORY_NAME_BYTES {
        return Err(DirectoryNameError::TooLong);
    }
    if bytes.contains(&b'/') || bytes.contains(&0) {
        return Err(DirectoryNameError::Forbidden);
    }
    if name == "." || name == ".." {
        return Err(DirectoryNameError::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names_including_dots_and_non_nfc() {
        for name in [
            "a",
            "file.txt",
            ".hidden",
            "...",
            " ..",
            ".. ",
            " ",
            "\\",
            "é",
            "e\u{0301}",
        ] {
            assert_eq!(check_directory_name(name), Ok(()), "{name:?}");
        }
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
        assert_eq!(check_directory_name(&max_ascii), Ok(()));
        let too_long_ascii = "a".repeat(MAX_DIRECTORY_NAME_BYTES + 1);
        assert_eq!(
            check_directory_name(&too_long_ascii),
            Err(DirectoryNameError::TooLong)
        );
        let mut exactly = "a".repeat(MAX_DIRECTORY_NAME_BYTES - 2);
        exactly.push('é');
        assert_eq!(exactly.len(), MAX_DIRECTORY_NAME_BYTES);
        assert_eq!(check_directory_name(&exactly), Ok(()));
        let mut over = "a".repeat(MAX_DIRECTORY_NAME_BYTES - 1);
        over.push('é');
        assert_eq!(over.len(), MAX_DIRECTORY_NAME_BYTES + 1);
        assert_eq!(
            check_directory_name(&over),
            Err(DirectoryNameError::TooLong)
        );
    }
}
