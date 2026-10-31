#![forbid(unsafe_code)]
//! Cryptographic boundary for the local synthetic prototype.
//!
//! P2.2 links pinned RustCrypto crates, checks published primitive vectors, and
//! derives the candidate v0 passphrase and object keys. Those operations do not
//! open a vault encryption API. [`encrypt_authenticated`] still returns
//! [`CryptoError::NotImplemented`] and never produces ciphertext.

mod schedule;

#[cfg(test)]
mod published_kat;

pub use schedule::{
    KdfParams, ObjectKey, RawPwdKey, RootSecret, WRAPPED_ROOT_LEN, WrapKey, derive_object_key,
    derive_raw_pwd_key, derive_wrap_key, open_root, seal_root,
};

/// Status of the cryptographic backend. This is not a security assurance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoStatus {
    NotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    NotImplemented,
    /// Wrong key, changed associated data, bad tag, or truncated wrapper.
    /// The value does not contain key or plaintext bytes.
    Unavailable,
    /// Passphrase length or Argon2 parameters are outside the candidate bounds.
    UnsupportedParameters,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotImplemented => "cryptographic operation is not implemented",
            Self::Unavailable => "unavailable",
            Self::UnsupportedParameters => "unsupported key-derivation parameters",
        })
    }
}

impl std::error::Error for CryptoError {}

/// Deliberate fail-closed gate: never return "encrypted" data from a stub.
pub fn encrypt_authenticated(_plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::NotImplemented)
}

pub fn status() -> CryptoStatus {
    CryptoStatus::NotImplemented
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_does_not_pretend_to_encrypt() {
        assert_eq!(
            encrypt_authenticated(b"synthetic only"),
            Err(CryptoError::NotImplemented)
        );
        assert_eq!(status(), CryptoStatus::NotImplemented);
    }
}
