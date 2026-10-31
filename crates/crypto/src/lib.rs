#![forbid(unsafe_code)]
//! Cryptographic boundary for the local synthetic prototype.
//!
//! Passphrase and object keys follow the candidate v0 schedule. Object bodies
//! are sealed with XChaCha20-Poly1305. [`status`] stays [`CryptoStatus::NotImplemented`]
//! until a vault session exists. Wiping key bytes on drop is best-effort.

mod object_aead;
mod schedule;

#[cfg(test)]
mod published_kat;

pub use object_aead::{
    EncryptedObject, MAX_OBJECT_CIPHERTEXT_LEN, MAX_OBJECT_PLAINTEXT_LEN,
    MIN_OBJECT_CIPHERTEXT_LEN, MIN_OBJECT_PLAINTEXT_LEN, decrypt_authenticated,
    encrypt_authenticated,
};
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
    /// Passphrase length, Argon2 parameters, or object plaintext length is outside the candidate bounds.
    UnsupportedParameters,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotImplemented => "cryptographic operation is not implemented",
            Self::Unavailable => "unavailable",
            Self::UnsupportedParameters => "unsupported parameters",
        })
    }
}

impl std::error::Error for CryptoError {}

pub fn status() -> CryptoStatus {
    CryptoStatus::NotImplemented
}
