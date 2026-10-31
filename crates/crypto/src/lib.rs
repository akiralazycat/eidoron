#![forbid(unsafe_code)]
//! Cryptographic boundary for the local synthetic prototype.
//!
//! P2.2 links pinned RustCrypto crates and checks three published known-answer
//! vectors from unit tests. Those tests do not open a vault encryption API.
//! [`encrypt_authenticated`] still returns [`CryptoError::NotImplemented`] and
//! never produces ciphertext.

#[cfg(test)]
mod published_kat;

/// Status of the cryptographic backend. This is not a security assurance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoStatus {
    NotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    NotImplemented,
}

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
