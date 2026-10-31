#![forbid(unsafe_code)]
//! Placeholder for independently verified cryptography.
//!
//! P2.1 has NO encryption, key derivation or authentication implementation.
//! All cryptographic operations fail closed until the P2.2+ test gates.

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
