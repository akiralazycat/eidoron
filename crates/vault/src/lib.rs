#![forbid(unsafe_code)]
//! Vault scaffold. Creation, unlock, import, and sync stay unavailable.
//! [`check_genesis_predecessor`](crate::check_genesis_predecessor) applies one rule
//! to an already decrypted commit body.
//! [`check_directory_name`](crate::check_directory_name) rejects a few names and
//! does not normalize Unicode.

mod commit_check;
mod directory_name;

pub use commit_check::{CommitCheckError, GenesisPredecessor, check_genesis_predecessor};
pub use directory_name::{DirectoryNameError, MAX_DIRECTORY_NAME_BYTES, check_directory_name};

use eidoron_provider_local::MemoryStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    NotImplemented,
}

#[derive(Debug, Default)]
pub struct PrototypeVault {
    synthetic_store: MemoryStore,
}

impl PrototypeVault {
    pub fn new_synthetic_only() -> Self {
        Self::default()
    }

    pub fn import_encrypted(&mut self, _plaintext: &[u8]) -> Result<(), VaultError> {
        // Never persist or return plaintext as a pretend encrypted object.
        Err(VaultError::NotImplemented)
    }

    pub fn synthetic_object_count(&self) -> usize {
        self.synthetic_store.len()
    }

    pub fn candidate_max_object_len() -> usize {
        eidoron_format::MAX_OBJECT_LEN
    }

    pub fn crypto_is_ready() -> bool {
        eidoron_crypto::status() != eidoron_crypto::CryptoStatus::NotImplemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_usable_vault_operations_in_p2_1() {
        let mut vault = PrototypeVault::new_synthetic_only();
        assert_eq!(
            vault.import_encrypted(b"synthetic"),
            Err(VaultError::NotImplemented)
        );
        assert_eq!(vault.synthetic_object_count(), 0);
        assert!(!PrototypeVault::crypto_is_ready());
        assert_eq!(PrototypeVault::candidate_max_object_len(), 1_048_680);
    }
}
