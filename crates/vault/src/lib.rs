#![forbid(unsafe_code)]
//! P2.1 scaffold: NO real vault creation, unlock, encryption, sync or recovery.
//! The explicit fail-closed API prevents accidental use as a security product.

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
        assert_eq!(vault.import_encrypted(b"synthetic"), Err(VaultError::NotImplemented));
        assert_eq!(vault.synthetic_object_count(), 0);
        assert!(!PrototypeVault::crypto_is_ready());
        assert_eq!(PrototypeVault::candidate_max_object_len(), 1_048_680);
    }
}
