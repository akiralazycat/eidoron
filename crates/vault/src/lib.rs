#![forbid(unsafe_code)]
//! Sync-folder vault sessions.
//!
//! [`create_vault`](crate::create_vault) and [`open_vault`](crate::open_vault)
//! write and read one local directory. [`Session::status`](crate::Session::status)
//! reports one head, every conflicting head, a missing parent, or a locked
//! session. [`PrototypeVault::import_encrypted`] stays unavailable.
//! `eidoron_crypto::status` is a separate scaffold flag and stays
//! `NotImplemented`.
//! [`check_genesis_predecessor`](crate::check_genesis_predecessor) applies one rule
//! to an already decrypted commit body.
//! [`check_directory_name`](crate::check_directory_name) stores names in NFC.
//! [`check_chunk_identity`](crate::check_chunk_identity) compares one chunk's
//! `file_id` and ordinal with the caller.

mod chunk_identity;
mod commit_check;
mod commit_history;
mod directory_name;
mod session;

pub use chunk_identity::{ChunkIdentityError, check_chunk_identity};
pub use commit_check::{CommitCheckError, GenesisPredecessor, check_genesis_predecessor};
pub use commit_history::{HistoryError, HistoryStatus, HistoryView, LocalCommit, classify_heads};
pub use directory_name::{DirectoryNameError, MAX_DIRECTORY_NAME_BYTES, check_directory_name};
pub use session::{Session, VaultStatus, create_vault, open_vault};

use eidoron_provider_local::MemoryStore;

/// Why a vault operation failed. Display text does not include a password,
/// a key, or header bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    NotImplemented,
    Unavailable,
    DirectoryNotEmpty,
    Locked,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotImplemented => "not implemented",
            Self::Unavailable => "unavailable",
            Self::DirectoryNotEmpty => "directory not empty",
            Self::Locked => "locked",
        })
    }
}

impl std::error::Error for VaultError {}

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
    fn prototype_import_stays_unavailable() {
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
