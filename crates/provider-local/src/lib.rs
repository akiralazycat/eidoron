#![forbid(unsafe_code)]
//! Local synthetic object stores.
//!
//! [`MemoryStore`] keeps bytes in process memory. [`TempDirStore`] writes opaque
//! bytes under a caller-chosen directory. Neither store is a cloud backend,
//! and neither claims crash-safe or atomic replacement. A retry is accepted
//! only when the opaque bytes already stored for that id are identical. That
//! comparison is not a hash of plaintext.

mod conditional_head;
mod temp_dir;

pub use conditional_head::{
    ConditionalHead, Etag, HeadError, HeadPrecondition, MemoryHead, StoredHead,
};
pub use temp_dir::TempDirStore;

use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    ExistingObjectDiffers,
    /// A directory read or write failed. The message does not include the path or the bytes.
    Io,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ExistingObjectDiffers => "existing object differs",
            Self::Io => "io error",
        })
    }
}

/// Decide a put from bytes already stored for one id.
///
/// `existing` is the opaque blob for that id, not a plaintext hash.
pub fn immutable_put_decision(
    existing: Option<&[u8]>,
    bytes: &[u8],
) -> Result<PutOutcome, StoreError> {
    match existing {
        Some(existing) if existing == bytes => Ok(PutOutcome::IdenticalRetry),
        Some(_) => Err(StoreError::ExistingObjectDiffers),
        None => Ok(PutOutcome::Created),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    IdenticalRetry,
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    objects: HashMap<[u8; 32], Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a synthetic immutable object. Identical retries are idempotent.
    pub fn put_immutable(
        &mut self,
        object_id: [u8; 32],
        bytes: &[u8],
    ) -> Result<PutOutcome, StoreError> {
        match immutable_put_decision(self.objects.get(&object_id).map(Vec::as_slice), bytes)? {
            PutOutcome::IdenticalRetry => Ok(PutOutcome::IdenticalRetry),
            PutOutcome::Created => {
                self.objects.insert(object_id, bytes.to_vec());
                Ok(PutOutcome::Created)
            }
        }
    }

    pub fn get(&self, object_id: &[u8; 32]) -> Option<&[u8]> {
        self.objects.get(object_id).map(Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_retry_cannot_overwrite() {
        let mut store = MemoryStore::new();
        let id = [7u8; 32];
        assert_eq!(
            store.put_immutable(id, b"synthetic-a"),
            Ok(PutOutcome::Created)
        );
        assert_eq!(
            store.put_immutable(id, b"synthetic-a"),
            Ok(PutOutcome::IdenticalRetry)
        );
        assert_eq!(
            store.put_immutable(id, b"synthetic-b"),
            Err(StoreError::ExistingObjectDiffers)
        );
        assert_eq!(store.get(&id), Some(b"synthetic-a".as_slice()));
        assert_eq!(store.len(), 1);
    }
}
