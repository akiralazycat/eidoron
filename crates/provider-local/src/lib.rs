#![forbid(unsafe_code)]
//! MEMORY-ONLY synthetic object store, NOT a durable disk or cloud backend.
//!
//! This code is never to be used as an assertion of crash-safe persistence,
//! compare-and-swap, encryption, rollback detection or user-data protection.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    ExistingObjectDiffers,
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
        match self.objects.get(&object_id) {
            Some(existing) if existing == bytes => Ok(PutOutcome::IdenticalRetry),
            Some(_) => Err(StoreError::ExistingObjectDiffers),
            None => {
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
        assert_eq!(store.put_immutable(id, b"synthetic-a"), Ok(PutOutcome::Created));
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
