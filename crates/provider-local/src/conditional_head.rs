//! Optional future backend: provider-agnostic conditional HEAD update.
//!
//! The consumer product does not call a cloud API. A vault is a local folder
//! the user's own sync tool copies, and that folder has no single HEAD file.
//! This module stays for a possible later adapter. It is not the primary path.
//!
//! Semantics follow HTTP `If-None-Match: *` and `If-Match: <etag>`.
//! [`MemoryHead`] is an in-process fake. It does not open a socket.
//! Its etag is a generation counter, not a hash of the bytes.

use std::fmt;

/// Opaque validator for one stored HEAD. Callers must not treat it as a content hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Etag(u64);

impl fmt::Display for Etag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "etag-{}", self.0)
    }
}

/// Current HEAD bytes and the etag a later `If-Match` must present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHead {
    pub etag: Etag,
    pub bytes: Vec<u8>,
}

/// Precondition for one HEAD write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadPrecondition {
    /// `If-None-Match: *`. Succeeds only when no HEAD is stored.
    IfNoneMatchStar,
    /// `If-Match`. Succeeds only when the stored etag equals this value.
    IfMatch(Etag),
}

/// Why a conditional HEAD write did not happen. The text does not include HEAD bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadError {
    PreconditionFailed,
}

impl fmt::Display for HeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PreconditionFailed => "precondition failed",
        })
    }
}

/// Conditional publication of one opaque HEAD.
///
/// Adapters for a real provider must map [`HeadPrecondition::IfNoneMatchStar`]
/// to `If-None-Match: *` and [`HeadPrecondition::IfMatch`] to `If-Match` with
/// that provider's opaque etag. This trait does not perform network I/O.
pub trait ConditionalHead {
    fn get_head(&self) -> Option<&StoredHead>;
    fn put_head(&mut self, precondition: HeadPrecondition, bytes: &[u8])
    -> Result<Etag, HeadError>;
}

/// In-memory HEAD. Successful writes advance a counter. Repeating the same
/// bytes still produces a new etag, so the etag is not a plaintext hash.
#[derive(Debug, Default)]
pub struct MemoryHead {
    generation: u64,
    current: Option<StoredHead>,
}

impl MemoryHead {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConditionalHead for MemoryHead {
    fn get_head(&self) -> Option<&StoredHead> {
        self.current.as_ref()
    }

    fn put_head(
        &mut self,
        precondition: HeadPrecondition,
        bytes: &[u8],
    ) -> Result<Etag, HeadError> {
        let matches = match (&precondition, &self.current) {
            (HeadPrecondition::IfNoneMatchStar, None) => true,
            (HeadPrecondition::IfMatch(expected), Some(current)) => &current.etag == expected,
            _ => false,
        };
        if !matches {
            return Err(HeadError::PreconditionFailed);
        }
        self.generation = self.generation.saturating_add(1);
        let etag = Etag(self.generation);
        self.current = Some(StoredHead {
            etag: etag.clone(),
            bytes: bytes.to_vec(),
        });
        Ok(etag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_update_and_stale_match() {
        let mut head = MemoryHead::new();
        assert!(head.get_head().is_none());
        assert_eq!(
            head.put_head(HeadPrecondition::IfMatch(Etag(1)), b"first"),
            Err(HeadError::PreconditionFailed)
        );

        let created = head
            .put_head(HeadPrecondition::IfNoneMatchStar, b"first")
            .expect("create");
        assert_eq!(
            head.get_head().map(|h| h.bytes.as_slice()),
            Some(b"first".as_slice())
        );
        assert_eq!(
            head.put_head(HeadPrecondition::IfNoneMatchStar, b"second"),
            Err(HeadError::PreconditionFailed)
        );
        assert_eq!(
            head.get_head().map(|h| h.bytes.as_slice()),
            Some(b"first".as_slice())
        );

        assert_eq!(
            head.put_head(HeadPrecondition::IfMatch(Etag(99)), b"second"),
            Err(HeadError::PreconditionFailed)
        );
        assert_eq!(
            head.get_head().map(|h| h.bytes.as_slice()),
            Some(b"first".as_slice())
        );

        let updated = head
            .put_head(HeadPrecondition::IfMatch(created.clone()), b"second")
            .expect("update");
        assert_ne!(updated, created);
        assert_eq!(
            head.get_head().map(|h| h.bytes.as_slice()),
            Some(b"second".as_slice())
        );

        let restored = head
            .put_head(HeadPrecondition::IfMatch(updated), b"first")
            .expect("restore");
        assert_ne!(restored, created);
        assert_eq!(
            head.get_head().map(|h| h.etag.to_string()),
            Some(restored.to_string())
        );
        assert_eq!(
            HeadError::PreconditionFailed.to_string(),
            "precondition failed"
        );
    }
}
