//! One rule on a decrypted commit body: kind `0x01` and generation 0 require a
//! null predecessor.
//!
//! The input is `kind || schema || payload`. Payload bytes are read only far
//! enough to see map keys 0 and 1. Later map entries, directory graphs, and a
//! general CBOR decoder are not part of this check. Generation greater than 0
//! is reported and not judged.

use std::fmt;

const COMMIT_KIND: u8 = 0x01;
const BODY_SCHEMA: u8 = 0x00;
const MAJOR_UINT: u8 = 0;
const MAJOR_BSTR: u8 = 2;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;
const SIMPLE_NULL: u8 = 22;

/// What the genesis-predecessor rule says about a decrypted body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisPredecessor {
    /// `kind` is not `0x01`. The payload was not read.
    NotACommit,
    /// Commit whose generation is not 0. The predecessor requirement for later
    /// generations is not applied here.
    NotGenesis,
    /// Commit kind `0x01`, generation 0, predecessor null.
    EmptyPredecessor,
}

/// The genesis rule failed, or the two fields could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitCheckError {
    /// Truncated, non-minimal, or not the narrow shape this check understands.
    Unreadable,
    /// Generation 0 carries a predecessor other than null.
    PredecessorNotEmpty,
}

impl fmt::Display for CommitCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "unreadable",
            Self::PredecessorNotEmpty => "predecessor not empty",
        })
    }
}

/// Apply only the generation-0 predecessor rule.
pub fn check_genesis_predecessor(decrypted: &[u8]) -> Result<GenesisPredecessor, CommitCheckError> {
    if decrypted.len() < 2 {
        return Err(CommitCheckError::Unreadable);
    }
    if decrypted[0] != COMMIT_KIND {
        return Ok(GenesisPredecessor::NotACommit);
    }
    if decrypted[1] != BODY_SCHEMA {
        return Err(CommitCheckError::Unreadable);
    }
    let mut cursor = Cursor {
        data: &decrypted[2..],
        index: 0,
    };
    let (major, argument) = cursor.header()?;
    if major != MAJOR_MAP {
        return Err(CommitCheckError::Unreadable);
    }
    let pairs = cursor.argument(argument)?;
    if pairs < 2 {
        return Err(CommitCheckError::Unreadable);
    }
    let key_0 = cursor.uint()?;
    if key_0 != 0 {
        return Err(CommitCheckError::Unreadable);
    }
    let generation = cursor.uint()?;
    let key_1 = cursor.uint()?;
    if key_1 != 1 {
        return Err(CommitCheckError::Unreadable);
    }
    let prior = cursor.prior()?;
    if generation != 0 {
        return Ok(GenesisPredecessor::NotGenesis);
    }
    if prior.is_null() {
        Ok(GenesisPredecessor::EmptyPredecessor)
    } else {
        Err(CommitCheckError::PredecessorNotEmpty)
    }
}

/// Parent object id of a decrypted commit body.
///
/// Generation 0 with a null predecessor has no parent. A later generation
/// returns its 32-byte predecessor. This does not walk a store.
pub fn read_commit_parent(decrypted: &[u8]) -> Result<Option<[u8; 32]>, CommitCheckError> {
    Ok(parse_commit_link(decrypted)?.parent)
}

/// Generation field of a decrypted commit body. This does not walk a store.
pub fn read_commit_generation(decrypted: &[u8]) -> Result<u64, CommitCheckError> {
    Ok(parse_commit_link(decrypted)?.generation)
}

/// Object id of the commit's root directory, map key 2.
///
/// A body that stops before key 2 is unreadable here. This does not open the
/// directory object.
pub fn read_commit_root(decrypted: &[u8]) -> Result<[u8; 32], CommitCheckError> {
    parse_commit_link(decrypted)?
        .root
        .ok_or(CommitCheckError::Unreadable)
}

struct CommitLink {
    generation: u64,
    parent: Option<[u8; 32]>,
    root: Option<[u8; 32]>,
}

fn parse_commit_link(decrypted: &[u8]) -> Result<CommitLink, CommitCheckError> {
    if decrypted.len() < 2 || decrypted[0] != COMMIT_KIND || decrypted[1] != BODY_SCHEMA {
        return Err(CommitCheckError::Unreadable);
    }
    let mut cursor = Cursor {
        data: &decrypted[2..],
        index: 0,
    };
    let (major, argument) = cursor.header()?;
    if major != MAJOR_MAP {
        return Err(CommitCheckError::Unreadable);
    }
    let pairs = cursor.argument(argument)?;
    if pairs < 2 {
        return Err(CommitCheckError::Unreadable);
    }
    if cursor.uint()? != 0 {
        return Err(CommitCheckError::Unreadable);
    }
    let generation = cursor.uint()?;
    if cursor.uint()? != 1 {
        return Err(CommitCheckError::Unreadable);
    }
    let prior = cursor.prior()?;
    let parent = match (generation, prior) {
        (0, Prior::Null) => None,
        (0, Prior::Bytes(_)) => return Err(CommitCheckError::PredecessorNotEmpty),
        (_, Prior::Null) => return Err(CommitCheckError::Unreadable),
        (_, Prior::Bytes(bytes)) if bytes.len() == 32 => {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            Some(id)
        }
        (_, Prior::Bytes(_)) => return Err(CommitCheckError::Unreadable),
    };
    let root = if pairs >= 3 {
        if cursor.uint()? != 2 {
            return Err(CommitCheckError::Unreadable);
        }
        match cursor.prior()? {
            Prior::Bytes(bytes) if bytes.len() == 32 => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                Some(id)
            }
            _ => return Err(CommitCheckError::Unreadable),
        }
    } else {
        None
    };
    Ok(CommitLink {
        generation,
        parent,
        root,
    })
}

struct Cursor<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> Cursor<'a> {
    fn header(&mut self) -> Result<(u8, u8), CommitCheckError> {
        let byte = *self
            .data
            .get(self.index)
            .ok_or(CommitCheckError::Unreadable)?;
        self.index += 1;
        Ok((byte >> 5, byte & 0x1f))
    }

    fn argument(&mut self, additional: u8) -> Result<u64, CommitCheckError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(
                    *self
                        .data
                        .get(self.index)
                        .ok_or(CommitCheckError::Unreadable)?,
                );
                self.index += 1;
                if value < 24 {
                    return Err(CommitCheckError::Unreadable);
                }
                Ok(value)
            }
            25 => self.wide(2, 256),
            26 => self.wide(4, 1 << 16),
            27 => self.wide(8, 1 << 32),
            _ => Err(CommitCheckError::Unreadable),
        }
    }

    fn wide(&mut self, width: usize, minimum: u64) -> Result<u64, CommitCheckError> {
        let end = self
            .index
            .checked_add(width)
            .ok_or(CommitCheckError::Unreadable)?;
        let bytes = self
            .data
            .get(self.index..end)
            .ok_or(CommitCheckError::Unreadable)?;
        let mut be = [0u8; 8];
        be[8 - width..].copy_from_slice(bytes);
        self.index = end;
        let value = u64::from_be_bytes(be);
        if value < minimum {
            return Err(CommitCheckError::Unreadable);
        }
        Ok(value)
    }

    fn uint(&mut self) -> Result<u64, CommitCheckError> {
        let (major, argument) = self.header()?;
        if major != MAJOR_UINT {
            return Err(CommitCheckError::Unreadable);
        }
        self.argument(argument)
    }

    fn prior(&mut self) -> Result<Prior, CommitCheckError> {
        let (major, argument) = self.header()?;
        if major == MAJOR_SIMPLE && argument == SIMPLE_NULL {
            return Ok(Prior::Null);
        }
        if major != MAJOR_BSTR {
            return Err(CommitCheckError::Unreadable);
        }
        let length = self.argument(argument)?;
        let length = usize::try_from(length).map_err(|_| CommitCheckError::Unreadable)?;
        let end = self
            .index
            .checked_add(length)
            .ok_or(CommitCheckError::Unreadable)?;
        if end > self.data.len() {
            return Err(CommitCheckError::Unreadable);
        }
        let bytes = self.data[self.index..end].to_vec();
        self.index = end;
        Ok(Prior::Bytes(bytes))
    }
}

enum Prior {
    Null,
    Bytes(Vec<u8>),
}

impl Prior {
    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eidoron_test_vectors::commit_genesis::{
        DIRECTORY_KIND, DIRECTORY_KIND_EXPECT, GENESIS_EMPTY_BSTR, GENESIS_EMPTY_BSTR_EXPECT,
        GENESIS_NULL, GENESIS_NULL_EXPECT, GENESIS_WITH_PRIOR, GENESIS_WITH_PRIOR_EXPECT,
        LATER_WITH_PRIOR, LATER_WITH_PRIOR_EXPECT, NONMINIMAL_ZERO, NONMINIMAL_ZERO_EXPECT,
    };

    fn label(result: Result<GenesisPredecessor, CommitCheckError>) -> &'static str {
        match result {
            Ok(GenesisPredecessor::EmptyPredecessor) => "EmptyPredecessor",
            Ok(GenesisPredecessor::NotGenesis) => "NotGenesis",
            Ok(GenesisPredecessor::NotACommit) => "NotACommit",
            Err(CommitCheckError::PredecessorNotEmpty) => "PredecessorNotEmpty",
            Err(CommitCheckError::Unreadable) => "Unreadable",
        }
    }

    #[test]
    fn genesis_rule_matches_independent_fixtures() {
        let cases = [
            (GENESIS_NULL, GENESIS_NULL_EXPECT),
            (GENESIS_WITH_PRIOR, GENESIS_WITH_PRIOR_EXPECT),
            (GENESIS_EMPTY_BSTR, GENESIS_EMPTY_BSTR_EXPECT),
            (LATER_WITH_PRIOR, LATER_WITH_PRIOR_EXPECT),
            (NONMINIMAL_ZERO, NONMINIMAL_ZERO_EXPECT),
            (DIRECTORY_KIND, DIRECTORY_KIND_EXPECT),
        ];
        for (body, expect) in cases {
            assert_eq!(label(check_genesis_predecessor(body)), expect);
        }
    }

    #[test]
    fn parent_ids_match_the_same_fixtures() {
        assert_eq!(read_commit_parent(GENESIS_NULL), Ok(None));
        assert_eq!(read_commit_generation(GENESIS_NULL), Ok(0));
        assert_eq!(read_commit_root(GENESIS_NULL), Ok([0x71; 32]));
        assert_eq!(read_commit_parent(LATER_WITH_PRIOR), Ok(Some([0x91; 32])));
        assert_eq!(read_commit_generation(LATER_WITH_PRIOR), Ok(1));
        assert_eq!(
            read_commit_parent(GENESIS_WITH_PRIOR),
            Err(CommitCheckError::PredecessorNotEmpty)
        );
        assert_eq!(
            read_commit_parent(NONMINIMAL_ZERO),
            Err(CommitCheckError::Unreadable)
        );
    }

    #[test]
    fn short_or_wrong_schema_is_unreadable() {
        assert_eq!(
            check_genesis_predecessor(&[]),
            Err(CommitCheckError::Unreadable)
        );
        assert_eq!(
            check_genesis_predecessor(&[0x01]),
            Err(CommitCheckError::Unreadable)
        );
        assert_eq!(
            check_genesis_predecessor(&[0x01, 0x01]),
            Err(CommitCheckError::Unreadable)
        );
    }
}
