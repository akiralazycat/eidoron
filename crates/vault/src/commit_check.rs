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
    let prior_is_null = cursor.prior_is_null()?;
    if generation != 0 {
        return Ok(GenesisPredecessor::NotGenesis);
    }
    if prior_is_null {
        Ok(GenesisPredecessor::EmptyPredecessor)
    } else {
        Err(CommitCheckError::PredecessorNotEmpty)
    }
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

    fn prior_is_null(&mut self) -> Result<bool, CommitCheckError> {
        let (major, argument) = self.header()?;
        if major == MAJOR_SIMPLE && argument == SIMPLE_NULL {
            return Ok(true);
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
        self.index = end;
        Ok(false)
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
