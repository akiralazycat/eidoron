//! Commit heads in a folder that has no single HEAD file.
//!
//! Each device appends its own immutable commit. A sync tool may deliver
//! those files late or out of order. This function only classifies the set
//! it is given. It does not delete a commit and it does not pick a winner
//! when two heads diverge.

use std::collections::{HashMap, HashSet};

/// One commit the caller has already decrypted far enough to know its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalCommit {
    pub id: [u8; 32],
    pub parent: Option<[u8; 32]>,
}

/// How the given commits relate. A conflict keeps every head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryStatus {
    Empty,
    /// One head, and every parent it names is also in the set.
    Single {
        head: [u8; 32],
    },
    /// One head, but some parent id has not arrived yet. The head is kept.
    Incomplete {
        head: [u8; 32],
    },
    /// Two or more heads. None of them is discarded.
    Conflict {
        heads: Vec<[u8; 32]>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryView {
    pub status: HistoryStatus,
    pub missing_parents: Vec<[u8; 32]>,
}

/// The set names the same id twice with different parents, or a parent cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryError {
    InconsistentId,
    Cycle,
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InconsistentId => "inconsistent commit id",
            Self::Cycle => "commit cycle",
        })
    }
}

/// Classify heads. `commits` is not modified and no entry is dropped by this function.
pub fn classify_heads(commits: &[LocalCommit]) -> Result<HistoryView, HistoryError> {
    let mut parents: HashMap<[u8; 32], Option<[u8; 32]>> = HashMap::new();
    for commit in commits {
        if let Some(previous) = parents.get(&commit.id) {
            if previous != &commit.parent {
                return Err(HistoryError::InconsistentId);
            }
            continue;
        }
        parents.insert(commit.id, commit.parent);
    }
    if has_cycle(&parents) {
        return Err(HistoryError::Cycle);
    }
    let referenced: HashSet<[u8; 32]> = parents.values().filter_map(|parent| *parent).collect();
    let mut heads: Vec<[u8; 32]> = parents
        .keys()
        .copied()
        .filter(|id| !referenced.contains(id))
        .collect();
    heads.sort();
    let mut missing_parents: Vec<[u8; 32]> = referenced
        .into_iter()
        .filter(|id| !parents.contains_key(id))
        .collect();
    missing_parents.sort();
    let status = match heads.as_slice() {
        [] => HistoryStatus::Empty,
        [head] if missing_parents.is_empty() => HistoryStatus::Single { head: *head },
        [head] => HistoryStatus::Incomplete { head: *head },
        _ => HistoryStatus::Conflict { heads },
    };
    Ok(HistoryView {
        status,
        missing_parents,
    })
}

fn has_cycle(parents: &HashMap<[u8; 32], Option<[u8; 32]>>) -> bool {
    for start in parents.keys() {
        let mut seen = HashSet::new();
        let mut cursor = Some(*start);
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return true;
            }
            cursor = parents.get(&id).copied().flatten();
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn two_devices_that_fork_from_the_same_parent_are_both_kept() {
        let genesis = id(1);
        let device_a = id(2);
        let device_b = id(3);
        let view = classify_heads(&[
            LocalCommit {
                id: genesis,
                parent: None,
            },
            LocalCommit {
                id: device_a,
                parent: Some(genesis),
            },
            LocalCommit {
                id: device_b,
                parent: Some(genesis),
            },
        ])
        .expect("fork");
        assert_eq!(
            view.status,
            HistoryStatus::Conflict {
                heads: vec![device_a, device_b],
            }
        );
        assert!(view.missing_parents.is_empty());
    }

    #[test]
    fn a_linear_history_has_one_head() {
        let genesis = id(1);
        let second = id(2);
        let third = id(3);
        let view = classify_heads(&[
            LocalCommit {
                id: third,
                parent: Some(second),
            },
            LocalCommit {
                id: genesis,
                parent: None,
            },
            LocalCommit {
                id: second,
                parent: Some(genesis),
            },
        ])
        .expect("line");
        assert_eq!(view.status, HistoryStatus::Single { head: third });
    }

    #[test]
    fn a_child_whose_parent_has_not_synced_is_kept() {
        let parent = id(4);
        let child = id(5);
        let view = classify_heads(&[LocalCommit {
            id: child,
            parent: Some(parent),
        }])
        .expect("incomplete");
        assert_eq!(view.status, HistoryStatus::Incomplete { head: child });
        assert_eq!(view.missing_parents, vec![parent]);
    }

    #[test]
    fn duplicate_same_parent_is_one_commit_and_disagreement_is_an_error() {
        let genesis = id(1);
        let child = id(2);
        let view = classify_heads(&[
            LocalCommit {
                id: genesis,
                parent: None,
            },
            LocalCommit {
                id: child,
                parent: Some(genesis),
            },
            LocalCommit {
                id: child,
                parent: Some(genesis),
            },
        ])
        .expect("duplicate delivery");
        assert_eq!(view.status, HistoryStatus::Single { head: child });
        assert_eq!(
            classify_heads(&[
                LocalCommit {
                    id: child,
                    parent: Some(genesis),
                },
                LocalCommit {
                    id: child,
                    parent: None,
                },
            ]),
            Err(HistoryError::InconsistentId)
        );
    }

    #[test]
    fn a_cycle_is_not_an_empty_history() {
        let left = id(8);
        let right = id(9);
        assert_eq!(
            classify_heads(&[
                LocalCommit {
                    id: left,
                    parent: Some(right),
                },
                LocalCommit {
                    id: right,
                    parent: Some(left),
                },
            ]),
            Err(HistoryError::Cycle)
        );
    }
}
