//! Binary Merkle root over audit row hashes.
//!
//! Leaves are the 32-byte `row_hash` values in chain order. Odd nodes at
//! any level are paired with themselves (Bitcoin-style). Empty input
//! yields `GENESIS_PREV` (all zeros).

use sha2::{Digest, Sha256};

use crate::hash::GENESIS_PREV;

/// Compute the Merkle root of `leaves` (each leaf is a 32-byte hash).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return GENESIS_PREV;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(hash_pair(&left, &right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let dig = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

/// Convert a `Vec<u8>` of length 32 into an array, or None.
pub fn as_hash32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(bytes);
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_genesis() {
        assert_eq!(merkle_root(&[]), GENESIS_PREV);
    }

    #[test]
    fn single_leaf_is_itself() {
        let leaf = [0xab; 32];
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn two_leaves_hash_pair() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(merkle_root(&[a, b]), hash_pair(&a, &b));
    }

    #[test]
    fn three_leaves_pads_last() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        // level0: pair(a,b), pair(c,c)
        let l1_0 = hash_pair(&a, &b);
        let l1_1 = hash_pair(&c, &c);
        let expected = hash_pair(&l1_0, &l1_1);
        assert_eq!(merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn deterministic() {
        let leaves = [[9u8; 32], [8u8; 32], [7u8; 32], [6u8; 32]];
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
    }
}
