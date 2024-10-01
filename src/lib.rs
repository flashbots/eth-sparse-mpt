//! This library is useful when you need to calculate Ethereum root hash many times on top of the same parent block using reth database.
//!
//! To use this, for each parent block:
//! * create `SparseTrieSharedCache`
//! * call `calculate_root_hash_with_sparse_trie` with the given cache, reth db view and execution outcome.

pub mod reth_sparse_trie;
pub mod sparse_mpt;
pub mod utils;

pub use reth_sparse_trie::{
    calculate_root_hash_with_sparse_trie, prefetch_tries_for_accounts, ChangedAccountData,
    SparseTrieSharedCache,
};
