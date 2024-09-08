use ahash::HashMap;
use std::sync::{Arc, Mutex};

use super::change_set::ETHTrieChangeSet;
use super::internal::EthSparseTries;
use super::trie_fetcher::MultiProof;
use crate::neo_sparse_mpt::{SparseTrieError, SparseTrieNodes};
use alloy_primitives::Bytes;
use alloy_trie::Nibbles;

#[derive(Debug, Clone, Default)]
pub struct RethSparseTrieSharedCache {
    internal: Arc<Mutex<RethSparseTrieShareCacheInternal>>,
}

pub struct StorageTrieInfo {}

#[derive(Default)]
pub struct MissingNodes {
    pub account_trie_nodes: Vec<Nibbles>,
    pub storage_trie_nodes: HashMap<Bytes, Vec<Nibbles>>,
}

impl MissingNodes {
    pub fn is_empty(&self) -> bool {
        self.account_trie_nodes.is_empty() && self.storage_trie_nodes.is_empty()
    }
}

impl RethSparseTrieSharedCache {
    pub fn gather_tries_for_changes(
        &self,
        change_set: &ETHTrieChangeSet,
    ) -> Result<EthSparseTries, MissingNodes> {
        let mut internal = self.internal.lock().unwrap();
        internal.gather_tries_for_changes(change_set)
    }

    pub fn update_cache_with_fetched_nodes(
        &self,
        multiproof: MultiProof,
    ) -> Result<(), SparseTrieError> {
        let mut internal = self.internal.lock().unwrap();
        internal.update_cache_with_fetched_nodes(multiproof)
    }
}

#[derive(Debug, Clone, Default)]
struct RethSparseTrieShareCacheInternal {
    account_trie: SparseTrieNodes,
    storage_tries: HashMap<Bytes, SparseTrieNodes>,
}

impl RethSparseTrieShareCacheInternal {
    fn new() -> Self {
        Self {
            account_trie: SparseTrieNodes::uninit_trie(),
            storage_tries: HashMap::default(),
        }
    }

    pub fn gather_tries_for_changes(
        &mut self,
        change_set: &ETHTrieChangeSet,
    ) -> Result<EthSparseTries, MissingNodes> {
        let mut missing_nodes = MissingNodes::default();
        let mut tries = EthSparseTries::default();

        match self.account_trie.gather_subtrie(
            &change_set.account_trie_updates,
            &change_set.account_trie_deletes,
        ) {
            Ok(account_trie) => {
                tries.account_trie = account_trie;
            }
            Err(missing_acccount_trie_nodes) => {
                missing_nodes.account_trie_nodes = missing_acccount_trie_nodes.nodes;
            }
        }

        for acc_idx in 0..change_set.account_trie_updates.len() {
            let account = change_set.account_trie_updates[acc_idx].clone();
            let updates = &change_set.storage_trie_updated_keys[acc_idx];
            let deletes = &change_set.storage_trie_deleted_keys[acc_idx];
            let storage_trie = self.storage_tries.entry(account.clone()).or_default();
            match storage_trie.gather_subtrie(&updates, &deletes) {
                Ok(storage_trie) => {
                    tries.storage_tries.insert(account, storage_trie);
                }
                Err(missing_storage_trie_nodes) => {
                    missing_nodes
                        .storage_trie_nodes
                        .insert(account, missing_storage_trie_nodes.nodes);
                }
            }
        }

        if missing_nodes.is_empty() {
            Ok(tries)
        } else {
            Err(missing_nodes)
        }
    }

    pub fn update_cache_with_fetched_nodes(
        &mut self,
        multiproof: MultiProof,
    ) -> Result<(), SparseTrieError> {
        self.account_trie
            .add_nodes(multiproof.account_subtree.into_iter())?;
        for (account, storge_proofs) in multiproof.storages {
            let account = Bytes::copy_from_slice(account.as_slice());
            let storage_trie = self.storage_tries.entry(account).or_default();
            storage_trie.add_nodes(storge_proofs.subtree.into_iter())?;
        }
        Ok(())
    }
}
