use crate::utils::{hash_map_with_capacity, HashMap, HashSet};
use alloy_primitives::{Bytes, B256};
use alloy_trie::Nibbles;
use rayon::prelude::*;
use reth_db_api::database::Database;
use reth_errors::ProviderError;
use reth_execution_errors::trie::StateProofError;
use reth_provider::providers::ConsistentDbView;
use reth_provider::DatabaseProviderFactory;
use reth_trie::proof::Proof;
use reth_trie::{MultiProof as RethMultiProof, StorageMultiProof as RethStorageMultiProof};
use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Seq};
use std::collections::HashMap as StdHashMap;

use super::shared_cache::MissingNodes;

#[derive(Debug, thiserror::Error)]
pub enum FetchNodeError {
    #[error("Provider error {0:?}")]
    ProviderError(#[from] ProviderError),
    #[error("Provider error {0:?}")]
    StateProofError(#[from] StateProofError),
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MultiProof {
    pub account_subtree: Vec<(Nibbles, Bytes)>,
    #[serde_as(as = "Seq<(_, _)>")]
    pub storages: HashMap<B256, StorageMultiProof>,
}

impl MultiProof {
    pub fn len(&self) -> usize {
        self.account_subtree.len()
            + self
                .storages
                .iter()
                .map(|(_, v)| v.subtree.len())
                .sum::<usize>()
    }
}

impl From<RethMultiProof> for MultiProof {
    fn from(reth_proof: RethMultiProof) -> Self {
        let mut account_subtree = Vec::with_capacity(reth_proof.account_subtree.len());
        for (k, v) in reth_proof.account_subtree {
            account_subtree.push((k, v));
        }
        account_subtree.sort_by_key(|a| a.0.clone());
        let mut storages = hash_map_with_capacity(reth_proof.storages.len());
        for (k, v) in reth_proof.storages {
            storages.insert(k, v.into());
        }
        Self {
            account_subtree,
            storages,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct StorageMultiProof {
    pub subtree: Vec<(Nibbles, Bytes)>,
}

impl From<RethStorageMultiProof> for StorageMultiProof {
    fn from(reth_proof: RethStorageMultiProof) -> Self {
        let mut subtree = Vec::with_capacity(reth_proof.subtree.len());
        for (k, v) in reth_proof.subtree {
            subtree.push((k, v));
        }
        subtree.sort_by_key(|a| a.0.clone());
        Self { subtree }
    }
}

#[derive(Debug)]
pub struct TrieFetcher<DB, Provider> {
    consistent_db_view: ConsistentDbView<DB, Provider>,
}

impl<DB, Provider> TrieFetcher<DB, Provider>
where
    DB: Database,
    Provider: DatabaseProviderFactory<DB> + Send + Sync,
{
    pub fn new(consistent_db_view: ConsistentDbView<DB, Provider>) -> Self {
        Self { consistent_db_view }
    }

    pub fn fetch_missing_nodes(
        &self,
        missing_nodes: MissingNodes,
    ) -> Result<MultiProof, FetchNodeError> {
        let (targets, all_requested_accounts) = get_proof_targets(missing_nodes);

        let proofs: Vec<_> = targets
            .into_par_iter()
            .map(|targets| -> Result<MultiProof, FetchNodeError> {
                let provider = self.consistent_db_view.provider_ro()?;

                let proof = Proof::new(
                    DatabaseTrieCursorFactory::new(provider.tx_ref()),
                    DatabaseHashedCursorFactory::new(provider.tx_ref()),
                );

                let result: MultiProof = proof.with_targets(targets).multiproof()?.into();
                Ok(result)
            })
            .collect();

        let mut proofs_ok = Vec::new();
        for res in proofs {
            proofs_ok.push(res?);
        }
        Ok(merge_results(proofs_ok, all_requested_accounts))
    }
}

fn pad_path(mut path: Nibbles) -> B256 {
    path.as_mut_vec_unchecked().resize(64, 0);
    let mut res = B256::default();
    path.pack_to(res.as_mut_slice());
    res
}

fn get_proof_targets(
    missing_nodes: MissingNodes,
) -> (Vec<StdHashMap<B256, Vec<B256>>>, HashSet<B256>) {
    // we will split all missing nodes accounts into buckets of (missing accounts / account_per_fetch)
    let account_per_fetch = 5;

    let mut targets = std::collections::HashMap::new();
    let mut all_requested_accounts = HashSet::default();
    for account_trie_node in missing_nodes.account_trie_nodes {
        let is_address = account_trie_node.len() == 64;
        let hashed_address = pad_path(account_trie_node);
        if is_address {
            all_requested_accounts.insert(hashed_address);
        }
        targets.insert(hashed_address, Vec::new());
    }
    for (account, missing_storage_nodes) in missing_nodes.storage_trie_nodes {
        let hashed_address = B256::from_slice(&account);
        all_requested_accounts.insert(hashed_address);
        let storage_targets = targets.entry(hashed_address).or_default();
        for node in missing_storage_nodes {
            let node = pad_path(node);
            storage_targets.push(node);
        }
    }

    let mut result = Vec::new();
    let mut iter = targets.into_iter();
    loop {
        let mut split_target = StdHashMap::new();
        let mut count = 0;
        while let Some((target_key, target_value)) = iter.next() {
            split_target.insert(target_key, target_value);
            count += 1;
            if count > account_per_fetch {
                break;
            }
        }
        if split_target.is_empty() {
            break;
        } else {
            result.push(split_target);
        }
    }
    (result, all_requested_accounts)
}

fn merge_results(
    multiproofs: Vec<MultiProof>,
    all_requested_accounts: HashSet<B256>,
) -> MultiProof {
    let mut result = MultiProof::default();
    for mut proof in multiproofs {
        result.account_subtree.append(&mut proof.account_subtree);
        result.account_subtree.sort_by_key(|s| s.0.clone());
        result.account_subtree.dedup_by_key(|s| s.0.clone());

        for (account, mut storage_proof) in proof.storages {
            let result_storage_proof = result.storages.entry(account).or_default();
            result_storage_proof
                .subtree
                .append(&mut storage_proof.subtree);
            result_storage_proof.subtree.sort_by_key(|s| s.0.clone());
            result_storage_proof.subtree.dedup_by_key(|s| s.0.clone());
        }
    }

    for account in all_requested_accounts {
        result
            .storages
            .entry(account)
            .or_insert_with(|| StorageMultiProof::default());
    }
    result
}
