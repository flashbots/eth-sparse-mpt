mod toy_trie_tests;

use ahash::{HashMap, HashMapExt, HashSet};
use alloy_primitives::{Bytes, B256};
use alloy_trie::Nibbles;
use reth_db_api::database::Database;
use reth_db_api::transaction::DbTx;
use reth_provider::providers::ConsistentDbView;
use reth_provider::DatabaseProviderFactory;
use reth_trie::proof::Proof;
use reth_trie::{MultiProof as RethMultiProof, StorageMultiProof as RethStorageMultiProof};
use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use serde::{Deserialize, Serialize};

use super::shared_cache::MissingNodes;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MultiProof {
    pub account_subtree: HashMap<Nibbles, Bytes>,
    pub storages: HashMap<B256, StorageMultiProof>,
}

impl From<RethMultiProof> for MultiProof {
    fn from(reth_proof: RethMultiProof) -> Self {
        let mut account_subtree = HashMap::with_capacity(reth_proof.account_subtree.len());
        for (k, v) in reth_proof.account_subtree {
            account_subtree.insert(k, v);
        }
        let mut storages = HashMap::with_capacity(reth_proof.storages.len());
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
    pub subtree: HashMap<Nibbles, Bytes>,
}

impl From<RethStorageMultiProof> for StorageMultiProof {
    fn from(reth_proof: RethStorageMultiProof) -> Self {
        let mut subtree = HashMap::with_capacity(reth_proof.subtree.len());
        for (k, v) in reth_proof.subtree {
            subtree.insert(k, v);
        }
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
    Provider: DatabaseProviderFactory<DB>,
{
    pub fn new(consistent_db_view: ConsistentDbView<DB, Provider>) -> Self {
        Self { consistent_db_view }
    }

    pub fn fetch_missing_nodes(&self, missing_nodes: MissingNodes) -> eyre::Result<MultiProof> {
        let provider = self.consistent_db_view.provider_ro()?;
        let tx_fetcher = TrieFetcherTx::new(provider.tx_ref());
        tx_fetcher.fetch_missing_nodes(missing_nodes)
    }
}

#[derive(Debug)]
pub struct TrieFetcherTx<'a, TX> {
    tx: &'a TX,
}

impl<'a, TX> TrieFetcherTx<'a, TX>
where
    TX: DbTx,
{
    pub fn new(tx: &'a TX) -> Self {
        Self { tx }
    }

    pub fn fetch_missing_nodes(&self, mut missing_nodes: MissingNodes) -> eyre::Result<MultiProof> {
        // println!("mutliproof missing nodes: {:#?}", missing_nodes);
        let mut proof = Proof::new(
            DatabaseTrieCursorFactory::new(self.tx),
            DatabaseHashedCursorFactory::new(self.tx),
        );
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

        // println!("mutliproof targets: {:#?}", targets);
        let mut result: MultiProof = proof.with_targets(targets).multiproof()?.into();

        // when account does not exist in the trie its storage proof is non existant in the result so we add empty trie here
        for account in all_requested_accounts {
            if result.storages.contains_key(&account) {
                continue;
            }
            result
                .storages
                .insert(account, StorageMultiProof::default());
        }

        // println!("mutliproof result: {:#?}", result);
        Ok(result)
    }
}

fn pad_path(mut path: Nibbles) -> B256 {
    path.as_mut_vec_unchecked().resize(64, 0);
    let mut res = B256::default();
    path.pack_to(res.as_mut_slice());
    res
}
