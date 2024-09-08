mod toy_trie_tests;

use ahash::{HashMap, HashMapExt};
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageMultiProof {
    pub root: B256,
    pub subtree: HashMap<Nibbles, Bytes>,
}

impl From<RethStorageMultiProof> for StorageMultiProof {
    fn from(reth_proof: RethStorageMultiProof) -> Self {
        let mut subtree = HashMap::with_capacity(reth_proof.subtree.len());
        for (k, v) in reth_proof.subtree {
            subtree.insert(k, v);
        }
        Self {
            root: reth_proof.root,
            subtree,
        }
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
        let mut proof = Proof::new(
            DatabaseTrieCursorFactory::new(self.tx),
            DatabaseHashedCursorFactory::new(self.tx),
        );
        let mut targets = std::collections::HashMap::new();
        for account_trie_node in missing_nodes.account_trie_nodes {
            if account_trie_node.len() == 64 {
                let mut hashed_address = pad_path(account_trie_node);
                let bytes = Bytes::copy_from_slice(hashed_address.as_slice());
                let storage_targets = if let Some(storage_targets) =
                    missing_nodes.storage_trie_nodes.remove(&bytes)
                {
                    let mut res = Vec::new();
                    for storage_path in storage_targets {
                        res.push(pad_path(storage_path));
                    }
                    res
                } else {
                    Vec::new()
                };
                targets.insert(hashed_address, storage_targets);
            } else {
                targets.insert(pad_path(account_trie_node), Vec::new());
            }
        }
        Ok(proof.with_targets(targets).multiproof()?.into())
    }
}

fn pad_path(mut path: Nibbles) -> B256 {
    path.as_mut_vec_unchecked().resize(64, 0);
    let mut res = B256::default();
    path.pack_to(res.as_mut_slice());
    res
}
