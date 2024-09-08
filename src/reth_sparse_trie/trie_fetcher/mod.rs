mod toy_trie_tests;

use ahash::{HashMap, HashMapExt};
use alloy_primitives::{Bytes, B256};
use alloy_trie::Nibbles;
use reth_db_api::transaction::DbTx;
use reth_trie::proof::Proof;
use reth_trie::{MultiProof as RethMultiProof, StorageMultiProof as RethStorageMultiProof};
use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use serde::{Deserialize, Serialize};

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
pub struct TrieFetcher<'a, TX> {
    tx: &'a TX,
}

impl<'a, TX> TrieFetcher<'a, TX>
where
    TX: DbTx,
{
    pub fn new(tx: &'a TX) -> Self {
        Self { tx }
    }

    pub fn foo(&self) {
        let mut proof = Proof::new(
            DatabaseTrieCursorFactory::new(self.tx),
            DatabaseHashedCursorFactory::new(self.tx),
        );
        proof.with_targets(todo!());
        proof.multiproof();
    }
}
