pub mod trie_fetcher;

use crate::reth_sparse_trie::trie_fetcher::TrieFetcher;
use crate::sparse_mpt::{DeletionError, InsertionError, NodeNotFound, SparseMPT, SparseTrieStore};
use ahash::HashMap;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::Encodable;
use alloy_trie::Nibbles;
use dashmap::DashSet;
use reth::primitives::trie::TrieAccount;
use reth::providers::providers::ConsistentDbView;
use reth::providers::DatabaseProviderFactory;
use reth::revm::db::BundleAccount;
use reth::revm::primitives::AccountInfo;
use reth::tasks::pool::BlockingTaskPool;
use reth_db::database::Database;
use reth_interfaces::db::DatabaseError;
use reth_interfaces::provider::ProviderResult;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct RethSparseMPTSharedCache<DB, Provider> {
    state_trie_sparse_store: SparseTrieStore,
    account_tries_sparse_store: Arc<Mutex<HashMap<Address, SparseTrieStore>>>,
    blocking_task_pool: BlockingTaskPool,
    consistent_db_view: ConsistentDbView<DB, Provider>,
    // hashed address path
    fetched_account_proofs: DashSet<Address, ahash::RandomState>,
    // (hashed address, path)
    fetched_storage_proofs: DashSet<(Address, U256), ahash::RandomState>,
}

impl<DB, Provider> RethSparseMPTSharedCache<DB, Provider> {
    fn get_account_trie_sparse_store(&self, address: Address) -> SparseTrieStore {
        let mut stores = self.account_tries_sparse_store.lock().unwrap();
        stores.entry(address).or_default().clone()
    }
}

struct AccountFetchRequest {
    account: Address,
    slots: Vec<U256>,
}

impl<DB, Provider> RethSparseMPTSharedCache<DB, Provider>
where
    DB: Database,
    Provider: DatabaseProviderFactory<DB>,
{
    fn fetch_needed_proofs(&self, accounts: Vec<AccountFetchRequest>) -> ProviderResult<()> {
        /// TODO: parallel
        for account in accounts {
            if self.fetched_account_proofs.contains(&account.account) {
                continue;
            }

            let provider = self.consistent_db_view.provider_ro()?;

            let trie_fetcher = TrieFetcher::new(provider.tx_ref());

            let hashed_address = keccak256(account.account);
            let target = Nibbles::unpack(hashed_address.as_slice());

            let nodes = trie_fetcher
                .account_proof_path(target)
                .map_err(DatabaseError::from)?;
            self.state_trie_sparse_store
                .add_sparse_nodes_from_raw_proof(nodes);
            self.fetched_account_proofs.insert(account.account);

            let mut slots = Vec::new();
            let mut slots_path = Vec::new();
            for slot in account.slots {
                if self
                    .fetched_storage_proofs
                    .contains(&(account.account, slot))
                {
                    continue;
                }
                slots.push(slot);
                slots_path.push(Nibbles::unpack(&keccak256(B256::from(slot)).to_vec()));
            }
            if slots.is_empty() {
                continue;
            }

            let (_, storage_proofs) =
                trie_fetcher.storage_proof_paths(hashed_address, &slots_path)?;
            let account_trie = self.get_account_trie_sparse_store(account.account);
            account_trie.add_sparse_nodes_from_raw_proof(storage_proofs);
            for slot in slots {
                self.fetched_storage_proofs.insert((account.account, slot));
            }
        }
        Ok(())
    }

    fn fetch_missing_nodes(
        &self,
        missing_nodes: Vec<NodeNotFound>,
        missing_account_nodes: Vec<(B256, Vec<NodeNotFound>)>,
    ) -> ProviderResult<()> {
        let provider = self.consistent_db_view.provider_ro()?;

        let trie_fetcher = TrieFetcher::new(provider.tx_ref());
        for NodeNotFound { node, path } in missing_nodes {
            let proof = trie_fetcher.account_proof_path(path)?;
            self.state_trie_sparse_store
                .add_sparse_nodes_from_raw_proof(proof);
            if !self.state_trie_sparse_store.is_node_exists(&node) {
                panic!("State trie fetcher failed to get needed node");
            }
        }

        for (hashed_address, missing_nodes) in missing_account_nodes {
            let account_trie = self.get_account_trie_sparse_store(Address::from(hashed_address));
            let mut slots = Vec::new();
            let mut node_ref = Vec::new();
            for NodeNotFound { node, path } in missing_nodes {
                slots.push(path);
                node_ref.push(node);
            }

            let (_, storage_proofs) = trie_fetcher.storage_proof_paths(hashed_address, &slots)?;
            account_trie.add_sparse_nodes_from_raw_proof(storage_proofs);
            for node in node_ref {
                if !account_trie.is_node_exists(&node) {
                    panic!("Account trie fetcher failed to get needed node");
                }
            }
        }

        Ok(())
    }
}

pub struct RethSparseRootHash {
    cache: RethSparseMPTSharedCache,
}

struct AccountTrieChanges {
    address: Address,
    address_path: Vec<u8>,
    acccount_info: Option<AccountInfo>,
    slots: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl RethSparseRootHash {
    pub fn new_from_shared_cache(shared_cache: RethSparseMPTSharedCache) -> Self {
        todo!()
    }

    pub fn calc_root_hash<'a>(
        &mut self,
        bundle_accounts: impl Iterator<Item = (&'a Address, &'a BundleAccount)>,
    ) -> eyre::Result<B256> {
        let mut fetch_requests = Vec::new();
        let mut trie_changes = Vec::new();

        for (address, bundle_account) in bundle_accounts {
            let mut fetch_request = AccountFetchRequest {
                account: *address,
                // we always request proof for slot 0 to populate storage trie
                slots: vec![U256::ZERO],
            };

            let mut slot_trie_changes = Vec::new();
            for (slot, state) in &bundle_account.storage {
                if state.previous_or_original_value == state.present_value {
                    continue;
                }
                fetch_request.slots.push(*slot);
                let slot: B256 = (*slot).into();
                let slot_path = keccak256(slot.as_slice()).to_vec();
                let slot_value = if state.present_value.is_zero() {
                    None
                } else {
                    let value: B256 = state.present_value.into();
                    Some(value.to_vec())
                };
                slot_trie_changes.push((slot_path, slot_value));
            }
            fetch_requests.push(fetch_request);

            trie_changes.push(AccountTrieChanges {
                address: *address,
                address_path: keccak256(address.as_slice()).to_vec(),
                acccount_info: bundle_account.info.clone(),
                slots: slot_trie_changes,
            });
        }
        self.cache.fetch_needed_proofs(fetch_requests);

        let mut state_trie =
            SparseMPT::with_sparse_store(self.cache.state_trie_sparse_store.clone());
        let mut state_trie_missing_nodes = Vec::new();
        let mut storage_trie_missing_nodes = HashMap::default();

        for AccountTrieChanges {
            address,
            address_path,
            acccount_info,
            slots,
        } in trie_changes
        {
            // selfdestruct
            let account_info = if let Some(acccount_info) = acccount_info {
                acccount_info
            } else {
                match state_trie.delete(&address_path) {
                    Ok(_) => {}
                    Err(DeletionError::KeyNotFound) => {
                        eyre::bail!("key not found when deleting account, probably proofs were requested incorrectly");
                    }
                    Err(DeletionError::NodeNotFound(missing_node)) => {
                        state_trie_missing_nodes.push(missing_node);
                    }
                }
                continue;
            };

            // update account_root_hash
            let mut missing_account_trie_nodes = Vec::new();
            let mut account_storage_trie =
                SparseMPT::with_sparse_store(self.cache.get_account_trie_sparse_store(address));
            for (hashed_slot, new_value) in slots {
                match new_value {
                    Some(new_value) => {
                        match account_storage_trie.insert(&hashed_slot, &new_value) {
                            Ok(_) => {}
                            Err(InsertionError::NodeNotFound(node_not_found)) => {
                                missing_account_trie_nodes.push(node_not_found);
                            }
                        }
                    }
                    None => {}
                }
            }
            if !missing_account_trie_nodes.is_empty() {
                storage_trie_missing_nodes.insert(address, missing_account_trie_nodes);
                continue;
            }
            let storage_hash = account_storage_trie.root_hash();

            let mut account_trie_value: Vec<u8> = Vec::new();
            let trie_account = TrieAccount::from((account_info, storage_hash));
            trie_account.encode(&mut account_trie_value);

            match state_trie.insert(&address_path, &account_trie_value) {
                Ok(()) => {}
                Err(InsertionError::NodeNotFound(not_found)) => {
                    state_trie_missing_nodes.push(not_found);
                }
            }
        }

        if !state_trie_missing_nodes.is_empty() || !storage_trie_missing_nodes.is_empty() {
            todo!("fetch missing nodes");
        }

        Ok(state_trie.root_hash())
    }
}
