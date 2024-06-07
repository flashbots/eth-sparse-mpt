use crate::sparse_mpt::{DeletionError, InsertionError, NodeNotFound, SparseMPT, SparseTrieStore};
use ahash::HashMap;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::Encodable;
use alloy_trie::Nibbles;
use eyre::eyre;
use reth::primitives::trie::TrieAccount;
use reth::revm::db::BundleAccount;
use reth::revm::primitives::AccountInfo;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default)]
pub struct RethSparseMPTSharedCache {
    state_trie_sparse_store: SparseTrieStore,
    account_tries_sparse_store: Arc<Mutex<HashMap<Address, SparseTrieStore>>>,
}

impl RethSparseMPTSharedCache {
    fn get_account_trie_sparse_store(&self, address: Address) -> SparseTrieStore {
        let mut stores = self.account_tries_sparse_store.lock().unwrap();
        stores.entry(address).or_default().clone()
    }
}

struct AccountFetchRequest {
    account: Address,
    slots: Vec<U256>,
}

impl RethSparseMPTSharedCache {
    fn fetch_needed_proofs(&self, accounts: Vec<AccountFetchRequest>) {
        todo!()
    }

    fn fetch_missing_nodes(
        &self,
        missing_nodes: Vec<NodeNotFound>,
        missing_account_nodes: Vec<(Vec<u8>, NodeNotFound)>,
    ) {
        todo!()
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
                slots: vec![],
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
