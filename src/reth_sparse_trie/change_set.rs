use alloy_primitives::{keccak256, Address, Bytes, B256};
use revm::db::BundleAccount;
use revm_primitives::AccountInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ETHTrieChangeSet {
    pub account_trie_deletes: Vec<Bytes>,

    pub account_trie_updates: Vec<Bytes>,
    pub account_trie_updates_info: Vec<AccountInfo>,

    // for each account_trie_updates
    pub storage_trie_updated_keys: Vec<Vec<Bytes>>,
    pub storage_trie_updated_values: Vec<Vec<Bytes>>,
    pub storage_trie_deleted_keys: Vec<Vec<Bytes>>,
}

pub fn prepare_change_set<'a>(
    changes: impl Iterator<Item = (Address, &'a BundleAccount)>,
) -> ETHTrieChangeSet {
    let mut account_trie_deletes: Vec<Bytes> = Vec::new();

    let mut account_trie_updates: Vec<Bytes> = Vec::new();
    let mut account_trie_updates_info: Vec<AccountInfo> = Vec::new();

    let mut storage_trie_updated_keys: Vec<Vec<Bytes>> = Vec::new();
    let mut storage_trie_updated_values: Vec<Vec<Bytes>> = Vec::new();
    let mut storage_trie_deleted_keys: Vec<Vec<Bytes>> = Vec::new();
    for (address, bundle_account) in changes {
        let status = bundle_account.status;
        if status.is_not_modified() {
            continue;
        }

        // @cache consider caching in the scratchpad
        let hashed_address = Bytes::copy_from_slice(keccak256(address).as_slice());

        match bundle_account.account_info() {
            // account was modified
            Some(account) => {
                account_trie_updates.push(hashed_address);
                account_trie_updates_info.push(account.without_code());
            }
            // account was destroyed
            None => {
                account_trie_deletes.push(hashed_address);
                continue;
            }
        }

        let mut storage_updates_keys: Vec<Bytes> = Vec::new();
        let mut storage_updates_values: Vec<Bytes> = Vec::new();
        let mut storage_deleted_keys: Vec<Bytes> = Vec::new();
        for (storage_key, storage_value) in &bundle_account.storage {
            if !storage_value.is_changed() {
                continue;
            }
            // @cache consider caching in the scratchpad
            let hashed_key = Bytes::copy_from_slice(keccak256(B256::from(*storage_key)).as_slice());
            let value = storage_value.present_value();
            if value.is_zero() {
                storage_deleted_keys.push(hashed_key);
            } else {
                // @efficienty, alloy_fixed encoding
                let value = Bytes::from(alloy_rlp::encode(value));
                storage_updates_keys.push(hashed_key);
                storage_updates_values.push(value);
            }
        }
        storage_trie_updated_keys.push(storage_updates_keys);
        storage_trie_updated_values.push(storage_updates_values);
        storage_trie_deleted_keys.push(storage_deleted_keys);
    }

    ETHTrieChangeSet {
        account_trie_deletes,
        account_trie_updates,
        account_trie_updates_info,
        storage_trie_updated_keys,
        storage_trie_updated_values,
        storage_trie_deleted_keys,
    }
}
