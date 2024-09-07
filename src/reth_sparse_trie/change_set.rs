use ahash::HashMap;
use alloy_primitives::{Address, Bytes, U256};
use reth_trie::Nibbles;
use revm::db::BundleAccount;
use revm_primitives::AccountInfo;

struct Scratchpad {
    // TODO: various caches and stored allocations
    // address_prehash_cache: HashMap<Address, Nibbles>,
    // storage_key_prehash_cache: HashMap<U256, Nibbles>,
}

struct ETHTrieChangeSet {
    account_trie_deletes: Vec<Nibbles>,

    account_trie_updates: Vec<Nibbles>,
    account_trie_updates_info: Vec<AccountInfo>,

    // for each acctount_trie_updates
    storage_trie_updated_keys: Vec<Vec<Nibbles>>,
    storage_trie_updated_values: Vec<Vec<Bytes>>,
    storage_trie_deleted_keys: Vec<Vec<Nibbles>>,
}

pub fn prepare_change_set<'a>(
    changes: impl Iterator<Item = (Address, &'a BundleAccount)>,
    scratchpad: &mut Scratchpad,
) -> ETHTrieChangeSet {
    todo!()
}
