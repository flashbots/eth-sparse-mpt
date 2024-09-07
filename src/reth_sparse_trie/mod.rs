use alloy_primitives::{keccak256, Address, B256};
use reth::tasks::pool::BlockingTaskPool;
use reth_db_api::database::Database;
use reth_provider::providers::ConsistentDbView;
use reth_provider::DatabaseProviderFactory;
use reth_provider::ExecutionOutcome;
use reth_trie::TrieAccount;
use revm_primitives::AccountInfo;

mod change_set;
mod internal;
pub mod trie_fetcher;

struct FetchCommandBuffer {}

impl FetchCommandBuffer {
    fn new() -> Self {
        todo!()
    }

    fn fetch_and_clear(&mut self) {
        todo!()
    }
}

struct NiceTrie {}

#[derive(Debug, thiserror::Error)]
enum TrieHashError {
    #[error("Missing node")]
    MissingNode,
    #[error("Other error {0}")]
    Other(eyre::Error),
}

impl NiceTrie {
    fn prepare_fetch_commands(
        &self,
        added_keys: &[B256],
        removed_keys: &[B256],
        fetch_commands: &mut FetchCommandBuffer,
    ) {
        todo!()
    }

    fn calc_hash(
        &self,
        updated_keys: &[B256],
        updated_values: &[Vec<u8>],
        removed_keys: &[B256],
        fetch_commands: &mut FetchCommandBuffer,
    ) -> Result<B256, TrieHashError> {
        todo!()
    }
}

struct NiceTrieFactory {}
impl NiceTrieFactory {
    fn get_accounts_trie(&self) -> NiceTrie {
        todo!()
    }

    fn get_storage_trie(&self, address: Address) -> NiceTrie {
        todo!()
    }
}

pub fn calculate_root_hash<DB, Provider>(
    consistent_db_view: ConsistentDbView<DB, Provider>,
    parent_hash: B256,
    outcome: &ExecutionOutcome,
    blocking_task_pool: BlockingTaskPool,

    // other keys
    ignore_missing_key_deletion: bool,
    nice_trie_factory: &NiceTrieFactory,
) -> eyre::Result<B256>
where
    DB: Database,
    Provider: DatabaseProviderFactory<DB>,
{
    let mut fetch_command_buffer = FetchCommandBuffer::new();

    let mut account_trie_deletes: Vec<B256> = Vec::new();

    let mut account_trie_updated_nodes: Vec<B256> = Vec::new();
    let mut account_trie_updated_account_info: Vec<AccountInfo> = Vec::new();

    let mut storage_tries: Vec<NiceTrie> = Vec::new();
    let mut storage_trie_updates_keys: Vec<Vec<B256>> = Vec::new();
    let mut storage_trie_updates_values: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut storage_trie_deletes: Vec<Vec<B256>> = Vec::new();
    for (address, bundle_account) in outcome.bundle_accounts_iter() {
        let status = bundle_account.status;
        if status.is_not_modified() {
            continue;
        }

        let hashed_address = keccak256(address);
        match bundle_account.account_info() {
            // account was modified
            Some(account) => {
                account_trie_updated_nodes.push(hashed_address);
                account_trie_updated_account_info.push(account);
            }
            // account was destroyed
            None => {
                account_trie_deletes.push(hashed_address);
                continue;
            }
        }
        let mut storage_trie_updates: Vec<B256> = Vec::new();
        let mut storage_trie_updated_values: Vec<Vec<u8>> = Vec::new();
        let mut storage_trie_deletes: Vec<B256> = Vec::new();
        for (storage_key, storage_value) in &bundle_account.storage {
            if !storage_value.is_changed() {
                continue;
            }
            let hashed_key = keccak256(B256::from(*storage_key));
            let value = storage_value.present_value();
            if value.is_zero() {
                storage_trie_deletes.push(hashed_key);
            } else {
                // @efficienty, alloy_fixed encoding
                let value = alloy_rlp::encode(value).to_vec();
                storage_trie_updates.push(hashed_key);
                storage_trie_updated_values.push(value);
            }
        }
        let storage_trie = nice_trie_factory.get_storage_trie(address);
        storage_trie.prepare_fetch_commands(
            &storage_trie_updates,
            &storage_trie_deletes,
            &mut fetch_command_buffer,
        );
        storage_tries.push(storage_trie);
    }

    let accounts_trie = nice_trie_factory.get_accounts_trie();
    accounts_trie.prepare_fetch_commands(
        &account_trie_updated_nodes,
        &account_trie_deletes,
        &mut fetch_command_buffer,
    );

    fetch_command_buffer.fetch_and_clear();

    let mut storage_root_hashes: Vec<Option<B256>> = vec![None; storage_tries.len()];
    let mut missing_storage_nodes = Vec::new();
    for i in 0..storage_tries.len() {
        match storage_tries[i].calc_hash(
            &storage_trie_updates_keys[i],
            &storage_trie_updates_values[i],
            &storage_trie_deletes[i],
            &mut fetch_command_buffer,
        ) {
            Ok(hash) => storage_root_hashes[i] = Some(hash),
            Err(TrieHashError::MissingNode) => {
                missing_storage_nodes.push(i);
            }
            Err(err) => {
                return Err(err.into());
            }
        }
    }

    todo!()
}
