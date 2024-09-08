use alloy_primitives::{keccak256, Address, B256};
use change_set::prepare_change_set;
use reth::tasks::pool::BlockingTaskPool;
use reth_db_api::database::Database;
use reth_provider::providers::ConsistentDbView;
use reth_provider::DatabaseProviderFactory;
use reth_provider::ExecutionOutcome;
use reth_trie::TrieAccount;
use revm_primitives::AccountInfo;
use std::time::Instant;

pub mod change_set;
pub mod internal;
pub mod shared_cache;
pub mod trie_fetcher;

use self::shared_cache::*;
use self::trie_fetcher::*;

pub fn calculate_root_hash<DB, Provider>(
    consistent_db_view: ConsistentDbView<DB, Provider>,
    parent_hash: B256,
    outcome: &ExecutionOutcome,
    _blocking_task_pool: BlockingTaskPool,

    shared_cache: RethSparseTrieSharedCache,
) -> eyre::Result<B256>
where
    DB: Database,
    Provider: DatabaseProviderFactory<DB>,
{
    let fetcher = TrieFetcher::new(consistent_db_view);
    let change_set = prepare_change_set(outcome.bundle_accounts_iter());

    for _ in 0..3 {
        let missing_nodes = match shared_cache.gather_tries_for_changes(&change_set) {
            Ok(mut tries) => return tries.calculate_root_hash(change_set),
            Err(missing_nodes) => missing_nodes,
        };
        let multiproof = fetcher.fetch_missing_nodes(missing_nodes)?;
        shared_cache.update_cache_with_fetched_nodes(multiproof)?;
    }

    eyre::bail!("failed to fetch enough data after 3 iterations")
}

// let mut fetch_command_buffer = FetchCommandBuffer::new();
