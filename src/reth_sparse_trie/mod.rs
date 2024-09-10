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

pub use self::shared_cache::RethSparseTrieSharedCache;

pub fn calculate_root_hash_with_sparse_trie<DB, Provider>(
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

    let start = Instant::now();
    let change_set = prepare_change_set(outcome.bundle_accounts_iter());
    let change_set_time = start.elapsed();

    for i in 0..3 {
        let start = Instant::now();
        let gather_result = shared_cache.gather_tries_for_changes(&change_set);
        let gather_time = start.elapsed();

        let missing_nodes = match gather_result {
            Ok(mut tries) => {
                return {
                    let start = Instant::now();
                    let root_hash_result = tries.calculate_root_hash(change_set);
                    let root_hash_time = start.elapsed();

                    println!("smpt root hash, iteration {}, change_set_time: {:?}, gather_time: {:?}, root_hash_time: {:?}", i, change_set_time, gather_time, root_hash_time);

                    return root_hash_result;
                }
            }
            Err(missing_nodes) => missing_nodes,
        };
        let start = Instant::now();
        let multiproof = fetcher.fetch_missing_nodes(missing_nodes)?;
        let fetch_time = start.elapsed();

        let start = Instant::now();
        shared_cache.update_cache_with_fetched_nodes(multiproof)?;
        let shared_cache_update_time = start.elapsed();
        println!("smpt fetched missing nodes, iteration: {}, fetch_time {:?}, shared_cache_update_time {:?}", i, fetch_time, shared_cache_update_time);
    }

    eyre::bail!("failed to fetch enough data after 3 iterations")
}

// let mut fetch_command_buffer = FetchCommandBuffer::new();
