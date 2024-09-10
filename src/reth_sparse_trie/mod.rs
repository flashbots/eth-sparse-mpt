use alloy_primitives::B256;
use change_set::prepare_change_set;
use reth::tasks::pool::BlockingTaskPool;
use reth_db_api::database::Database;
use reth_provider::providers::ConsistentDbView;
use reth_provider::DatabaseProviderFactory;
use reth_provider::ExecutionOutcome;
use std::time::Instant;
use std::time::Duration;

pub mod change_set;
pub mod hash;
pub mod shared_cache;
pub mod local_cache;
pub mod trie_fetcher;

use self::trie_fetcher::*;

pub use self::shared_cache::RethSparseTrieSharedCache;
pub use self::local_cache::RethSparseTrieLocalCache;

#[derive(Debug, Clone, Default)]
pub struct RethSparseTrieMetsics {
    pub change_set_time: Duration,
    pub gather_nodes_time: Duration,
    pub fetch_iterations: usize,
    pub missing_nodes: usize,
    pub fetched_nodes: usize,
    pub fetch_nodes_time: Duration,
    pub fill_cache_time: Duration,
    pub root_hash_time: Duration,
}

/// Calculate root hash for the given outcome on top of the block defined by consistent_db_view.
/// * shared_cache should be created once for each parent block and it stores fethed pieces of the trie 
/// * blocking_task_pool - implemenation will use parallelism if set (not implemented right now)
/// * local_cache - implemenation will use is to cache some operations.
///   It should be owned by one thread that computes root hash in a loop.
pub fn calculate_root_hash_with_sparse_trie<DB, Provider>(
    consistent_db_view: ConsistentDbView<DB, Provider>,
    outcome: &ExecutionOutcome,
    blocking_task_pool: Option<BlockingTaskPool>,
    shared_cache: RethSparseTrieSharedCache,
    local_cache: Option<&mut RethSparseTrieLocalCache>,
) -> (eyre::Result<B256>, RethSparseTrieMetsics)
where
    DB: Database,
    Provider: DatabaseProviderFactory<DB>,
{
    // @perf use parallelism and local cache
    let _ = blocking_task_pool;
    let _ = local_cache;

    let mut metrics = RethSparseTrieMetsics::default();

    let fetcher = TrieFetcher::new(consistent_db_view);

    let start = Instant::now();
    let change_set = prepare_change_set(outcome.bundle_accounts_iter());
    metrics.change_set_time = start.elapsed();

    for _ in 0..3 {
	metrics.fetch_iterations += 1;
        let start = Instant::now();
        let gather_result = shared_cache.gather_tries_for_changes(&change_set);
	metrics.gather_nodes_time += start.elapsed();

        let missing_nodes = match gather_result {
            Ok(mut tries) => {
                return {
                    let start = Instant::now();
                    let root_hash_result = tries.calculate_root_hash(change_set);
                    metrics.root_hash_time = start.elapsed();
                    (root_hash_result, metrics)
                }
            }
            Err(missing_nodes) => missing_nodes,
        };
	metrics.missing_nodes += missing_nodes.len();
        let start = Instant::now();
        let multiproof = match fetcher.fetch_missing_nodes(missing_nodes) {
	    Ok(ok) => ok,
	    Err(err) => return (Err(err.into()), metrics),
	};
        metrics.fetch_nodes_time += start.elapsed();
	metrics.fetched_nodes += multiproof.len();

        let start = Instant::now();
        match shared_cache.update_cache_with_fetched_nodes(multiproof) {
	    Err(err) => return (Err(err.into()), metrics),
	    _ => {},
	};
        metrics.fill_cache_time = start.elapsed();
    }

    (Err(eyre::eyre!("failed to fetch enough data after 3 iterations")), metrics)
}
