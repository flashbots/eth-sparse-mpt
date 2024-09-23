use alloy_primitives::B256;
use change_set::prepare_change_set;
use reth_db_api::database::Database;
use reth_provider::providers::ConsistentDbView;
use reth_provider::DatabaseProviderFactory;
use reth_provider::ExecutionOutcome;
use std::time::Duration;
use std::time::Instant;

pub mod change_set;
pub mod hash;
pub mod local_cache;
pub mod shared_cache;
pub mod trie_fetcher;

use self::trie_fetcher::*;

pub use self::local_cache::RethSparseTrieLocalCache;
pub use self::shared_cache::RethSparseTrieSharedCache;

#[derive(Debug, Clone, Default)]
pub struct RethSparseTrieMetrics {
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
    thread_pool: Option<rayon::ThreadPool>,
    shared_cache: RethSparseTrieSharedCache,
    local_cache: Option<&mut RethSparseTrieLocalCache>,
) -> (eyre::Result<B256>, RethSparseTrieMetrics)
where
    DB: Database,
    Provider: DatabaseProviderFactory<DB>,
{
    // @perf use parallelism and local cache
    let _ = thread_pool;
    let _ = local_cache;

    let mut metrics = RethSparseTrieMetrics::default();

    let fetcher = TrieFetcher::new(consistent_db_view);

    let start = Instant::now();
    let change_set = prepare_change_set(outcome.bundle_accounts_iter());
    metrics.change_set_time += start.elapsed();

    // {
    //     let change_set_json = serde_json::to_string_pretty(&change_set).expect("to json fail");
    //     let mut file = std::fs::File::create("/tmp/changeset.json").unwrap();
    //     file.write_all(change_set_json.as_bytes()).unwrap();
    // }

    for _ in 0..3 {
        let start = Instant::now();
        let gather_result = shared_cache.gather_tries_for_changes(&change_set);
        metrics.gather_nodes_time += start.elapsed();

        let missing_nodes = match gather_result {
            Ok(mut tries) => {
                return {
                    let start = Instant::now();
                    let root_hash_result = tries.calculate_root_hash(change_set, true, true);
                    metrics.root_hash_time += start.elapsed();
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
        metrics.fetch_iterations += 1;

        // {
        //     let multiproof_json = serde_json::to_string_pretty(&multiproof).expect("to json fail");
        //     let mut file = std::fs::File::create(&format!("/tmp/mutliproof_{}.json", i)).unwrap();
        //     file.write_all(multiproof_json.as_bytes()).unwrap();
        // }

        metrics.fetch_nodes_time += start.elapsed();
        metrics.fetched_nodes += multiproof.len();

        let start = Instant::now();
        match shared_cache.update_cache_with_fetched_nodes(multiproof) {
            Err(err) => return (Err(err.into()), metrics),
            _ => {}
        };
        metrics.fill_cache_time += start.elapsed();
    }

    (
        Err(eyre::eyre!(
            "failed to fetch enough data after 3 iterations"
        )),
        metrics,
    )
}
