use std::fs::read_to_string;

use ahash::HashMap;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use eth_sparse_mpt::reth_sparse_trie::change_set::ETHTrieChangeSet;
use eth_sparse_mpt::reth_sparse_trie::hash::EthSparseTries;
use eth_sparse_mpt::reth_sparse_trie::trie_fetcher::MultiProof;
use eth_sparse_mpt::reth_sparse_trie::RethSparseTrieSharedCache;
use eth_sparse_mpt::sparse_mpt::SparseTrieNodes;

fn get_test_mutliproofs() -> Vec<MultiProof> {
    let files = [
        "./test_data/mutliproof_0.json",
        "./test_data/mutliproof_1.json",
    ];
    let mut result = Vec::new();
    for file in files {
        let data = read_to_string(file).expect("reading multiproof");
        result.push(serde_json::from_str(&data).expect("parsing multiproof"));
    }
    result
}

fn get_change_set() -> ETHTrieChangeSet {
    let data = read_to_string("./test_data/changeset.json").expect("reading changeset");
    serde_json::from_str(&data).expect("parsing changeset")
}

fn get_storage_tries(changes: &ETHTrieChangeSet, tries: &EthSparseTries) -> Vec<SparseTrieNodes> {
    let mut storage_tries = Vec::new();
    for (_, account) in changes.account_trie_updates.iter().enumerate() {
        storage_tries.push(
            tries
                .storage_tries
                .get(account)
                .expect("storage trie must exist")
                .clone(),
        );
    }
    storage_tries
}

fn apply_storage_tries_changes<'a>(
    storage_tries: impl Iterator<Item = &'a mut SparseTrieNodes>,
    changes: &ETHTrieChangeSet,
) {
    for (i, trie) in storage_tries.enumerate() {
        let keys = &changes.storage_trie_updated_keys[i];
        let value = &changes.storage_trie_updated_values[i];
        let deletes = &changes.storage_trie_deleted_keys[i];
        for (k, v) in keys.iter().zip(value) {
            trie.insert(k.clone(), v.clone())
                .expect("must insert storage trie");
        }
        for d in deletes {
            trie.delete(d.clone()).expect("must delete storage trie");
        }
    }
}

fn gather_nodes(c: &mut Criterion) {
    let multiproof = get_test_mutliproofs();
    let changes = get_change_set();

    let shared_cache = RethSparseTrieSharedCache::default();
    for p in multiproof {
        shared_cache
            .update_cache_with_fetched_nodes(p)
            .expect("populate shared cache")
    }

    let tries = shared_cache.gather_tries_for_changes(&changes).unwrap();
    println!(
        "acc trie len: {}, count: {:?}",
        tries.account_trie.len(),
        tries.account_trie.count_nodes()
    );

    c.bench_function("gather_nodes_clone_acc_trie", |b| {
        b.iter(|| {
            let out = tries.clone();
            black_box(out);
        })
    });

    c.bench_function("gather_nodes", |b| {
        b.iter(|| {
            let out = shared_cache
                .gather_tries_for_changes(&changes)
                .expect("gather must succed");
            black_box(out);
        })
    });
}

fn root_hash_main_trie(c: &mut Criterion) {
    let multiproof = get_test_mutliproofs();
    let changes = get_change_set();

    let shared_cache = RethSparseTrieSharedCache::default();
    for p in multiproof {
        shared_cache
            .update_cache_with_fetched_nodes(p)
            .expect("populate shared cache")
    }

    let mut trie = shared_cache
        .gather_tries_for_changes(&changes)
        .expect("gather must succed")
        .account_trie;
    for key in changes.account_trie_updates {
        trie.insert(key.clone(), key.clone()).expect("must instert");
    }
    for key in changes.account_trie_deletes {
        trie.delete(key).expect("must update");
    }

    c.bench_function("root_hash_main_trie_no_cache", |b| {
        b.iter_batched(
            || trie.clone(),
            |mut trie| trie.root_hash().expect("must hash"),
            BatchSize::SmallInput,
        );
    });

    let mut root_hash_cache = HashMap::default();
    c.bench_function("root_hash_main_trie_with_cache", |b| {
        b.iter_batched(
            || trie.clone(),
            |mut trie| {
                trie.root_hash_no_recursion(Some(&mut root_hash_cache))
                    .expect("must hash")
            },
            BatchSize::SmallInput,
        );
    });
}

fn root_hash_accounts(c: &mut Criterion) {
    let multiproof = get_test_mutliproofs();
    let changes = get_change_set();

    let shared_cache = RethSparseTrieSharedCache::default();
    for p in multiproof {
        shared_cache
            .update_cache_with_fetched_nodes(p)
            .expect("populate shared cache")
    }

    let tries = shared_cache
        .gather_tries_for_changes(&changes)
        .expect("gather must succed");

    c.bench_function("root_hash_accounts_insert", |b| {
        b.iter_batched(
            || get_storage_tries(&changes, &tries),
            |mut storage_tries| {
                apply_storage_tries_changes(storage_tries.iter_mut(), &changes);
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("root_hash_accounts_hash_no_recursion_no_cache", |b| {
        b.iter_batched(
            || get_storage_tries(&changes, &tries),
            |mut storage_tries| {
                apply_storage_tries_changes(storage_tries.iter_mut(), &changes);
                for trie in storage_tries.iter_mut() {
                    trie.root_hash_no_recursion(None)
                        .expect("must hash storage trie");
                }
            },
            BatchSize::SmallInput,
        );
    });

    let mut root_hash_cache = HashMap::default();
    c.bench_function("root_hash_accounts_hash_no_recursion_with_cache", |b| {
        b.iter_batched(
            || get_storage_tries(&changes, &tries),
            |mut storage_tries| {
                apply_storage_tries_changes(storage_tries.iter_mut(), &changes);
                for trie in storage_tries.iter_mut() {
                    trie.root_hash_no_recursion(Some(&mut root_hash_cache))
                        .expect("must hash storage trie");
                }
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("root_hash_old_accounts_hash_no_cache", |b| {
        b.iter_batched(
            || get_storage_tries(&changes, &tries),
            |mut storage_tries| {
                apply_storage_tries_changes(storage_tries.iter_mut(), &changes);
                for trie in storage_tries.iter_mut() {
                    trie.root_hash_advanced(false, None)
                        .expect("must hash storage trie");
                }
            },
            BatchSize::SmallInput,
        );
    });

    let mut root_hash_cache = HashMap::default();
    c.bench_function("root_hash_old_accounts_hash_with_cache", |b| {
        b.iter_batched(
            || get_storage_tries(&changes, &tries),
            |mut storage_tries| {
                apply_storage_tries_changes(storage_tries.iter_mut(), &changes);
                for trie in storage_tries.iter_mut() {
                    trie.root_hash_advanced(false, Some(&mut root_hash_cache))
                        .expect("must hash storage trie");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    gather_nodes,
    root_hash_main_trie,
    root_hash_accounts
);
criterion_main!(benches);
