use std::fs::read_to_string;

use alloy_primitives::{keccak256, Bytes, B256, U256};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use eth_sparse_mpt::reth_sparse_trie::change_set::ETHTrieChangeSet;
use eth_sparse_mpt::reth_sparse_trie::trie_fetcher::MultiProof;
use eth_sparse_mpt::reth_sparse_trie::RethSparseTrieSharedCache;
use eth_sparse_mpt::sparse_mpt::SparseTrieNodes;
use eth_sparse_mpt::utils::KeccakHasher;

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

fn gather_nodes(c: &mut Criterion) {
    let multiproof = get_test_mutliproofs();
    let changes = get_change_set();

    let shared_cache = RethSparseTrieSharedCache::default();
    for p in multiproof {
        shared_cache
            .update_cache_with_fetched_nodes(p)
            .expect("populate shared cache")
    }

    let out = shared_cache
        .gather_tries_for_changes(&changes)
        .expect("gather must succed");

    c.bench_function("gather_nodes", |b| {
        b.iter(|| {
            let out = shared_cache
                .gather_tries_for_changes(&changes)
                .expect("gather must succed");
            black_box(out);
        })
    });
}

criterion_group!(benches, gather_nodes,);
criterion_main!(benches);
