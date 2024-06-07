use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::nodes::TrieNode;
use criterion::{criterion_group, criterion_main, Criterion};
use eth_sparse_mpt::sparse_mpt::{SparseMPT, SparseTrieStore};
use eth_sparse_mpt::utils::{clone_trie_node, KeccakHasher, StoredProof};

fn add_elements(keys: &[&[u8]], values: &[&[u8]]) -> B256 {
    triehash::trie_root::<KeccakHasher, _, _, _>(keys.iter().zip(values))
}

fn add_elements_sparse_trie(keys: &[&[u8]], values: &[&[u8]]) -> B256 {
    let mut trie = SparseMPT::new_empty();
    for (key, value) in keys.iter().zip(values.iter()) {
        trie.insert(key, value).expect("can't insert");
    }
    trie.root_hash()
}

fn trie_insert(c: &mut Criterion) {
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for i in 0u64..3000 {
        let b: B256 = U256::from(i).into();
        let data = keccak256(b).to_vec();
        keys.push(data.clone());
        values.push(data.clone());
    }
    let input_keys = keys.iter().map(|x| x.as_slice()).collect::<Vec<_>>();
    let input_values = values.iter().map(|x| x.as_slice()).collect::<Vec<_>>();
    c.bench_function("trie 3000 elements reference", |b| {
        b.iter(|| add_elements(&input_keys, &input_values))
    });
    c.bench_function("trie 3000 elements sparse trie", |b| {
        b.iter(|| add_elements_sparse_trie(&input_keys, &input_values))
    });
}

fn insert_proof(proofs: &Vec<Vec<TrieNode>>) {
    let mut sparse_trie_store = SparseTrieStore::default();
    for proof in proofs {
        sparse_trie_store.add_sparse_nodes_from_proof(proof.iter().map(clone_trie_node).collect());
    }
}

fn proof_insert(c: &mut Criterion) {
    let stored_proof = StoredProof::load_known_proofs();
    let proof_paths = stored_proof
        .into_iter()
        .map(|p| p.nodes())
        .collect::<Vec<_>>();
    c.bench_function("insert all account proofs into sparse trie", |b| {
        b.iter(|| insert_proof(&proof_paths))
    });
}

fn sparse_trie_update(c: &mut Criterion) {
    let proofs = StoredProof::load_known_proofs();

    let mut keys = Vec::new();
    let mut values = Vec::new();

    for p in proofs.iter().cloned() {
        let nodes = p.nodes();

        let hashed_address = keccak256(p.address).to_vec();

        let mut node_value = match nodes.last() {
            Some(TrieNode::Leaf(leaf)) => leaf.value.clone(),
            _ => {
                continue;
            }
        };
        for v in &mut node_value {
            *v = v.wrapping_add(1);
        }
        keys.push(hashed_address.clone());
        values.push(node_value);
    }

    let sparse_store = SparseTrieStore::default();
    for proof in proofs.iter() {
        sparse_store.add_sparse_nodes_from_proof(proof.nodes());
    }
    let mut trie = SparseMPT::with_sparse_store(sparse_store);

    c.bench_function("update all accounts sparse trie", |b| {
        b.iter(|| {
            trie.clear_changed_nodes();
            for (key, value) in keys.iter().zip(values.iter()) {
                trie.insert(key, value).expect("must insert")
            }
        })
    });
}

criterion_group!(benches, sparse_trie_update, proof_insert, trie_insert);
criterion_main!(benches);
