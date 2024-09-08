use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_trie::nodes::TrieNode;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use eth_sparse_mpt::neo_sparse_mpt::SparseTrieNodes;
use eth_sparse_mpt::sparse_mpt::{SparseMPT, SparseTrieStore};
use eth_sparse_mpt::utils::{KeccakHasher, StoredProof};

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

fn add_elements_only_neo_sparse_trie(keys: &[Bytes], values: &[Bytes]) {
    let mut trie = SparseTrieNodes::empty_trie();
    trie.reserve(keys.len());
    for (key, value) in keys.iter().zip(values.iter()) {
        trie.insert(key.clone(), value.clone())
            .expect("can't insert");
    }
}

fn add_elements_only_neo_sparse_trie_insert_and_hash(keys: &[Bytes], values: &[Bytes]) -> B256 {
    let mut trie = SparseTrieNodes::empty_trie();
    for (key, value) in keys.iter().zip(values.iter()) {
        trie.insert(key.clone(), value.clone())
            .expect("can't insert");
    }
    trie.hash_seq().expect("must hash")
}

fn neo_trie_insert_only(c: &mut Criterion) {
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for i in 0u64..3000 {
        let b: B256 = U256::from(i).into();
        let data = keccak256(b).to_vec();
        keys.push(data.clone());
        values.push(data.clone());
    }
    let input_keys = keys
        .iter()
        .map(|x| Bytes::from(x.as_slice().to_vec()))
        .collect::<Vec<_>>();
    let input_values = values
        .iter()
        .map(|x| Bytes::from(x.as_slice().to_vec()))
        .collect::<Vec<_>>();
    c.bench_function("neo trie 3000 elements insert only", |b| {
        b.iter(|| add_elements_only_neo_sparse_trie(&input_keys, &input_values))
    });
}

fn neo_trie_insert_and_hash(c: &mut Criterion) {
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for i in 0u64..3000 {
        let b: B256 = U256::from(i).into();
        let data = keccak256(b).to_vec();
        keys.push(data.clone());
        values.push(data.clone());
    }
    let input_keys = keys
        .iter()
        .map(|x| Bytes::from(x.as_slice().to_vec()))
        .collect::<Vec<_>>();
    let input_values = values
        .iter()
        .map(|x| Bytes::from(x.as_slice().to_vec()))
        .collect::<Vec<_>>();
    c.bench_function("neo trie 3000 elements insert and hash", |b| {
        b.iter(|| add_elements_only_neo_sparse_trie_insert_and_hash(&input_keys, &input_values))
    });
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
    todo!()
    // let mut sparse_trie_store = SparseTrieStore::new();
    // for proof in proofs {
    //     sparse_trie_store.add_sparse_nodes_from_proof(proof.clone());
    // }
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

fn hashing(c: &mut Criterion) {
    let size = 3000;
    let mut data = Vec::new();
    for _ in 0..size {
        data.push(B256::random());
    }

    let mut hash_cache = ahash::HashMap::default();

    c.bench_function(&format!("hashing_{}_elements", size), |b| {
        b.iter(|| {
            for d in data.iter() {
                let hash = keccak256(d);
                black_box(hash);
            }
        })
    });

    c.bench_function(&format!("hashing_{}_elements_with_cache", size), |b| {
        b.iter(|| {
            for d in data.iter() {
                let hash = hash_cache.entry(d).or_insert_with(|| keccak256(d));
                black_box(hash);
            }
        })
    });
}

fn cloning(c: &mut Criterion) {
    let size = 3000;
    let mut data = Vec::new();
    for _ in 0..size {
        data.push(vec![B256::random(); 16]);
    }

    c.bench_function(
        &format!("cloning_{}_branch_trie_size_elements", size),
        |b| {
            b.iter(|| {
                black_box(data.clone());
            })
        },
    );
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

    let sparse_store = SparseTrieStore::new_empty();
    for proof in proofs.iter() {
        // sparse_store.add_sparse_nodes_from_raw_proof(proof.nodes());
    }
    let mut trie = SparseMPT::with_sparse_store(sparse_store).unwrap();

    c.bench_function("update all accounts sparse trie", |b| {
        b.iter(|| {
            trie.clear_changed_nodes();
            for (key, value) in keys.iter().zip(values.iter()) {
                trie.insert(key, value).expect("must insert")
            }
        })
    });
}

criterion_group!(
    benches,
    // sparse_trie_update,
    // proof_insert,
    // trie_insert,
    // hashing,
    // cloning,
    neo_trie_insert_only,
    // neo_trie_insert_and_hash,
);
criterion_main!(benches);
