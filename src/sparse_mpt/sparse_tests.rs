use crate::sparse_mpt::{NodeNotFound, SparseMPT, SparseTrieError, SparseTrieStore};
use crate::utils::{pretty_print_trie_nodes, StoredProof};
use ahash::HashMap;
use alloy_primitives::{address, hex, keccak256};
use alloy_trie::nodes::TrieNode;
use alloy_trie::Nibbles;

#[test]
fn print_proofs_trie_nodes() {
    let proofs = StoredProof::load_known_proofs();

    let mut branch_node_count = 0;
    let mut extension_node_count = 0;
    let mut small_branch_nodes_count = 0;

    let mut branch_node_min_size = 1000;
    for (_idx, proof) in proofs.into_iter().enumerate() {
        let mut nodes = Vec::new();
        for node in proof.nodes() {
            match &node {
                TrieNode::Branch(b) => {
                    let branch_size = b.state_mask.count_ones();
                    branch_node_min_size = std::cmp::min(branch_node_min_size, branch_size);
                    if branch_size == 2 {
                        small_branch_nodes_count += 1;
                    }
                    branch_node_count += 1;
                }
                TrieNode::Extension(_) => {
                    extension_node_count += 1;
                }
                _ => {}
            }
            nodes.push(node);
        }
        // if idx == 1 {
        //     pretty_print_trie_nodes(&nodes);
        //     println!("Address: {:?}, trie_key: {:?}", proof.address, keccak256(proof.address));
        // }
        if proof.address == address!("ca65eed6554f94c0fe4d94334036fac741a876c2") {
            pretty_print_trie_nodes(&nodes);
        }
    }
    dbg!(branch_node_min_size);
    dbg!(small_branch_nodes_count);
    dbg!(branch_node_count);
    dbg!(extension_node_count);
}

#[test]
fn test_remove_when_node_is_missing() {
    let proofs = StoredProof::load_known_proofs();

    let sparse_store = SparseTrieStore::new_empty();
    for proof in proofs {
        sparse_store.add_sparse_nodes_from_proof(proof.nodes());
    }

    let mut trie = SparseMPT::with_sparse_store(sparse_store.clone()).unwrap();

    // path for address 0xca65eed6554f94c0fe4d94334036fac741a876c2 that has 2 branch node above it
    match trie
        .delete(&hex!(
            "c2ce74bf48ecfb02144d03994591dc1d2a137c11fd33e6d6a663403c9bf8b672"
        ))
        .unwrap_err()
    {
        SparseTrieError::NodeNotFound(NodeNotFound { node, path }) => {
            // this is info about missing branch
            assert_eq!(
                node,
                hex!("a094a16167027b1e8916726a98d0ec843febf8ec1de56591fcac376fe017affb0d")
            );
            assert_eq!(path, Nibbles::from_nibbles(hex!("0c020c0e07040b07")));
        }
        _ => {
            panic!("incorrect error")
        }
    }
}

#[test]
fn test_modify_all_accounts() {
    let proofs = StoredProof::load_known_proofs();

    let sparse_store = SparseTrieStore::new_empty();

    let mut rev_key = HashMap::default();

    let mut keys = Vec::new();
    let mut values = Vec::new();

    for p in proofs.iter().cloned() {
        let nodes = p.nodes();

        let hashed_address = keccak256(p.address).to_vec();
        rev_key.insert(hashed_address.clone(), p.address);

        let mut node_value = match nodes.last() {
            Some(TrieNode::Leaf(leaf)) => leaf.value.clone(),
            _ => {
                println!("Address is missing from the trie: {:?}", p.address);
                vec![0x1, 0x2, 0x3]
            }
        };
        for v in &mut node_value {
            *v = v.wrapping_add(1);
        }
        keys.push(hashed_address.clone());
        values.push(node_value);

        sparse_store.add_sparse_nodes_from_proof(nodes);
    }

    let mut trie = SparseMPT::with_sparse_store(sparse_store.clone()).unwrap();

    println!("Total keys: {}", keys.len());

    for (key, value) in keys.iter().zip(values.iter()) {
        println!(
            "Inserting value for address: {:?}",
            rev_key.get(key).unwrap()
        );
        match trie.insert(key, value) {
            Ok(_) => {}
            Err(_) => {
                panic!(
                    "Failed inserting node, address: {:?}",
                    rev_key.get(key).unwrap()
                );
            }
        }
    }

    trie.root_hash();
}
