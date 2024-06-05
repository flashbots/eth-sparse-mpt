use crate::sparse_mpt::SparseMPT;
use crate::utils::{pretty_print_trie_nodes, StoredProof};
use ahash::HashMap;
use alloy_primitives::{address, keccak256};
use alloy_trie::nodes::TrieNode;

#[test]
fn print_proofs_trie_nodes() {
    let proofs = StoredProof::load_known_proofs();

    let mut branch_node_count = 0;
    let mut extension_node_count = 0;

    let mut branch_node_min_size = 1000;
    for (_idx, proof) in proofs.into_iter().enumerate() {
        let mut nodes = Vec::new();
        for node in proof.nodes() {
            match &node {
                TrieNode::Branch(b) => {
                    branch_node_min_size =
                        std::cmp::min(branch_node_min_size, b.state_mask.count_ones());
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
        // }

        if proof.address == address!("ce74b79c8eb1ae745d0d377fef3b13d0342a34d1") {
            pretty_print_trie_nodes(&nodes);
        }
    }
    dbg!(branch_node_min_size);
    dbg!(branch_node_count);
    dbg!(extension_node_count);
}

#[test]
fn test_modify_all_accounts() {
    let proofs = StoredProof::load_known_proofs();
    let mut trie = SparseMPT::new_empty();

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
                continue;
            }
        };
        for v in &mut node_value {
            *v = v.wrapping_add(1);
        }
        keys.push(hashed_address.clone());
        values.push(node_value);

        trie.add_sparse_nodes_from_proof(nodes);
    }

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
