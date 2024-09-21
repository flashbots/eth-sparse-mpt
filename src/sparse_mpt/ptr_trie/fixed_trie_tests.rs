use super::fixed_trie::*;

use crate::reth_sparse_trie::{change_set::ETHTrieChangeSet, trie_fetcher::MultiProof};
use std::fs::read_to_string;

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

#[test]
fn test_insert_and_gather_account_trie() {
    let account_proof = {
        let multiproof = get_test_mutliproofs();
        let mut account_proof: Vec<_> = multiproof
            .into_iter()
            .map(|mp| mp.account_subtree.into_iter().collect::<Vec<_>>())
            .flatten()
            .collect();
        account_proof.sort_by_key(|(p, _)| p.clone());
        account_proof.dedup_by_key(|(p, _)| p.clone());
        account_proof
    };

    let mut fixed_trie = FixedTrie::default();
    fixed_trie.add_nodes(&account_proof).expect("must add");
    assert_eq!(fixed_trie.nodes.len(), account_proof.len());
    assert_eq!(fixed_trie.nodes_inserted.len(), account_proof.len());

    fixed_trie.add_nodes(&account_proof).expect("must add 2");
    assert_eq!(fixed_trie.nodes.len(), account_proof.len());
    assert_eq!(fixed_trie.nodes_inserted.len(), account_proof.len());

    let change_set = get_change_set();
    let mut gather_result = fixed_trie
        .gather_subtrie(
            &change_set.account_trie_updates,
            &change_set.account_trie_deletes,
        )
        .expect("must gather");
    dbg!(gather_result.nodes.len());
    for key in change_set.account_trie_updates {
        gather_result.insert(key.clone(), key).expect("must insert");
    }
    let root_hash = gather_result.root_hash().expect("must hash");
    let root_hash_parallel = gather_result.root_hash_parallel().expect("must hash");
    assert_eq!(root_hash, root_hash_parallel);
}
