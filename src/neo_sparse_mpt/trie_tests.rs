use crate::utils::reference_trie_hash;
use ahash::HashSet;
use alloy_primitives::hex;
use proptest::prelude::any;
use proptest::proptest;

use super::*;

fn compare_impls_with_hashing(data: &[(Vec<u8>, Vec<u8>)], insert_hashing: bool) {
    let expected = reference_trie_hash(data);
    let mut trie = SparseTrieNodes::empty_trie();
    for (key, value) in data {
        trie.insert(key.clone().into(), value.clone().into())
            .expect("can't insert");
        if insert_hashing {
            trie.hash_seq().expect("must hash after insert");
        }
    }
    let got = trie.hash_seq().expect("hashing failed");
    assert_eq!(
        got, expected,
        "comparing hashing, insert_hashing: {}",
        insert_hashing
    );
}

fn compare_impls(data: &[(Vec<u8>, Vec<u8>)]) {
    compare_impls_with_hashing(data, false);
    compare_impls_with_hashing(data, true);
}

#[test]
fn empty_trie() {
    compare_impls(&[])
}

#[test]
fn one_element_trie() {
    let data = [(hex!("11").to_vec(), hex!("aa").to_vec())];
    compare_impls(&data)
}

#[test]
fn update_leaf_node() {
    let data = &[(vec![1], vec![2]), (vec![1], vec![3])];
    compare_impls(data);
}

#[test]
fn insert_into_leaf_node_no_extension() {
    let data = &[(vec![0x11], vec![0x0a]), (vec![0x22], vec![0x0b])];
    compare_impls(data);

    let data = &[(vec![0x22], vec![0x0b]), (vec![0x11], vec![0x0a])];
    compare_impls(data);
}
#[test]
fn insert_into_leaf_node_with_extension() {
    let data = &[
        (vec![0x33, 0x22], vec![0x0a]),
        (vec![0x33, 0x11], vec![0x0b]),
    ];
    compare_impls(data);
}

#[test]
fn insert_into_extension_node_no_extension_above() {
    let data = &[
        (vec![0x33, 0x22], vec![0x0a]),
        (vec![0x33, 0x11], vec![0x0b]),
        (vec![0x44, 0x33], vec![0x0c]),
    ];
    compare_impls(data);
}

#[test]
fn insert_into_extension_node_with_extension_above() {
    let data = &[
        (vec![0x33, 0x33, 0x22], vec![0x0a]),
        (vec![0x33, 0x33, 0x11], vec![0x0b]),
        (vec![0x33, 0x44, 0x33], vec![0x0c]),
    ];
    compare_impls(data);
}

#[test]
fn insert_into_extension_node_collapse_extension() {
    let data = &[
        (vec![0x33, 0x22, 0x44], vec![0x0a]),
        (vec![0x33, 0x11, 0x44], vec![0x0b]),
        (vec![0x34, 0x33, 0x44], vec![0x0c]),
    ];
    compare_impls(data);
}

#[test]
fn insert_into_extension_node_collapse_extension_no_ext_above() {
    let data = &[
        (vec![0x31, 0x11], vec![0x0a]),
        (vec![0x32, 0x22], vec![0x0b]),
        (vec![0x11, 0x33], vec![0x0c]),
    ];
    compare_impls(data);
}

#[test]
fn insert_into_branch_empty_child() {
    let data = &[
        (vec![0x11], vec![0x0a]),
        (vec![0x22], vec![0x0b]),
        (vec![0x33], vec![0x0c]),
    ];
    compare_impls(data);
}

#[test]
fn insert_into_branch_leaf_child() {
    let data = &[
        (vec![0x11], vec![0x0a]),
        (vec![0x22], vec![0x0b]),
        (vec![0x33], vec![0x0c]),
        (vec![0x33], vec![0x0d]),
    ];
    compare_impls(data);
}

fn compare_with_removals_with_hashing(
    data: &[(Vec<u8>, Vec<u8>)],
    remove: &[Vec<u8>],
    insert_hashing: bool,
) -> Result<(), SparseTrieError> {
    let removed_keys: HashSet<_> = remove.iter().cloned().collect();
    let filtered_data: Vec<_> = data
        .iter()
        .filter(|(k, _)| !removed_keys.contains(k))
        .cloned()
        .collect();

    let reference_hash = reference_trie_hash(&filtered_data);

    let mut trie = SparseTrieNodes::empty_trie();
    for (key, val) in data {
        trie.insert(key.clone().into(), val.clone().into())
            .expect("must insert");
        if insert_hashing {
            trie.hash_seq().expect("must hash after insert");
        }
    }

    for key in remove {
        trie.delete(key.clone().into())?;
        if insert_hashing {
            trie.hash_seq().expect("must hash after delete");
        }
    }

    let hash = trie.hash_seq().expect("must hash");
    assert_eq!(
        hash, reference_hash,
        "comparing hashing, insert_hashing: {}",
        insert_hashing
    );

    Ok(())
}

fn compare_with_removals(
    data: &[(Vec<u8>, Vec<u8>)],
    remove: &[Vec<u8>],
    print: bool,
) -> Result<(), SparseTrieError> {
    compare_with_removals_with_hashing(data, remove, false)?;
    // compare_with_removals_with_hashing(data, remove, true)?;
    Ok(())
}

#[test]
fn remove_empty_trie_err() {
    let add = &[];

    let remove = &[vec![0x12]];

    compare_with_removals(add, remove, true).unwrap_err();
}

#[test]
fn remove_leaf() {
    let add = &[(vec![0x11], vec![0x0a])];

    let remove = &[vec![0x11]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_leaf_key_error() {
    let add = &[(vec![0x11], vec![0x0a])];

    let remove = &[vec![0x12]];

    compare_with_removals(add, remove, true).unwrap_err();
}

#[test]
fn remove_extension_node_error() {
    let add = &[(vec![0x11, 0x1], vec![0x0a]), (vec![0x11, 0x2], vec![0x0b])];

    let remove = &[vec![0x12]];
}

// must panic
#[test]
#[should_panic]
fn remove_branch_err() {
    let add = &[
        (vec![0x01, 0x10], vec![0x0a]),
        (vec![0x01, 0x20], vec![0x0b]),
        (vec![0x01, 0x30], vec![0x0c]),
    ];

    let remove = &[vec![0x01]];

    compare_with_removals(add, remove, true).unwrap_or_default();
}

#[test]
fn remove_branch_leave_2_children() {
    let add = &[
        (vec![0x01], vec![0x0a]),
        (vec![0x02], vec![0x0b]),
        (vec![0x03], vec![0x0c]),
    ];

    let remove = &[vec![0x01]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_leaf_below_branch_above() {
    let add = &[
        (vec![0x11], vec![0x0a]),
        (vec![0x12], vec![0x0b]),
        (vec![0x23], vec![0x0b]),
        (vec![0x33], vec![0x0c]),
    ];

    let remove = &[vec![0x11]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_branch_below_branch_above() {
    let add = &[
        (vec![0x11, 0x00], vec![0x0a]),
        (vec![0x12, 0x10], vec![0x0b]),
        (vec![0x12, 0x20], vec![0x0b]),
        (vec![0x23, 0x00], vec![0x0b]),
        (vec![0x33, 0x00], vec![0x0c]),
    ];

    let remove = &[vec![0x11, 0x00]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_ext_below_branch_above() {
    let add = &[
        (vec![0x11, 0x00, 0x00], vec![0x0a]),
        (vec![0x12, 0x10, 0x20], vec![0x0b]),
        (vec![0x12, 0x10, 0x30], vec![0x0b]),
        (vec![0x23, 0x00, 0x00], vec![0x0b]),
        (vec![0x33, 0x00, 0x00], vec![0x0c]),
    ];

    let remove = &[vec![0x11, 0x00, 0x00]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_leaf_below_ext_above() {
    let add = &[(vec![0x11], vec![0x0a]), (vec![0x12], vec![0x0b])];

    let remove = &[vec![0x11]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_branch_below_ext_above() {
    let add = &[
        (vec![0x11, 0x00], vec![0x0a]),
        (vec![0x12, 0x10], vec![0x0b]),
        (vec![0x12, 0x20], vec![0x0b]),
    ];

    let remove = &[vec![0x11, 0x00]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_branch_below_null_above() {
    let add = &[
        (vec![0x10], vec![0xa]),
        (vec![0x23], vec![0xb]),
        (vec![0x24], vec![0xc]),
    ];

    let remove = &[vec![0x10]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_ext_below_null_above() {
    let add = &[
        (vec![0x10, 0x00], vec![0xa]),
        (vec![0x23, 0x01], vec![0xb]),
        (vec![0x23, 0x02], vec![0xb]),
    ];

    let remove = &[vec![0x10, 0x00]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_leaf_below_null_above() {
    let add = &[(vec![0x10, 0x00], vec![0xa]), (vec![0x23, 0x01], vec![0xb])];

    let remove = &[vec![0x10, 0x00]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn remove_branch_leave_1_children_ext_below_ext_above() {
    let add = &[
        (vec![0x11, 0x00], vec![0x0a]),
        (vec![0x12, 0x11], vec![0x0b]),
        (vec![0x12, 0x12], vec![0x0b]),
    ];

    let remove = &[vec![0x11, 0x00]];

    compare_with_removals(add, remove, true).unwrap();
}

#[test]
fn failing_test_1() {
    let add = &[
        (vec![0xea, 0xbc, 0x01], vec![0x0a]),
        (vec![0xea, 0xbc, 0x10], vec![0x0b]),
    ];

    let remove = &[vec![0xea, 0xbc, 0x10]];

    compare_with_removals(add, remove, true).unwrap();
}

proptest! {
    #[test]
    fn proptest_random_insert_any_values(key_values in any::<Vec<([u8; 3], Vec<u8>)>>()) {
        let data: Vec<_> = key_values.into_iter().map(|(k, v)| (k.to_vec(), v)).collect();
        compare_impls(&data);
    }


    #[test]
    fn proptest_random_insert_big_values(key_values in any::<Vec<([u8; 3], [u8; 64])>>()) {
        let data: Vec<_> = key_values.into_iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
        compare_impls(&data);
    }

    #[test]
    fn proptest_random_insert_small_values(key_values in any::<Vec<([u8; 3], [u8; 3])>>()) {
        let data: Vec<_> = key_values.into_iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
        compare_impls(&data);
    }

    #[test]
    fn proptest_random_insert_big_keys(key_values in any::<Vec<([u8; 32], Vec<u8>)>>()) {
        let data: Vec<_> = key_values.into_iter().map(|(k, v)| (k.to_vec(), v)).collect();
        compare_impls(&data);
    }


    #[test]
    fn proptest_random_insert_remove_any_values(key_values in any::<Vec<(([u8; 3], bool), Vec<u8>)>>()) {
        let mut keys_to_remove_set = HashSet::default();
        let mut keys_to_remove = Vec::new();
        let data: Vec<_> = key_values.into_iter().map(|((k, remove), v)| {
            if remove && !keys_to_remove_set.contains(&k) {
                keys_to_remove_set.insert(k.clone());
                keys_to_remove.push(k.to_vec());
            }
            (k.to_vec(), v)
        }).collect();
        compare_with_removals(&data, &keys_to_remove, false).unwrap()
    }
}

#[test]
fn print_trie_example_from_reth() {
    let keys = &[
        hex!("30af561000000000000000000000000000000000000000000000000000000000").to_vec(),
        hex!("30af569000000000000000000000000000000000000000000000000000000000").to_vec(),
        hex!("30af650000000000000000000000000000000000000000000000000000000000").to_vec(),
        hex!("30af6f0000000000000000000000000000000000000000000000000000000000").to_vec(),
        hex!("30af8f0000000000000000000000000000000000000000000000000000000000").to_vec(),
        hex!("3100000000000000000000000000000000000000000000000000000000000000").to_vec(),
    ];

    let mut trie = SparseTrieNodes::empty_trie();
    for (idx, key) in keys.iter().enumerate() {
        trie.insert(key.clone().into(), Bytes::copy_from_slice(&[idx as u8]))
            .expect("insertion failed");
    }
    // trie.print_trie();
}
