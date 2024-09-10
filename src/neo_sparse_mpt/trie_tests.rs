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
            trie.root_hash().expect("must hash after insert");
        }
    }
    let got = trie.root_hash().expect("hashing failed");
    assert_eq!(
        got, expected,
        "comparing hashing, insert_hashing: {}",
        insert_hashing
    );
}

fn convert_input_to_bytes(input: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Bytes, Bytes)> {
    input
        .into_iter()
        .map(|(k, v)| (k.clone().into(), v.clone().into()))
        .collect()
}

fn compare_sparse_impl(data: &[(Vec<u8>, Vec<u8>)], insert_hashing: bool) {
    let expected = reference_trie_hash(data);

    let mut data = convert_input_to_bytes(data);

    let (last, data) = if let Some(last) = data.pop() {
        (vec![last], data)
    } else {
        (vec![], data)
    };

    let mut trie = SparseTrieNodes::empty_trie();
    for (key, value) in data {
        trie.insert(key, value).expect("can't insert");
        if insert_hashing {
            trie.root_hash().expect("must hash");
        }
    }
    trie.root_hash().expect("must hash");

    let changed_keys = last.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>();
    let mut gathered_trie = trie
        .gather_subtrie(&changed_keys, &[])
        .expect("gather must work");
    for (k, v) in last {
        gathered_trie
            .insert(k, v)
            .expect("can't insert into gathered trie");
    }
    let got = gathered_trie.root_hash().expect("can't hash gathered trie");
    assert_eq!(got, expected);
}

fn compare_impls(data: &[(Vec<u8>, Vec<u8>)]) {
    compare_impls_with_hashing(data, false);
    compare_impls_with_hashing(data, true);
    compare_sparse_impl(data, false);
    compare_sparse_impl(data, true);
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
            trie.root_hash().expect("must hash after insert");
        }
    }

    for key in remove {
        trie.delete(key.clone().into())?;
        if insert_hashing {
            trie.root_hash().expect("must hash after delete");
        }
    }

    let hash = trie.root_hash().expect("must hash");
    assert_eq!(
        hash, reference_hash,
        "comparing hashing, insert_hashing: {}",
        insert_hashing
    );

    Ok(())
}

fn compare_with_removals_sparse(
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

    let data = convert_input_to_bytes(data);

    let reference_hash = reference_trie_hash(&filtered_data);

    let mut trie = SparseTrieNodes::empty_trie();
    for (key, val) in data {
        trie.insert(key, val).expect("must insert");
        if insert_hashing {
            trie.root_hash().expect("must hash after insert");
        }
    }
    trie.root_hash().expect("must hash");

    let deleted_keys = remove
        .iter()
        .map(|r| Bytes::copy_from_slice(r))
        .collect::<Vec<_>>();
    let mut trie = trie
        .gather_subtrie(&[], &deleted_keys)
        .expect("failed to gather for removals");

    dbg!(&trie);

    for key in remove {
        let key = key.clone().into();
        println!("deleting: {:?}", key);
        trie.delete(key)?;
        if insert_hashing {
            trie.root_hash().expect("must hash after delete");
        }
    }

    dbg!(&trie);

    let hash = trie.root_hash().expect("must hash");
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
    compare_with_removals_with_hashing(data, remove, true)?;
    compare_with_removals_sparse(data, remove, false)?;
    compare_with_removals_sparse(data, remove, true)?;
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
fn remove_branch_err() {
    let add = &[
        (vec![0x01, 0x10], vec![0x0a]),
        (vec![0x01, 0x20], vec![0x0b]),
        (vec![0x01, 0x30], vec![0x0c]),
    ];

    let remove = &[vec![0x01]];

    assert!(matches!(
        compare_with_removals(add, remove, true).unwrap_err(),
        SparseTrieError::KeyNotFound
    ));
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

fn assert_corect_gather(
    add: &[(Vec<u8>, Vec<u8>)],
    changed: &[Vec<u8>],
    deleted: &[Vec<u8>],
    expected_node_nibbles: &[Vec<u8>],
) {
    let mut trie = SparseTrieNodes::empty_trie();
    for (key, value) in add {
        trie.insert(key.clone().into(), value.clone().into());
    }
    let changed_keys = changed
        .iter()
        .map(|c| Bytes::from(c.clone()))
        .collect::<Vec<_>>();
    let deleted_keys = deleted
        .iter()
        .map(|c| Bytes::from(c.clone()))
        .collect::<Vec<_>>();

    let result = trie
        .gather_subtrie(&changed_keys, &deleted_keys)
        .expect("should suceed");
    for expected_node in expected_node_nibbles {
        let path = Nibbles::from_nibbles_unchecked(expected_node);
        assert!(result.nodes.contains_key(&path), "key {:?}", path);
    }
}

#[test]
fn test_gather_subtrie_simple() {
    let add = &[
        (vec![0x10], vec![0xa]),
        (vec![0x23], vec![0xb]),
        (vec![0x34], vec![0xc]),
    ];

    let changed = &[vec![0x10]];
    let deleted = &[];

    let expected_nodes_nibbles = &[vec![], vec![0x01]];

    assert_corect_gather(add, changed, deleted, expected_nodes_nibbles);
}

#[test]
fn test_gather_subtrie_deletion() {
    let add = &[
        (vec![0x10], vec![0xa]),
        (vec![0x23], vec![0xb]),
        (vec![0x34], vec![0xc]),
    ];

    let changed = &[];
    let deleted = &[vec![0x23]];

    let expected_nodes_nibbles = &[vec![], vec![0x02]];

    assert_corect_gather(add, changed, deleted, expected_nodes_nibbles);
}

#[test]
fn test_gather_subtrie_deletion_need_neighbour() {
    let add = &[
        (vec![0x10], vec![0xa]),
        (vec![0x23], vec![0xb]),
        (vec![0x34], vec![0xc]),
    ];

    let changed = &[];
    let deleted = &[vec![0x23], vec![0x34]];

    let expected_nodes_nibbles = &[vec![], vec![0x01], vec![0x02], vec![0x03]];

    assert_corect_gather(add, changed, deleted, expected_nodes_nibbles);
}
