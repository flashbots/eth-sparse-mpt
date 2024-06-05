mod basic_tests;
mod sparse_tests;

use crate::utils::clone_trie_node;
use ahash::HashMap;
use alloy_primitives::bytes::BytesMut;
use alloy_primitives::{hex, keccak256, B256};
use alloy_rlp::Encodable;
use alloy_trie::nodes::{BranchNode, ExtensionNode, LeafNode, TrieNode, CHILD_INDEX_RANGE};
use alloy_trie::{Nibbles, TrieMask, EMPTY_ROOT_HASH};

type NodeRef = Vec<u8>;

#[derive(Debug, thiserror::Error)]
pub enum InsertionError {
    #[error("Unknown branch")]
    UnknownBranch,
}

#[derive(Debug, thiserror::Error)]
pub enum DeletionError {
    #[error("Key node found")]
    KeyNotFound,
}

#[derive(Debug)]
enum NodeDeletionResult {
    NodeDeleted,
    NodeUpdated(NodeRef),
    BranchBelowRemovedWithOneChild { nibble: u8, child: NodeRef },
}

#[derive(Debug)]
pub struct SparseMPT {
    sparse_original_root: Option<NodeRef>,
    sparse_nodes: HashMap<NodeRef, TrieNode>,

    current_root: Option<NodeRef>,
    new_nodes: HashMap<NodeRef, TrieNode>,
}

// returns common prefix, suffix for p1, suffix for p2
fn extract_prefix_and_suffix(p1: Nibbles, p2: Nibbles) -> (Nibbles, Nibbles, Nibbles) {
    let prefix_len = p1.common_prefix_length(&p2);
    let prefix = Nibbles::from_nibbles(&p1[..prefix_len]);
    let suffix1 = Nibbles::from_nibbles(&p1[prefix_len..]);
    let suffix2 = Nibbles::from_nibbles(&p2[prefix_len..]);

    (prefix, suffix1, suffix2)
}

fn branch_node_from_2_children(
    child1: NodeRef,
    nibble1: u8,
    child2: NodeRef,
    nibble2: u8,
) -> TrieNode {
    assert_ne!(nibble1, nibble2);
    let (first_nibble, first_child, second_nibble, second_child) = if nibble1 < nibble2 {
        (nibble1, child1, nibble2, child2)
    } else {
        (nibble2, child2, nibble1, child1)
    };

    let mut mask = TrieMask::default();
    mask.set_bit(first_nibble);
    mask.set_bit(second_nibble);

    TrieNode::Branch(BranchNode::new(vec![first_child, second_child], mask))
}

fn trie_mask_remove_bit(trie_mask: TrieMask, index: u8) -> TrieMask {
    let value = trie_mask.get();
    let new_value = value & !(1u16 << index);
    TrieMask::new(new_value)
}

// returns node reference and index into array where to insert new value (or update in-place)
fn branch_node_get_child_reference(branch: &BranchNode, child: u8) -> (Option<NodeRef>, usize) {
    let mut child_node_ref = None;
    let mut vec_idx: i32 = -1;
    for idx in CHILD_INDEX_RANGE {
        if branch.state_mask.is_bit_set(idx) {
            vec_idx += 1;
        }
        if idx == child {
            if branch.state_mask.is_bit_set(idx) {
                child_node_ref = Some(branch.stack[vec_idx as usize].clone());
            } else {
                vec_idx += 1;
            }
            break;
        }
    }
    (child_node_ref, vec_idx as usize)
}

impl SparseMPT {
    pub fn new_empty() -> Self {
        Self {
            sparse_original_root: None,
            sparse_nodes: HashMap::default(),
            current_root: None,
            new_nodes: HashMap::default(),
        }
    }

    pub fn clear_changed_nodes(&mut self) {
        self.new_nodes.clear();
        self.current_root = self.sparse_original_root.clone();
    }

    pub fn add_sparse_nodes_from_proof(&mut self, proof_path: Vec<TrieNode>) {
        for (idx, nodes) in proof_path.into_iter().enumerate() {
            let reference = self.add_new_sparse_node(nodes);
            if idx == 0 && self.sparse_original_root.is_none() {
                self.sparse_original_root = Some(reference);
                if self.current_root.is_none() {
                    self.current_root.clone_from(&self.sparse_original_root);
                }
            }
        }
    }

    fn get_node(&self, node: &NodeRef) -> TrieNode {
        if let Some(node) = self.new_nodes.get(node) {
            return clone_trie_node(node);
        }
        if let Some(node) = self.sparse_nodes.get(node) {
            return clone_trie_node(node);
        }
        panic!("NODE NOT FOUND; todo");
    }

    fn add_new_sparse_node(&mut self, node: TrieNode) -> NodeRef {
        let mut buff = Vec::new();
        let node_ref = node.rlp(&mut buff);
        self.sparse_nodes.insert(node_ref.clone(), node);
        node_ref
    }

    fn add_new_node(&mut self, node: TrieNode) -> NodeRef {
        let mut buff = Vec::new();
        let node_ref = node.rlp(&mut buff);
        self.new_nodes.insert(node_ref.clone(), node);
        node_ref
    }

    fn insert_node(&mut self, path: Nibbles, value: Vec<u8>, node: Option<&NodeRef>) -> NodeRef {
        let node = if let Some(node) = node {
            self.get_node(node)
        } else {
            // inserting into a null node
            let node = TrieNode::Leaf(LeafNode::new(path, value));
            return self.add_new_node(node);
        };

        return match node {
            TrieNode::Leaf(leaf) => {
                // just modify the leaf
                if leaf.key == path {
                    let mut new_leaf = leaf;
                    new_leaf.value = value;
                    return self.add_new_node(TrieNode::Leaf(new_leaf));
                }

                let (pref, suff1, suff2) = extract_prefix_and_suffix(path, leaf.key);
                assert!(suff1.len() == suff2.len() && !suff1.is_empty());

                let nibble1 = suff1[0];
                let nibble2 = suff2[0];

                // paths for new leaf nodes
                let suff1 = Nibbles::from_nibbles(&suff1[1..]);
                let suff2 = Nibbles::from_nibbles(&suff2[1..]);

                // create new leaf nodes
                let child_1 = self.add_new_node(TrieNode::Leaf(LeafNode::new(suff1, value)));
                let child_2 = self.add_new_node(TrieNode::Leaf(LeafNode::new(suff2, leaf.value)));

                // create branch node
                let branch = self.add_new_node(branch_node_from_2_children(
                    child_1, nibble1, child_2, nibble2,
                ));

                if pref.is_empty() {
                    branch
                } else {
                    // add extension node
                    self.add_new_node(TrieNode::Extension(ExtensionNode::new(pref, branch)))
                }
            }
            TrieNode::Extension(extension) => {
                if path.starts_with(&extension.key) {
                    // just pass insertion deeper
                    let remaining_path = Nibbles::from_nibbles(&path[extension.key.len()..]);
                    let modified_child =
                        self.insert_node(remaining_path, value, Some(&extension.child));
                    return self.add_new_node(TrieNode::Extension(ExtensionNode::new(
                        extension.key,
                        modified_child,
                    )));
                }

                // need to split
                let (pref, suff1, suff2) = extract_prefix_and_suffix(path, extension.key);
                assert!(!suff2.is_empty());
                assert!(
                    !suff1.is_empty(),
                    "in sec trie we don't insert value into branch nodes"
                );

                let nibble1 = suff1[0];
                let nibble2 = suff2[0];

                // paths for new nodes from branch
                let suff1 = Nibbles::from_nibbles(&suff1[1..]);
                let suff2 = Nibbles::from_nibbles(&suff2[1..]);

                // create new nodes
                let child_1 = self.add_new_node(TrieNode::Leaf(LeafNode::new(suff1, value)));

                let child2 = if suff2.is_empty() {
                    extension.child
                } else {
                    self.add_new_node(TrieNode::Extension(ExtensionNode::new(
                        suff2,
                        extension.child,
                    )))
                };

                // create branch node
                let branch = self.add_new_node(branch_node_from_2_children(
                    child_1, nibble1, child2, nibble2,
                ));

                if pref.is_empty() {
                    branch
                } else {
                    // add extension node
                    self.add_new_node(TrieNode::Extension(ExtensionNode::new(pref, branch)))
                }
            }
            TrieNode::Branch(branch) => {
                assert!(
                    !path.is_empty(),
                    "trying to insert value into a branch node (sec trie)"
                );
                let branch_nibble = path[0];
                let remaining_path = Nibbles::from_nibbles(&path[1..]);

                let (child_node_ref, vec_idx) =
                    branch_node_get_child_reference(&branch, branch_nibble);

                let modified_child =
                    self.insert_node(remaining_path, value, child_node_ref.as_ref());

                let mut new_stack = branch.stack;
                if branch.state_mask.is_bit_set(branch_nibble) {
                    new_stack[vec_idx] = modified_child;
                } else {
                    new_stack.insert(vec_idx, modified_child);
                }
                let mut new_mask = branch.state_mask;
                new_mask.set_bit(branch_nibble);
                self.add_new_node(TrieNode::Branch(BranchNode::new(new_stack, new_mask)))
            }
        };
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), InsertionError> {
        let path = Nibbles::unpack(key);
        let current_head_node = self.current_root.clone();

        self.current_root =
            Some(self.insert_node(path, value.to_vec(), current_head_node.as_ref()));
        Ok(())
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<(), DeletionError> {
        let path = Nibbles::unpack(key);
        let current_head_node = self.current_root.clone();

        match self.delete_node(path, current_head_node.as_ref())? {
            NodeDeletionResult::NodeUpdated(node) => self.current_root = Some(node),
            NodeDeletionResult::NodeDeleted => {
                self.current_root = None;
            }

            NodeDeletionResult::BranchBelowRemovedWithOneChild { nibble, child } => {
                let child_node = self.get_node(&child);
                let new_node = match child_node {
                    TrieNode::Branch(_) => {
                        // create extension node with the nibble and the child
                        let ext = TrieNode::Extension(ExtensionNode::new(
                            Nibbles::from_nibbles(&[nibble]),
                            child,
                        ));
                        self.add_new_node(ext)
                    }
                    TrieNode::Extension(ext_child) => {
                        let mut new_path = Nibbles::from_nibbles(&[nibble]);
                        new_path.extend_from_slice(&ext_child.key);
                        let ext =
                            TrieNode::Extension(ExtensionNode::new(new_path, ext_child.child));
                        self.add_new_node(ext)
                    }
                    TrieNode::Leaf(child_leaf) => {
                        let mut new_path = Nibbles::from_nibbles(&[nibble]);
                        new_path.extend_from_slice(&child_leaf.key);
                        let leaf = TrieNode::Leaf(LeafNode::new(new_path, child_leaf.value));
                        self.add_new_node(leaf)
                    }
                };
                self.current_root = Some(new_node);
            }
        }
        Ok(())
    }

    fn delete_node(
        &mut self,
        path: Nibbles,
        node: Option<&NodeRef>,
    ) -> Result<NodeDeletionResult, DeletionError> {
        let node = if let Some(node) = node {
            self.get_node(node)
        } else {
            // deleting from a null node
            return Err(DeletionError::KeyNotFound);
        };

        match node {
            TrieNode::Leaf(leaf) => {
                if leaf.key != path {
                    return Err(DeletionError::KeyNotFound);
                }
                Ok(NodeDeletionResult::NodeDeleted)
            }
            TrieNode::Extension(ext) => {
                if !path.starts_with(&ext.key) {
                    return Err(DeletionError::KeyNotFound);
                }

                let remaining_path = Nibbles::from_nibbles(&path[ext.key.len()..]);
                // pass deletion to a child
                match self.delete_node(remaining_path, Some(&ext.child))? {
                    NodeDeletionResult::NodeDeleted => {
                        // Only branch nodes can be children of the extension nodes
                        // to remove branch node in sec trie we must remove all of its children
                        // but when we remove the second last children and left with one branch node
                        // will trigger BranchBelowRemovedWithOneChild code path so this code path will never
                        // be reachable
                        unreachable!("Child of the extension node can't be deleted in sec trie")
                    }
                    NodeDeletionResult::NodeUpdated(new_child) => {
                        let updated_ext_node =
                            TrieNode::Extension(ExtensionNode::new(ext.key.clone(), new_child));
                        Ok(NodeDeletionResult::NodeUpdated(
                            self.add_new_node(updated_ext_node),
                        ))
                    }
                    NodeDeletionResult::BranchBelowRemovedWithOneChild { nibble, child } => {
                        let child_node = self.get_node(&child);
                        return match child_node {
                            TrieNode::Leaf(child_leaf) => {
                                // we just remove extension node and merge path into leaf
                                let mut new_leaf_path = ext.key.clone();
                                new_leaf_path.push(nibble);
                                new_leaf_path.extend_from_slice(&child_leaf.key);
                                let new_leaf =
                                    TrieNode::Leaf(LeafNode::new(new_leaf_path, child_leaf.value));
                                let new_node = self.add_new_node(new_leaf);
                                Ok(NodeDeletionResult::NodeUpdated(new_node))
                            }
                            TrieNode::Extension(child_ext) => {
                                // we merge two extension nodes together
                                let mut new_ext_path = ext.key.clone();
                                new_ext_path.push(nibble);
                                new_ext_path.extend_from_slice(&child_ext.key);

                                let new_ext = TrieNode::Extension(ExtensionNode::new(
                                    new_ext_path,
                                    child_ext.child,
                                ));
                                let new_node = self.add_new_node(new_ext);
                                Ok(NodeDeletionResult::NodeUpdated(new_node))
                            }
                            TrieNode::Branch(_) => {
                                // consume nibble of the removed branch into extension key and adopt the child
                                let mut new_ext_path = ext.key.clone();
                                new_ext_path.push(nibble);
                                let new_ext =
                                    TrieNode::Extension(ExtensionNode::new(new_ext_path, child));
                                let new_node = self.add_new_node(new_ext);
                                Ok(NodeDeletionResult::NodeUpdated(new_node))
                            }
                        };
                    }
                }
            }
            TrieNode::Branch(current_branch) => {
                if path.is_empty() {
                    return Err(DeletionError::KeyNotFound);
                }

                let removing_branch_nibble = path[0];
                let remaining_path = Nibbles::from_nibbles(&path[1..]);

                let (child_node_ref, vec_idx) =
                    branch_node_get_child_reference(&current_branch, removing_branch_nibble);

                // deleting from a null child
                let child_node_ref = child_node_ref.ok_or(DeletionError::KeyNotFound)?;

                match self.delete_node(remaining_path, Some(&child_node_ref))? {
                    NodeDeletionResult::NodeUpdated(modified_child) => {
                        let mut new_stack = current_branch.stack;
                        // we are sure that this child is in the branch
                        new_stack[vec_idx] = modified_child;
                        let updated_branch = self.add_new_node(TrieNode::Branch(BranchNode::new(
                            new_stack,
                            current_branch.state_mask,
                        )));
                        Ok(NodeDeletionResult::NodeUpdated(updated_branch))
                    }
                    NodeDeletionResult::NodeDeleted => {
                        // multiple cases
                        // 1. 0 children left  -> just remove itself
                        // 2. 2+ children left -> remove child and update node
                        // 3. 1 child left     -> remove itself but pass remaining child up to decide what to do with it

                        match current_branch.state_mask.count_ones() - 1 {
                            0 => Ok(NodeDeletionResult::NodeDeleted),
                            1 => {
                                let mut stack = current_branch.stack;
                                stack.remove(vec_idx);
                                assert_eq!(stack.len(), 1, "should have one child left");
                                let mut child_nibble = 0;
                                for idx in CHILD_INDEX_RANGE {
                                    if current_branch.state_mask.is_bit_set(idx)
                                        && idx != removing_branch_nibble
                                    {
                                        child_nibble = idx;
                                        break;
                                    }
                                }
                                let remaining_child = stack.pop().unwrap();
                                Ok(NodeDeletionResult::BranchBelowRemovedWithOneChild {
                                    nibble: child_nibble,
                                    child: remaining_child,
                                })
                            }
                            2.. => {
                                let mut new_stack = current_branch.stack;
                                new_stack.remove(vec_idx);
                                let new_mask = trie_mask_remove_bit(
                                    current_branch.state_mask,
                                    removing_branch_nibble,
                                );
                                let updated_branch = self.add_new_node(TrieNode::Branch(
                                    BranchNode::new(new_stack, new_mask),
                                ));
                                Ok(NodeDeletionResult::NodeUpdated(updated_branch))
                            }
                        }
                    }
                    NodeDeletionResult::BranchBelowRemovedWithOneChild { nibble, child } => {
                        let child_node = self.get_node(&child);
                        let new_child_node = match child_node {
                            TrieNode::Leaf(child_leaf) => {
                                // merge missing nibble into leaf path
                                let mut new_leaf_path = Nibbles::new();
                                new_leaf_path.push(nibble);
                                new_leaf_path.extend_from_slice(&child_leaf.key);
                                let new_leaf =
                                    TrieNode::Leaf(LeafNode::new(new_leaf_path, child_leaf.value));

                                self.add_new_node(new_leaf)
                            }
                            TrieNode::Extension(child_ext) => {
                                // merge missing nibble into ext path
                                let mut new_ext_path = Nibbles::new();
                                new_ext_path.push(nibble);
                                new_ext_path.extend_from_slice(&child_ext.key);
                                let new_ext = TrieNode::Extension(ExtensionNode::new(
                                    new_ext_path,
                                    child_ext.child,
                                ));

                                self.add_new_node(new_ext)
                            }
                            TrieNode::Branch(_) => {
                                // create a new extension node to replace removed branch node with 1 child
                                let mut ext_path = Nibbles::new();
                                ext_path.push(nibble);
                                let new_ext =
                                    TrieNode::Extension(ExtensionNode::new(ext_path, child));

                                self.add_new_node(new_ext)
                            }
                        };
                        let mut new_branch = current_branch;
                        new_branch.stack[vec_idx] = new_child_node;
                        let updated_branch = self.add_new_node(TrieNode::Branch(new_branch));
                        Ok(NodeDeletionResult::NodeUpdated(updated_branch))
                    }
                }
            }
        }
    }

    pub fn root_hash(&self) -> B256 {
        if let Some(root_node_ref) = &self.current_root {
            let mut bytes = BytesMut::new();
            self.new_nodes
                .get(root_node_ref)
                .expect("TODO use sparse nodes and so on")
                .encode(&mut bytes);
            keccak256(&bytes)
        } else {
            EMPTY_ROOT_HASH
        }
    }
}

impl SparseMPT {
    fn print_trie(&self) {
        if let Some(root) = &self.current_root {
            self.print_node(root, 0);
        } else {
            println!("Empty trie");
        }
    }

    fn print_node(&self, node: &NodeRef, ident: usize) {
        let node = self.get_node(node);
        let ident_str = " ".repeat(ident);
        match node {
            TrieNode::Leaf(leaf) => {
                let key = hex::encode(leaf.key.as_ref());
                let value = hex::encode(&leaf.value);
                println!("{}Leaf, path: {}, data:  {}", ident_str, key, value);
            }
            TrieNode::Extension(ext) => {
                let key = hex::encode(ext.key.as_ref());
                println!("{}Extension, path: {}", ident_str, key);
                println!("{}Extension child:", ident_str);
                self.print_node(&ext.child, ident + 2);
            }
            TrieNode::Branch(branch) => {
                println!("{}Branch", ident_str);
                let mut vec_idx = 0;
                for idx in CHILD_INDEX_RANGE {
                    if branch.state_mask.is_bit_set(idx) {
                        let child = &branch.stack[vec_idx];
                        println!("{}Child: {:x}", ident_str, idx);
                        self.print_node(child, ident + 2);
                        vec_idx += 1;
                    }
                }
            }
        }
    }
}
