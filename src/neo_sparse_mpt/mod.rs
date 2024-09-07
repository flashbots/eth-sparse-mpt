use std::borrow::BorrowMut;

use ahash::HashMap;
use std::collections::BTreeMap;
use alloy_primitives::keccak256;
use alloy_primitives::Bytes;
use alloy_primitives::B256;
use alloy_rlp::Encodable;
use alloy_trie::Nibbles;
use thiserror::Error;

mod sparse_trie_nodes;
mod utils;

use sparse_trie_nodes::*;
use utils::*;

#[cfg(test)]
mod trie_tests;

#[derive(Debug, Error)]
pub enum SparseTrieError {
    #[error("Key node found when deleting")]
    KeyNotFound,
    #[error("Node not found {0:?}")]
    NodeNotFound(Nibbles),
}

#[derive(Debug, Clone, Default)]
pub struct SparseTrieNodes {
    nodes: HashMap<Nibbles, SparseTrieNode>,
}

impl SparseTrieNodes {
    pub fn empty_trie() -> Self {
        Self {
            nodes: [(Nibbles::new(), SparseTrieNode::null_node())]
                .into_iter()
                .collect(),
        }
    }

    pub fn add_nodes(
        &mut self,
        nodes: impl Iterator<Item = (Nibbles, Bytes)>,
    ) -> Result<(), SparseTrieError> {
        //for (path, bytes) in nodes {}
        todo!()
    }

    pub fn delete(&mut self, key: Bytes) -> Result<(), SparseTrieError> {
        let mut path_left = Nibbles::unpack(key);
        let mut current_node = Nibbles::with_capacity(path_left.len());

        let mut walk_path: Vec<(Nibbles, u8)> = Vec::new();

        loop {
            let node = self.try_get_node_mut(&current_node)?;

            match &mut node.kind {
                SparseTrieNodeKind::NullNode => {
                    return Err(SparseTrieError::KeyNotFound);
                }
                SparseTrieNodeKind::LeafNode(leaf) => {
                    if leaf.key == path_left {
                        walk_path.push((current_node.clone(), 0));
                        break;
                    } else {
                        return Err(SparseTrieError::KeyNotFound);
                    }
                }
                SparseTrieNodeKind::ExtensionNode(extension) => {
                    if !path_left.starts_with(&extension.key) {
                        return Err(SparseTrieError::KeyNotFound);
                    }
                    walk_path.push((current_node.clone(), 0));
                    path_left = Nibbles::from_nibbles_unchecked(&path_left[extension.key.len()..]);

                    current_node = concat_path(&current_node, extension.key.as_slice());
                    // pass deletion deeper
                    extension.child.rlp_pointer_dirty = true;
                    node.rlp_pointer_dirty = true;
                    continue;
                }
                SparseTrieNodeKind::BranchNode(branch) => {
                    // TODO: check if we are removing from the branch with one child and we don't have a child
                    let (n, new_path_left) = strip_first_nibble(path_left.clone());
                    let child_path = concat_path(&current_node, &[n]);
                    if let Some(child) = &mut branch.children[n as usize] {
                        walk_path.push((current_node.clone(), n));
                        current_node = child_path;
                        path_left = new_path_left;
                        node.rlp_pointer_dirty = true;
                        child.rlp_pointer_dirty = true;
                        continue;
                    } else {
                        return Err(SparseTrieError::KeyNotFound);
                    }
                }
            }
        }

        #[derive(Debug)]
        enum NodeDeletionResult {
            NodeDeleted,
            NodeUpdated,
            BranchBelowRemovedWithOneChild {
                child_nibble: u8,
                child_ptr: Nibbles,
            },
        }

        let mut deletion_result = NodeDeletionResult::NodeDeleted;

        for (current_node, current_node_child) in walk_path.into_iter().rev() {
            match &mut deletion_result {
                NodeDeletionResult::NodeDeleted => {
                    let node = self.try_get_node_mut(&current_node)?;
                    let should_remove = match &mut node.kind {
                        SparseTrieNodeKind::NullNode => unreachable!(),
                        SparseTrieNodeKind::LeafNode(_) => {
                            deletion_result = NodeDeletionResult::NodeDeleted;
                            true
                        }
                        SparseTrieNodeKind::ExtensionNode(_) => {
                            // Only branch nodes can be children of the extension nodes
                            // to remove branch node in sec trie we must remove all of its children
                            // but when we remove the second last children and left with one branch node
                            // will trigger BranchBelowRemovedWithOneChild code path so this code path will never
                            // be reachable
                            unreachable!("Child of the extension node can't be deleted in sec trie")
                        }
                        SparseTrieNodeKind::BranchNode(branch) => {
                            let child_count =
                                branch.children.iter().filter(|c| c.is_some()).count();
                            match child_count - 1 {
                                0 => {
                                    // removing last child, should not be triggered
                                    unreachable!()
                                }
                                1 => {
                                    // removing one but last child, remove branch node and bubble the deletion up
                                    let (other_child_index, other_child) = branch
                                        .children
                                        .iter()
                                        .enumerate()
                                        .find(|(idx, c)| {
                                            c.is_some() && *idx != current_node_child as usize
                                        })
                                        .expect("other child must exist");
                                    let child_path =
                                        branch.child_path(&current_node, other_child_index as u8);
                                    deletion_result =
                                        NodeDeletionResult::BranchBelowRemovedWithOneChild {
                                            child_nibble: other_child_index as u8,
                                            child_ptr: child_path,
                                        };
                                    true
                                }
                                2.. => {
                                    branch.children[current_node_child as usize] = None;
                                    deletion_result = NodeDeletionResult::NodeUpdated;
                                    break;
                                }
                            }
                        }
                    };
                    if should_remove {
                        self.nodes
                            .remove(&current_node)
                            .expect("when deleting node it should be in the trie");
                    }
                }
                NodeDeletionResult::NodeUpdated => break,
                NodeDeletionResult::BranchBelowRemovedWithOneChild {
                    child_nibble,
                    child_ptr,
                } => {
                    let child_below = self.try_remove_node(&child_ptr)?;
                    // TODO: remove useless clone
                    let mut child_below_clone = child_below.clone();
                    let node_above = self.try_get_node_mut(&current_node)?;
                    let mut reinsert_nodes = Vec::with_capacity(2);
                    match (&mut node_above.kind, child_below.kind) {
                        (
                            SparseTrieNodeKind::ExtensionNode(ext_above),
                            SparseTrieNodeKind::LeafNode(leaf_below),
                        ) => {
                            // we just replace extension node by merging its path into leaf with child_nibble
			    let mut new_leaf_key = ext_above.key.clone();
                            new_leaf_key.push(*child_nibble);
			    new_leaf_key.extend_from_slice_unchecked(&leaf_below.key);

                            let mut new_leaf = leaf_below;
                            new_leaf.key = new_leaf_key;
                            node_above.kind = SparseTrieNodeKind::LeafNode(new_leaf);
                        }
                        (
                            SparseTrieNodeKind::ExtensionNode(ext_above),
                            SparseTrieNodeKind::ExtensionNode(ext_below),
                        ) => {
                            // we merge two extension nodes into current node with child_nibble
                            ext_above.key.push(*child_nibble);
                            ext_above.key = concat_path(&ext_above.key, ext_below.key.as_slice());
                            ext_above.child = ext_below.child;
                        }
                        (
                            SparseTrieNodeKind::ExtensionNode(ext_above),
                            SparseTrieNodeKind::BranchNode(_),
                        ) => {
                            // we consume remove child nibble into extension node and reinsert branch into the trie
                            // but with a different path
                            ext_above.key.push(*child_nibble);
                            let new_child_path = ext_above.child_path(&current_node);
                            ext_above.child.path = Some(new_child_path.clone());
                            reinsert_nodes.push((new_child_path, child_below_clone));
                        }
                        (
                            SparseTrieNodeKind::BranchNode(branch),
                            SparseTrieNodeKind::LeafNode(mut leaf_below),
                        ) => {
                            node_above.rlp_pointer_dirty = true;
                            branch.children[current_node_child as usize]
                                .as_mut()
                                .map(|c| c.rlp_pointer_dirty = true);

                            // merge missing nibble into the leaf
                            let mut new_leaf_key = Nibbles::new();
                            new_leaf_key.push(*child_nibble);
                            new_leaf_key.extend_from_slice(&leaf_below.key);
                            leaf_below.key = new_leaf_key;
                            let new_child_path =
                                Nibbles::from_nibbles_unchecked(&child_ptr[..child_ptr.len() - 1]);
                            child_below_clone.kind = SparseTrieNodeKind::LeafNode(leaf_below);
                            reinsert_nodes.push((new_child_path, child_below_clone));
                        }
                        (
                            SparseTrieNodeKind::BranchNode(branch),
                            SparseTrieNodeKind::ExtensionNode(mut ext_below),
                        ) => {
                            node_above.rlp_pointer_dirty = true;
                            branch.children[current_node_child as usize]
                                .as_mut()
                                .map(|c| c.rlp_pointer_dirty = true);

                            // merge missing nibble into the extension
                            let mut new_ext_key = Nibbles::new();
                            new_ext_key.push(*child_nibble);
                            new_ext_key.extend_from_slice(&ext_below.key);
                            ext_below.key = new_ext_key;
                            let new_child_path =
                                Nibbles::from_nibbles_unchecked(&child_ptr[..child_ptr.len() - 1]);
                            child_below_clone.kind = SparseTrieNodeKind::ExtensionNode(ext_below);
                            reinsert_nodes.push((new_child_path, child_below_clone));
                        }
                        (
                            SparseTrieNodeKind::BranchNode(branch),
                            SparseTrieNodeKind::BranchNode(_),
                        ) => {
                            node_above.rlp_pointer_dirty = true;
                            branch.children[current_node_child as usize]
                                .as_mut()
                                .map(|c| c.rlp_pointer_dirty = true);

                            let branch_path = child_ptr.clone();

                            // we leave branch in the trie but create extension node instead of the remove one child node
                            let new_ext_path = branch.child_path(&current_node, current_node_child);
                            let new_ext_node = SparseTrieNode::new_ext_node(
                                Nibbles::from_nibbles_unchecked(&[*child_nibble]),
                                branch_path.clone(),
                            );
                            reinsert_nodes.push((new_ext_path, new_ext_node));
                            reinsert_nodes.push((branch_path, child_below_clone));
                        }
                        _ => unreachable!(),
                    }

                    for (path, node) in reinsert_nodes {
                        self.nodes.insert(path, node);
                    }

                    deletion_result = NodeDeletionResult::NodeUpdated;
                }
            }
        }

        // here we handle the case on top of the trie
        match deletion_result {
            NodeDeletionResult::NodeDeleted => {
                // trie is emptry, insert the null node on top
                self.nodes
                    .insert(Nibbles::new(), SparseTrieNode::null_node());
            }
            NodeDeletionResult::BranchBelowRemovedWithOneChild {
                child_nibble,
                child_ptr,
            } => {
                let child_below = self.try_remove_node(&child_ptr)?;
                let new_top_node = match child_below.kind {
                    SparseTrieNodeKind::LeafNode(mut leaf) => {
                        // merge nibble into the leaf
                        let mut new_key = Nibbles::from_nibbles(&[child_nibble]);
                        new_key.extend_from_slice(&leaf.key);
                        leaf.key = new_key;
                        SparseTrieNode {
                            kind: SparseTrieNodeKind::LeafNode(leaf),
                            rlp_pointer: Bytes::new(),
                            rlp_pointer_dirty: true,
                        }
                    }
                    SparseTrieNodeKind::ExtensionNode(mut ext) => {
                        let mut new_key = Nibbles::from_nibbles(&[child_nibble]);
                        new_key.extend_from_slice(&ext.key);
                        ext.key = new_key;
                        SparseTrieNode {
                            kind: SparseTrieNodeKind::ExtensionNode(ext),
                            rlp_pointer: Bytes::new(),
                            rlp_pointer_dirty: true,
                        }
                    }
                    SparseTrieNodeKind::BranchNode(branch) => {
                        // create extension node with the nibble and the child
                        let path_to_branch = Nibbles::from_nibbles_unchecked(&[child_nibble]);
                        self.nodes.insert(
                            path_to_branch.clone(),
                            SparseTrieNode {
                                kind: SparseTrieNodeKind::BranchNode(branch),
                                rlp_pointer: child_below.rlp_pointer,
                                rlp_pointer_dirty: child_below.rlp_pointer_dirty,
                            },
                        );
                        let extension_node = SparseTrieNode::new_ext_node(
                            path_to_branch.clone(),
                            path_to_branch.clone(),
                        );
                        extension_node
                    }
                    SparseTrieNodeKind::NullNode => unreachable!(),
                };
		self.nodes.insert(Nibbles::new(), new_top_node);
            }
            NodeDeletionResult::NodeUpdated => {}
        }

        Ok(())
    }

    pub fn insert_or_update(&mut self, key: Bytes, value: Bytes) -> Result<(), SparseTrieError> {
        let mut path_left = Nibbles::unpack(key);
        let mut current_node = Nibbles::with_capacity(path_left.len());
        let mut new_nodes: Vec<(Nibbles, SparseTrieNode)> = Vec::with_capacity(0);

        loop {
            let node = self.try_get_node_mut(&current_node)?;

            match &mut node.kind {
                SparseTrieNodeKind::NullNode => {
                    let new_node = SparseTrieNode::new_leaf_node(path_left, value);
                    *node = new_node;
                    break;
                }
                SparseTrieNodeKind::LeafNode(leaf) => {
                    if leaf.key == path_left {
                        // update leaf inplace
                        leaf.value = value;
                        break;
                    }

                    let (pref, suff1, suff2) = extract_prefix_and_suffix(&path_left, &leaf.key);
                    assert!(suff1.len() == suff2.len() && !suff1.is_empty());

                    let (n1, key1) = strip_first_nibble(suff1);
                    let (n2, key2) = strip_first_nibble(suff2);

                    let branch_node_path = concat_path(&current_node, pref.as_slice());
                    let path_to_leaf1 = concat_path(&branch_node_path, &[n1]);
                    let path_to_leaf2 = concat_path(&branch_node_path, &[n2]);
                    let branch_node = SparseTrieNode::new_branch_node(
                        n1,
                        path_to_leaf1.clone(),
                        n2,
                        path_to_leaf2.clone(),
                    );

                    let leaf1 = SparseTrieNode::new_leaf_node(key1, value);
                    let leaf2 = SparseTrieNode::new_leaf_node(key2, leaf.value.clone());
                    new_nodes.push((path_to_leaf1, leaf1));
                    new_nodes.push((path_to_leaf2, leaf2));

                    // current node becomes either extension node pointing to a branch or branch node directly
                    let replace_current_node = if pref.is_empty() {
                        branch_node
                    } else {
                        new_nodes.push((branch_node_path.clone(), branch_node));
                        SparseTrieNode::new_ext_node(pref, branch_node_path)
                    };

                    *node = replace_current_node;
                    break;
                }
                SparseTrieNodeKind::ExtensionNode(extension) => {
                    if path_left.starts_with(&extension.key) {
                        path_left =
                            Nibbles::from_nibbles_unchecked(&path_left[extension.key.len()..]);
                        current_node = concat_path(&current_node, extension.key.as_slice());
                        // pass insertion deeper
                        extension.child.rlp_pointer_dirty = true;
                        node.rlp_pointer_dirty = true;
                        continue;
                    }

                    let (pref, suff1, suff2) =
                        extract_prefix_and_suffix(&path_left, &extension.key);
                    assert!(!suff2.is_empty());
                    assert!(
                        !suff1.is_empty(),
                        "in sec trie we don't insert value into branch nodes"
                    );

                    let (n1, key1) = strip_first_nibble(suff1);
                    let (n2, key2) = strip_first_nibble(suff2);

                    let branch_node_path = concat_path(&current_node, pref.as_slice());
                    let leaf_path = concat_path(&branch_node_path, &[n1]);
                    let leaf = SparseTrieNode::new_leaf_node(key1, value);
                    new_nodes.push((leaf_path.clone(), leaf));
                    let other_branch_child_path = concat_path(&branch_node_path, &[n2]);

                    // banch will point to the current extension child directly or to new extension node
                    // that will point to child
                    if !key2.is_empty() {
                        let ext = SparseTrieNode::new_ext_node(key2, extension.key.clone());
                        new_nodes.push((other_branch_child_path.clone(), ext));
                    }

                    let branch_node =
                        SparseTrieNode::new_branch_node(n1, leaf_path, n2, other_branch_child_path);
                    // current node becomes either extension node pointing to a branch or branch node directly
                    let replace_current_node = if pref.is_empty() {
                        branch_node
                    } else {
                        new_nodes.push((branch_node_path.clone(), branch_node));
                        SparseTrieNode::new_ext_node(pref, branch_node_path)
                    };

                    *node = replace_current_node;
                    break;
                }
                SparseTrieNodeKind::BranchNode(branch_node) => {
                    assert!(
                        !path_left.is_empty(),
                        "trying to insert value into a branch node (sec trie)"
                    );
                    node.rlp_pointer_dirty = true;

                    let (n1, new_path_left) = strip_first_nibble(path_left.clone());

                    let child_path = concat_path(&current_node, &[n1]);
                    if let Some(child) = &mut branch_node.children[n1 as usize] {
                        if child.path.is_none() {
                            return Err(SparseTrieError::NodeNotFound(child_path));
                        }
                        current_node = child_path;
                        path_left = new_path_left;
                        node.rlp_pointer_dirty = true;
                        child.rlp_pointer_dirty = true;
                        continue;
                    } else {
                        branch_node.children[n1 as usize] =
                            Some(NodePointer::path_pointer(child_path.clone()));
                        new_nodes.push((
                            child_path,
                            SparseTrieNode::new_leaf_node(new_path_left, value),
                        ));
                        break;
                    }
                }
            }
        }

        for (path, node) in new_nodes {
            self.nodes.insert(path, node);
        }

        Ok(())
    }

    fn try_get_node_mut(&mut self, path: &Nibbles) -> Result<&mut SparseTrieNode, SparseTrieError> {
        self.nodes
            .get_mut(path)
            .ok_or_else(|| SparseTrieError::NodeNotFound(path.clone()))
    }

    fn try_get_node(&self, path: &Nibbles) -> Result<&SparseTrieNode, SparseTrieError> {
        self.nodes
            .get(path)
            .ok_or_else(|| SparseTrieError::NodeNotFound(path.clone()))
    }

    fn try_remove_node(&mut self, path: &Nibbles) -> Result<SparseTrieNode, SparseTrieError> {
        self.nodes
            .remove(path)
            .ok_or_else(|| SparseTrieError::NodeNotFound(path.clone()))
    }

    pub fn hash_seq(&mut self) -> Result<B256, SparseTrieError> {
        let mut updates = HashMap::default();
        let root_node = Nibbles::new();
        self.update_rlp_pointers(root_node.clone(), &mut updates)?;
        for (path, updated) in updates {
            self.nodes.insert(path, updated);
        }
        let root_node = self.try_get_node(&root_node)?;
        let mut tmp_result = Vec::new();
        root_node.encode(&mut tmp_result);
        Ok(keccak256(&tmp_result))
    }

    fn update_rlp_pointers(
        &self,
        node_path: Nibbles,
        updates: &mut HashMap<Nibbles, SparseTrieNode>,
    ) -> Result<(), SparseTrieError> {
        let node = self.try_get_node(&node_path)?;
        if !node.rlp_pointer_dirty {
            return Ok(());
        }

        let mut new_node = node.clone();

        match &mut new_node.kind {
            SparseTrieNodeKind::NullNode => new_node.rlp_pointer(),
            SparseTrieNodeKind::LeafNode(_) => new_node.rlp_pointer(),
            SparseTrieNodeKind::ExtensionNode(ext) => {
                if ext.child.rlp_pointer_dirty {
                    let child_path = ext.child_path(&node_path);
                    self.update_rlp_pointers(child_path.clone(), updates)?;
                    let updated_child = updates
                        .get(&child_path)
                        .expect("update must happen")
                        .rlp_pointer
                        .clone();
                    ext.child.rlp_pointer = updated_child;
                    ext.child.rlp_pointer_dirty = false;
                }
                new_node.rlp_pointer()
            }
            SparseTrieNodeKind::BranchNode(branch) => {
                let mut has_dirty_chilrden = false;
                for (idx, child) in branch.children.iter_mut().enumerate() {
                    let child = if let Some(child) = child {
                        child
                    } else {
                        continue;
                    };
                    if !child.rlp_pointer_dirty {
                        continue;
                    }
                    let child_path = child.path.clone().expect("TODO handle");
                    self.update_rlp_pointers(child_path.clone(), updates)?;
                    let updated_child = updates
                        .get(&child_path)
                        .expect("update must happen")
                        .rlp_pointer
                        .clone();
                    child.rlp_pointer = updated_child;
                    child.rlp_pointer_dirty = false;
                }
                new_node.rlp_pointer()
            }
        };
        new_node.rlp_pointer_dirty = false;
        updates.insert(node_path, new_node);
        Ok(())
    }
}

fn extract_prefix_and_suffix(p1: &Nibbles, p2: &Nibbles) -> (Nibbles, Nibbles, Nibbles) {
    let prefix_len = p1.common_prefix_length(p2);
    let prefix = Nibbles::from_nibbles(&p1[..prefix_len]);
    let suffix1 = Nibbles::from_nibbles(&p1[prefix_len..]);
    let suffix2 = Nibbles::from_nibbles(&p2[prefix_len..]);

    (prefix, suffix1, suffix2)
}
