use std::borrow::BorrowMut;

use ahash::HashMap;
use alloy_primitives::keccak256;
use alloy_primitives::Bytes;
use alloy_primitives::B256;
use alloy_rlp::Decodable;
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
    #[error("Node decode error {0:?}")]
    NodeDecodeError(#[from] alloy_rlp::Error),
}

#[derive(Debug, Clone, Default)]
pub struct SparseTrieNodes {
    nodes: HashMap<Nibbles, SparseTrieNode>,
}

struct NodeCursor {
    path_left: Nibbles,
    current_node: Nibbles,
}

impl NodeCursor {
    fn new(key: Bytes) -> Self {
        let path_left = Nibbles::unpack(key);
        let current_node = Nibbles::with_capacity(path_left.len());
        Self {
            path_left,
            current_node,
        }
    }

    fn step_into_extension(&mut self, len: usize) {
        self.current_node
            .extend_from_slice_unchecked(&self.path_left[..len]);
        self.path_left.as_mut_vec_unchecked().drain(..len);
    }

    fn step_into_branch(&mut self) -> u8 {
        let nibble = strip_first_nibble_mut(&mut self.path_left);
        self.current_node.push_unchecked(nibble);
        nibble
    }
}

impl SparseTrieNodes {
    pub fn reserve(&mut self, n: usize) {
        self.nodes.reserve(n);
    }

    pub fn empty_trie() -> Self {
        Self {
            nodes: [(Nibbles::new(), SparseTrieNode::null_node())]
                .into_iter()
                .collect(),
        }
    }

    pub fn uninit_trie() -> Self {
        Self {
            nodes: HashMap::default(),
        }
    }

    pub fn add_nodes(
        &mut self,
        nodes: impl Iterator<Item = (Nibbles, Bytes)>,
    ) -> Result<(), SparseTrieError> {
        for (path, node) in nodes {
            if self.nodes.contains_key(&path) {
                continue;
            }
            let node = SparseTrieNode::decode(&mut node.as_ref())?;
            self.nodes.insert(path, node);
        }
        Ok(())
    }

    pub fn delete(&mut self, key: Bytes) -> Result<(), SparseTrieError> {
        let mut c = NodeCursor::new(key);

        let mut walk_path: Vec<(Nibbles, u8)> = Vec::new();

        loop {
            let node = self.try_get_node_mut(&c.current_node)?;

            match &mut node.kind {
                SparseTrieNodeKind::NullNode => {
                    return Err(SparseTrieError::KeyNotFound);
                }
                SparseTrieNodeKind::LeafNode(leaf) => {
                    if leaf.key == c.path_left {
                        walk_path.push((c.current_node, 0));
                        break;
                    } else {
                        return Err(SparseTrieError::KeyNotFound);
                    }
                }
                SparseTrieNodeKind::ExtensionNode(extension) => {
                    if !c.path_left.starts_with(&extension.key) {
                        return Err(SparseTrieError::KeyNotFound);
                    }
                    walk_path.push((c.current_node.clone(), 0));
                    c.step_into_extension(extension.key.len());

                    // pass deletion deeper
                    extension.child.rlp_pointer_dirty = true;
                    node.rlp_pointer_dirty = true;
                    continue;
                }
                SparseTrieNodeKind::BranchNode(branch) => {
                    let n = c
                        .path_left
                        .first()
                        .expect("trying to delete key from branch");
                    let branch_node_path = c.current_node.clone();

                    let n = c.step_into_branch();
                    if let Some(child) = &mut branch.children[n as usize] {
                        node.rlp_pointer_dirty = true;
                        child.rlp_pointer_dirty = true;

                        // check if we are removing from the branch with one child and we don't have a child
                        // its important to do it here so we don't modify the trie
                        let child_count = branch.child_count();
                        if child_count == 2 {
                            let other_child_idx = branch
                                .other_child(n as usize)
                                .expect("other child must exist");
                            let other_child_path =
                                BranchNode::child_path(&branch_node_path, other_child_idx as u8);
                            if !self.nodes.contains_key(&other_child_path) {
                                return Err(SparseTrieError::NodeNotFound(other_child_path));
                            }
                        }
                        walk_path.push((branch_node_path, n));
                        continue;
                    } else {
                        return Err(SparseTrieError::KeyNotFound);
                    }
                }
            }
        }

        // now we walk our path back

        #[derive(Debug)]
        enum NodeDeletionResult {
            NodeDeleted,
            NodeUpdated,
            BranchBelowRemovedWithOneChild {
                child_nibble: u8,
                child_path: Nibbles,
            },
        }

        let mut deletion_result = NodeDeletionResult::NodeDeleted;

        for (current_node, current_node_child) in walk_path.into_iter().rev() {
            match &mut deletion_result {
                NodeDeletionResult::NodeDeleted => {
                    let node = self
                        .try_get_node_mut(&current_node)
                        .expect("nodes must exist when walking back");
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
                            let child_count = branch.child_count();
                            match child_count {
                                0..=1 => {
                                    unreachable!("removing last child or removing from branch without children")
                                }
                                2 => {
                                    // removing one but last child, remove branch node and bubble the deletion up
                                    let other_child_index = branch
                                        .other_child(current_node_child as usize)
                                        .expect("other child must exist");
                                    let child_path = BranchNode::child_path(
                                        &current_node,
                                        other_child_index as u8,
                                    );
                                    deletion_result =
                                        NodeDeletionResult::BranchBelowRemovedWithOneChild {
                                            child_nibble: other_child_index as u8,
                                            child_path,
                                        };
                                    true
                                }
                                3.. => {
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
                    child_path,
                } => {
                    let child_below = self
                        .try_remove_node(&child_path)
                        .expect("orphaned child existance is checked when walking down");
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
                            ext_above
                                .key
                                .extend_from_slice_unchecked(ext_below.key.as_slice());
                            ext_above.child = ext_below.child;
                        }
                        (
                            SparseTrieNodeKind::ExtensionNode(ext_above),
                            SparseTrieNodeKind::BranchNode(branch),
                        ) => {
                            // we consume remove child nibble into extension node and reinsert branch into the trie
                            // but with a different path
                            ext_above.key.push(*child_nibble);
                            let new_child_path = ext_above.child_path(&current_node);
                            let new_child = SparseTrieNode {
                                kind: SparseTrieNodeKind::BranchNode(branch),
                                rlp_pointer: child_below.rlp_pointer,
                                rlp_pointer_dirty: child_below.rlp_pointer_dirty,
                            };
                            reinsert_nodes.push((new_child_path, new_child));
                        }
                        (
                            SparseTrieNodeKind::BranchNode(branch),
                            SparseTrieNodeKind::LeafNode(mut leaf_below),
                        ) => {
                            // merge missing nibble into the leaf
                            leaf_below
                                .key
                                .as_mut_vec_unchecked()
                                .insert(0, *child_nibble);
                            let new_child_path =
                                BranchNode::child_path(&current_node, current_node_child);
                            let new_child =
                                SparseTrieNode::new(SparseTrieNodeKind::LeafNode(leaf_below));
                            reinsert_nodes.push((new_child_path, new_child));
                        }
                        (
                            SparseTrieNodeKind::BranchNode(branch),
                            SparseTrieNodeKind::ExtensionNode(mut ext_below),
                        ) => {
                            // merge missing nibble into the extension
                            ext_below
                                .key
                                .as_mut_vec_unchecked()
                                .insert(0, *child_nibble);
                            let new_child_path =
                                BranchNode::child_path(&current_node, current_node_child);
                            let new_child =
                                SparseTrieNode::new(SparseTrieNodeKind::ExtensionNode(ext_below));
                            reinsert_nodes.push((new_child_path, new_child));
                        }
                        (
                            SparseTrieNodeKind::BranchNode(branch),
                            SparseTrieNodeKind::BranchNode(branch_below),
                        ) => {
                            let branch_path = child_path.clone();

                            // we leave branch in the trie but create extension node instead of the remove one child node
                            let new_ext_path =
                                BranchNode::child_path(&current_node, current_node_child);
                            let new_ext_node =
                                ExtensionNode::new(Nibbles::from_nibbles_unchecked(&[
                                    *child_nibble,
                                ]));
                            let below_branch_path = new_ext_node.child_path(&new_ext_path);
                            let new_ext_node = SparseTrieNode::new(
                                SparseTrieNodeKind::ExtensionNode(new_ext_node),
                            );

                            let branch_below_node = SparseTrieNode {
                                kind: SparseTrieNodeKind::BranchNode(branch_below),
                                rlp_pointer: child_below.rlp_pointer,
                                rlp_pointer_dirty: child_below.rlp_pointer_dirty,
                            };

                            reinsert_nodes.push((new_ext_path, new_ext_node));
                            reinsert_nodes.push((below_branch_path, branch_below_node));
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
                child_path: child_ptr,
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
                        let extension_node = SparseTrieNode::new_ext_node(path_to_branch.clone());
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

    pub fn insert(&mut self, key: Bytes, value: Bytes) -> Result<(), SparseTrieError> {
        let mut c = NodeCursor::new(key);

        let mut new_nodes: Vec<(Nibbles, SparseTrieNode)> = Vec::with_capacity(0);

        loop {
            let node = self.try_get_node_mut(&c.current_node)?;

            match &mut node.kind {
                SparseTrieNodeKind::NullNode => {
                    let new_node = SparseTrieNode::new_leaf_node(c.path_left, value);
                    *node = new_node;
                    break;
                }
                SparseTrieNodeKind::LeafNode(leaf) => {
                    if leaf.key == c.path_left {
                        // update leaf inplace
                        leaf.value = value;
                        node.rlp_pointer_dirty = true;
                        break;
                    }

                    let (pref, mut suff1, mut suff2) =
                        extract_prefix_and_suffix(&c.path_left, &leaf.key);
                    assert!(suff1.len() == suff2.len() && !suff1.is_empty());

                    let n1 = strip_first_nibble_mut(&mut suff1);
                    let n2 = strip_first_nibble_mut(&mut suff2);
                    let key1 = suff1;
                    let key2 = suff2;

                    let branch_node_path = concat_path(&c.current_node, pref.as_slice());
                    let path_to_leaf1 = BranchNode::child_path(&branch_node_path, n1);
                    let path_to_leaf2 = BranchNode::child_path(&branch_node_path, n2);
                    let branch_node = SparseTrieNode::new_branch_node(n1, n2);

                    let leaf1 = SparseTrieNode::new_leaf_node(key1, value);
                    let leaf2 = SparseTrieNode::new_leaf_node(key2, leaf.value.clone());

                    new_nodes.reserve(3);
                    new_nodes.push((path_to_leaf1, leaf1));
                    new_nodes.push((path_to_leaf2, leaf2));

                    // current node becomes either extension node pointing to a branch or branch node directly
                    let replace_current_node = if pref.is_empty() {
                        branch_node
                    } else {
                        new_nodes.push((branch_node_path, branch_node));
                        SparseTrieNode::new_ext_node(pref)
                    };

                    *node = replace_current_node;
                    break;
                }
                SparseTrieNodeKind::ExtensionNode(extension) => {
                    if c.path_left.starts_with(&extension.key) {
                        // pass insertion deeper
                        c.step_into_extension(extension.key.len());
                        extension.child.rlp_pointer_dirty = true;
                        node.rlp_pointer_dirty = true;
                        continue;
                    }

                    let (pref, mut suff1, mut suff2) =
                        extract_prefix_and_suffix(&c.path_left, &extension.key);
                    assert!(!suff2.is_empty());
                    assert!(
                        !suff1.is_empty(),
                        "in sec trie we don't insert value into branch nodes"
                    );

                    let n1 = strip_first_nibble_mut(&mut suff1);
                    let n2 = strip_first_nibble_mut(&mut suff2);
                    let key1 = suff1;
                    let key2 = suff2;

                    let branch_node_path = concat_path(&c.current_node, pref.as_slice());
                    let leaf_path = BranchNode::child_path(&branch_node_path, n1);
                    let leaf = SparseTrieNode::new_leaf_node(key1, value);
                    new_nodes.reserve(3);
                    new_nodes.push((leaf_path, leaf));
                    let other_branch_child_path = BranchNode::child_path(&branch_node_path, n2);

                    // banch will point to the current extension child directly or to new extension node
                    // that will point to child
                    if !key2.is_empty() {
                        let ext = SparseTrieNode::new_ext_node(key2);
                        new_nodes.push((other_branch_child_path, ext));
                    }

                    let branch_node = SparseTrieNode::new_branch_node(n1, n2);
                    // current node becomes either extension node pointing to a branch or branch node directly
                    let replace_current_node = if pref.is_empty() {
                        branch_node
                    } else {
                        new_nodes.push((branch_node_path, branch_node));
                        SparseTrieNode::new_ext_node(pref)
                    };

                    *node = replace_current_node;
                    break;
                }
                SparseTrieNodeKind::BranchNode(branch_node) => {
                    assert!(
                        !c.path_left.is_empty(),
                        "trying to insert value into a branch node (sec trie)"
                    );
                    node.rlp_pointer_dirty = true;

                    let nibble = c.step_into_branch();

                    if let Some(child) = &mut branch_node.children[nibble as usize] {
                        node.rlp_pointer_dirty = true;
                        child.rlp_pointer_dirty = true;
                        continue;
                    } else {
                        branch_node.children[nibble as usize] = Some(NodePointer::empty_pointer());
                        new_nodes.push((
                            c.current_node,
                            SparseTrieNode::new_leaf_node(c.path_left, value),
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
        // TODO: to do without recursion
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
                    let updated_child = if let Some(updated_child) = updates.get(&child_path) {
                        assert!(!updated_child.rlp_pointer_dirty);
                        updated_child.rlp_pointer.clone()
                    } else {
                        let child_in_trie = self.try_get_node(&child_path)?;
                        assert!(
                            !child_in_trie.rlp_pointer_dirty,
                            "update must happen or child should be not dirty"
                        );
                        child_in_trie.rlp_pointer.clone()
                    };
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
                    let child_path = BranchNode::child_path(&node_path, idx as u8);
                    self.update_rlp_pointers(child_path.clone(), updates)?;
                    let updated_child = if let Some(updated_child) = updates.get(&child_path) {
                        assert!(!updated_child.rlp_pointer_dirty);
                        updated_child.rlp_pointer.clone()
                    } else {
                        let child_in_trie = self.try_get_node(&child_path)?;
                        assert!(
                            !child_in_trie.rlp_pointer_dirty,
                            "update must happen or child should be not dirty"
                        );
                        child_in_trie.rlp_pointer.clone()
                    };
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

#[derive(Debug, Clone)]
pub struct MissingNodes {
    pub nodes: Vec<Nibbles>,
}

impl SparseTrieNodes {
    pub fn gather_subtrie(
        &self,
        changed_keys: &[Bytes],
        deleted_keys: &[Bytes],
    ) -> Result<Self, MissingNodes> {
        let mut missing_nodes = Vec::new();
        let mut result = SparseTrieNodes {
            nodes: HashMap::default(),
        };

        let iter = changed_keys
            .iter()
            .zip(std::iter::repeat(false))
            .chain(deleted_keys.iter().zip(std::iter::repeat(true)));

        for (changed_key, delete) in iter {
            let mut c = NodeCursor::new(changed_key.clone());
            loop {
                let node = match self.try_get_node(&c.current_node) {
                    Ok(node) => node,
                    Err(SparseTrieError::NodeNotFound(_)) => {
                        missing_nodes.push(Nibbles::unpack(&changed_key));
                        break;
                    }
                    _ => unreachable!(),
                };
                let just_inserted = if !result.nodes.contains_key(&c.current_node) {
                    result.nodes.insert(c.current_node.clone(), node.clone());
                    true
                } else {
                    false
                };
                let node = result
                    .nodes
                    .get_mut(&c.current_node)
                    .expect("we insert it above");
                match &mut node.kind {
                    SparseTrieNodeKind::NullNode => {
                        // this is empty trie, we have everything to return
                        return Ok(result);
                    }
                    SparseTrieNodeKind::LeafNode(_) => break,
                    SparseTrieNodeKind::ExtensionNode(extension) => {
                        if c.path_left.starts_with(&extension.key) {
                            // go deeper
                            c.step_into_extension(extension.key.len());
                            continue;
                        }
                        break;
                    }
                    SparseTrieNodeKind::BranchNode(branch) => {
                        if just_inserted {
                            branch.aux_bits = branch.children_bits();
                        }
                        let nibble = c.step_into_branch();
                        if branch.children[nibble as usize].is_some() {
                            if delete {
                                // here we check if we might delete all but one child from this branch
                                // and if so we add remaining child into the list of nodes that we need
                                branch.aux_bits &= !(1 << nibble);
                                if branch.aux_bits.count_ones() == 1 {
                                    let child_that_might_be_removed =
                                        branch.aux_bits.trailing_zeros();

                                    let path = {
                                        // this path points to current child that we stepped into so we change last nibble to get
                                        // path of the child that migth be removed
                                        let mut path = c.current_node.clone();
                                        path.as_mut_vec_unchecked()
                                            .last_mut()
                                            .map(|v| *v = child_that_might_be_removed as u8)
                                            .expect("can't be empty");
                                        path
                                    };
                                    if let Some(might_be_orphan) = self.nodes.get(&path).cloned() {
                                        result.nodes.insert(path, might_be_orphan);
                                    } else {
                                        missing_nodes.push(path)
                                    }
                                }
                            }
                            // go deeper
                            continue;
                        }
                        break;
                    }
                }
            }
        }

        if missing_nodes.is_empty() {
            Ok(result)
        } else {
            Err(MissingNodes {
                nodes: missing_nodes,
            })
        }
    }
}
