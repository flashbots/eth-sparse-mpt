use crate::utils::{
    encode_branch_node, encode_extension, encode_leaf, encode_len_branch_node,
    encode_len_extension, encode_len_leaf, encode_null_node, rlp_pointer, HashMap,
};
use crate::utils::{extract_prefix_and_suffix, strip_first_nibble_mut};
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_trie::nodes::word_rlp;
use reth_trie::Nibbles;
use smallvec::SmallVec;
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod tests;

use super::fixed_trie::*;

#[derive(Debug, Clone)]
pub struct DiffTrieNode {
    pub kind: DiffTrieNodeKind,
    // None -> dirty
    pub rlp_pointer: Option<Bytes>,
}

impl DiffTrieNode {
    pub fn new_null() -> Self {
        Self {
            kind: DiffTrieNodeKind::Null,
            rlp_pointer: None,
        }
    }

    pub fn new_leaf(key: Nibbles, value: Bytes) -> Self {
        Self {
            kind: DiffTrieNodeKind::Leaf(DiffLeafNode {
                fixed: None,
                changed_key: Some(key),
                changed_value: Some(value),
            }),
            rlp_pointer: None,
        }
    }

    pub fn new_branch(n1: u8, ptr1: DiffChildPtr, n2: u8, ptr2: DiffChildPtr) -> Self {
        let mut changed_children = SmallVec::new();
        changed_children.push((n1, Some(ptr1)));
        changed_children.push((n2, Some(ptr2)));
        Self {
            kind: DiffTrieNodeKind::Branch(DiffBranchNode {
                fixed: None,
                changed_children,
                aux_bits: 0,
            }),
            rlp_pointer: None,
        }
    }

    pub fn new_ext(key: Nibbles, child: DiffChildPtr) -> Self {
        Self {
            kind: DiffTrieNodeKind::Extension(DiffExtensionNode {
                fixed: None,
                changed_key: Some(key),
                child,
            }),
            rlp_pointer: None,
        }
    }

    pub fn rlp_pointer_slow(&mut self) -> Bytes {
        if let Some(rlp_pointer) = &self.rlp_pointer {
            return rlp_pointer.clone();
        }

        let encode = self.rlp_encode();

        let rlp_pointer = if encode.len() < 32 {
            encode
        } else {
            word_rlp(&keccak256(&encode)).into()
        };
        self.rlp_pointer = Some(rlp_pointer.clone());
        rlp_pointer
    }

    pub fn rlp_encode(&self) -> Bytes {
        let out = match &self.kind {
            DiffTrieNodeKind::Leaf(leaf) => {
                let (key, value) = (leaf.key(), leaf.value());
                let len = encode_len_leaf(key, value);
                let mut out = Vec::with_capacity(len);
                encode_leaf(key, value, &mut out);
                out
            }
            DiffTrieNodeKind::Extension(ext) => {
                let (key, child_rlp) = (
                    ext.key(),
                    &ext.child
                        .rlp_pointer
                        .as_ref()
                        .expect("ext node rlp: child rlp must be computed"),
                );
                let len = encode_len_extension(key, child_rlp);
                let mut out = Vec::with_capacity(len);
                encode_extension(key, child_rlp, &mut out);
                out
            }
            DiffTrieNodeKind::Branch(branch) => {
                let mut child_rlp_pointers: [Option<&[u8]>; 16] = [None; 16];
                if let Some(fixed) = &branch.fixed {
                    for i in 0..16 {
                        if let Some(child) = &fixed.children[i] {
                            child_rlp_pointers[i] = Some(child.as_ref());
                        }
                    }
                }
                for (n, child) in &branch.changed_children {
                    let child = if let Some(child) = child {
                        child
                    } else {
                        child_rlp_pointers[*n as usize] = None;
                        continue;
                    };
                    child_rlp_pointers[*n as usize] = Some(
                        child
                            .rlp_pointer
                            .as_ref()
                            .map(|c| c.as_ref())
                            .expect("branch node rlp: child rlp must be computed"),
                    );
                }
                let len = encode_len_branch_node(&child_rlp_pointers);
                let mut out = Vec::with_capacity(len);
                encode_branch_node(&child_rlp_pointers, &mut out);
                out
            }
            DiffTrieNodeKind::Null => {
                let mut out = Vec::with_capacity(1);
                encode_null_node(&mut out);
                out
            }
        };
        Bytes::from(out)
    }
}

#[derive(Debug, Clone)]
pub enum DiffTrieNodeKind {
    Leaf(DiffLeafNode),
    Extension(DiffExtensionNode),
    Branch(DiffBranchNode),
    Null,
}

#[derive(Debug, Clone)]
pub struct DiffLeafNode {
    pub fixed: Option<Arc<FixedLeafNode>>,
    pub changed_key: Option<Nibbles>,
    pub changed_value: Option<Bytes>,
}

impl DiffLeafNode {
    pub fn key(&self) -> &Nibbles {
        if let Some(changed) = &self.changed_key {
            return changed;
        }
        self.fixed
            .as_ref()
            .map(|k| &k.key)
            .expect("leaf incorrect form")
    }

    pub fn key_mut(&mut self) -> &mut Nibbles {
        if self.changed_key.is_none() {
            let fixed_key = self
                .fixed
                .as_ref()
                .map(|k| k.key.clone())
                .expect("leaf incorrect form");
            self.changed_key = Some(fixed_key);
        }
        self.changed_key.as_mut().unwrap()
    }

    pub fn value(&self) -> &Bytes {
        if let Some(changed) = &self.changed_value {
            return changed;
        }
        self.fixed
            .as_ref()
            .map(|k| &k.value)
            .expect("leaf incorrect form")
    }
}

#[derive(Debug, Clone)]
pub struct DiffChildPtr {
    pub rlp_pointer: Option<Bytes>,
    pub ptr: Option<u64>,
}

impl DiffChildPtr {
    fn new(ptr: u64) -> Self {
        Self {
            rlp_pointer: None,
            ptr: Some(ptr),
        }
    }

    fn ptr(&self) -> u64 {
        self.ptr.unwrap_or(u64::MAX)
    }

    fn mark_dirty(&mut self) {
        self.rlp_pointer = None;
    }
}

#[derive(Debug, Clone)]
pub struct DiffBranchNode {
    pub fixed: Option<Arc<FixedBranchNode>>,
    /// this must have an element for children that we have in the diff trie
    pub changed_children: SmallVec<[(u8, Option<DiffChildPtr>); 4]>,
    pub aux_bits: u16,
}

impl DiffBranchNode {
    pub fn has_child(&self, nibble: u8) -> bool {
        if let Some((_, changed_child)) = self.changed_children.iter().find(|(n, _)| n == &nibble) {
            return changed_child.is_some();
        }
        if let Some(fixed) = &self.fixed {
            return fixed.children[nibble as usize].is_some();
        }
        false
    }

    pub fn get_diff_child_mut(&mut self, nibble: u8) -> Option<&mut DiffChildPtr> {
        self.changed_children
            .iter_mut()
            .find(|(n, _)| n == &nibble)
            .and_then(|(_, c)| c.as_mut())
    }
    pub fn get_diff_child(&self, nibble: u8) -> Option<&DiffChildPtr> {
        self.changed_children
            .iter()
            .find(|(n, _)| n == &nibble)
            .and_then(|(_, c)| c.as_ref())
    }

    pub fn insert_diff_child(&mut self, nibble: u8, ptr: DiffChildPtr) {
        if let Some((_, child)) = self.changed_children.iter_mut().find(|(n, _)| n == &nibble) {
            *child = Some(ptr);
            return;
        }
        self.changed_children.push((nibble, Some(ptr)));
    }

    pub fn child_count(&self) -> usize {
        // @perf
        let mut count = 0;
        for i in 0..16 {
            if self.has_child(i) {
                count += 1;
            }
        }
        count
    }

    fn other_child_ptr_and_nibble(&self, nibble: u8) -> Option<(u64, u8)> {
        for i in 0..16 {
            if i == nibble {
                continue;
            }
            if let Some(ptr) = self.get_diff_child(i) {
                return ptr.ptr.map(|p| (p, i));
            }
        }
        None
    }

    fn delete_child(&mut self, nibble: u8) {
        if let Some((_, child)) = self.changed_children.iter_mut().find(|(n, _)| n == &nibble) {
            *child = None;
            return;
        }
        self.changed_children.push((nibble, None));
    }
}

#[derive(Debug, Clone)]
pub struct DiffExtensionNode {
    pub fixed: Option<Arc<FixedExtensionNode>>,
    pub changed_key: Option<Nibbles>,
    pub child: DiffChildPtr,
}

impl DiffExtensionNode {
    pub fn key(&self) -> &Nibbles {
        if let Some(changed) = &self.changed_key {
            return changed;
        }
        self.fixed
            .as_ref()
            .map(|k| &k.key)
            .expect("ext incorrect form")
    }

    pub fn key_mut(&mut self) -> &mut Nibbles {
        if self.changed_key.is_none() {
            let fixed_key = self
                .fixed
                .as_ref()
                .map(|k| k.key.clone())
                .expect("ext incorrect form");
            self.changed_key = Some(fixed_key);
        }
        self.changed_key.as_mut().unwrap()
    }

    pub fn child_with_rlp(&self) -> DiffChildPtr {
        if self.child.rlp_pointer.is_none() && self.fixed.is_some() {
            return DiffChildPtr {
                rlp_pointer: Some(self.fixed.as_ref().map(|f| f.child.clone()).unwrap()),
                ptr: self.child.ptr,
            };
        }
        self.child.clone()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiffTrie {
    pub nodes: HashMap<u64, DiffTrieNode>,
    pub head: u64,
    pub ptrs: u64,
}

impl DiffTrie {
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn new_empty() -> Self {
        Self {
            nodes: [(0, DiffTrieNode::new_null())].into_iter().collect(),
            head: 0,
            ptrs: 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Node not found")]
pub struct ErrSparseNodeNotFound {
    ptr: u64,
    path: Nibbles,
}

#[derive(Debug, thiserror::Error)]
pub enum DeletionError {
    #[error("Deletion error: {0:?}")]
    NodeNotFound(#[from] ErrSparseNodeNotFound),
    #[error("Key node found in the trie")]
    KeyNotFound,
}

#[derive(Debug)]
pub struct NodeCursor {
    pub current_node: u64,
    pub current_path: Nibbles,
    pub path_left: Nibbles,
}

impl NodeCursor {
    pub fn new(key: Nibbles, head: u64) -> Self {
        let current_path = Nibbles::with_capacity(key.len());
        Self {
            current_node: head,
            current_path,
            path_left: key,
        }
    }

    pub fn step_into_extension(&mut self, ext: &DiffExtensionNode) {
        let len = ext.key().len();
        self.current_path
            .extend_from_slice_unchecked(&self.path_left[..len]);
        self.path_left.as_mut_vec_unchecked().drain(..len);
        self.current_node = ext.child.ptr();
    }

    pub fn next_nibble(&self) -> u8 {
        self.path_left.first().unwrap()
    }

    pub fn step_into_branch(&mut self, branch: &DiffBranchNode) -> u8 {
        let nibble = strip_first_nibble_mut(&mut self.path_left);
        self.current_path.push_unchecked(nibble);
        self.current_node = branch
            .get_diff_child(nibble)
            .map(|c| c.ptr())
            .unwrap_or(u64::MAX);
        nibble
    }
}

fn try_get_node_mut<'a>(
    nodes: &'a mut HashMap<u64, DiffTrieNode>,
    ptr: u64,
    path: &Nibbles,
) -> Result<&'a mut DiffTrieNode, ErrSparseNodeNotFound> {
    nodes.get_mut(&ptr).ok_or_else(|| ErrSparseNodeNotFound {
        path: path.clone(),
        ptr,
    })
}

pub fn get_new_ptr(ptrs: &mut u64) -> u64 {
    *ptrs += 1;
    *ptrs
}

impl DiffTrie {
    pub fn insert(&mut self, key: Bytes, value: Bytes) -> Result<(), ErrSparseNodeNotFound> {
        let key = Nibbles::unpack(key);
        let mut c = NodeCursor::new(key, self.head);

        let mut new_nodes: Vec<(u64, DiffTrieNode)> = Vec::with_capacity(0);

        loop {
            let node = try_get_node_mut(&mut self.nodes, c.current_node, &c.current_path)?;
            match &mut node.kind {
                DiffTrieNodeKind::Null => {
                    let new_node = DiffTrieNode::new_leaf(c.path_left, value);
                    *node = new_node;
                    break;
                }
                DiffTrieNodeKind::Leaf(leaf) => {
                    if leaf.key() == &c.path_left {
                        // update leaf inplace
                        leaf.changed_value = Some(value);
                        node.rlp_pointer = None;
                        break;
                    }

                    let (pref, mut suff1, mut suff2) =
                        extract_prefix_and_suffix(&c.path_left, leaf.key());
                    assert!(suff1.len() == suff2.len() && !suff1.is_empty(), "inserting into the leaf using different key lengths (key lengths must be constant)");

                    let n1 = strip_first_nibble_mut(&mut suff1);
                    let n2 = strip_first_nibble_mut(&mut suff2);
                    let (key1, key2) = (suff1, suff2);

                    let leaf1_ptr = get_new_ptr(&mut self.ptrs);
                    let leaf2_ptr = get_new_ptr(&mut self.ptrs);

                    new_nodes.reserve(3);
                    new_nodes.push((leaf1_ptr, DiffTrieNode::new_leaf(key1, value)));
                    new_nodes.push((
                        leaf2_ptr,
                        DiffTrieNode::new_leaf(key2, leaf.value().clone()),
                    ));

                    let branch = DiffTrieNode::new_branch(
                        n1,
                        DiffChildPtr::new(leaf1_ptr),
                        n2,
                        DiffChildPtr::new(leaf2_ptr),
                    );

                    let replace_current_node = if pref.is_empty() {
                        branch
                    } else {
                        let branch_ptr = get_new_ptr(&mut self.ptrs);
                        new_nodes.push((branch_ptr, branch));
                        DiffTrieNode::new_ext(pref, DiffChildPtr::new(branch_ptr))
                    };

                    *node = replace_current_node;
                    break;
                }
                DiffTrieNodeKind::Extension(extension) => {
                    if c.path_left.starts_with(extension.key()) {
                        // pass insertion deeper
                        extension.child.mark_dirty();
                        node.rlp_pointer = None;
                        c.step_into_extension(&extension);
                        continue;
                    }

                    let (pref, mut suff1, mut suff2) =
                        extract_prefix_and_suffix(&c.path_left, extension.key());
                    assert!(
                        !suff2.is_empty(),
                        "inserting into the extension node while we should go deeper"
                    );
                    assert!(
                        !suff1.is_empty(),
                        "trying to insert value into the branch node (key lengths must be constant)"
                    );

                    let n1 = strip_first_nibble_mut(&mut suff1);
                    let n2 = strip_first_nibble_mut(&mut suff2);
                    let (key1, key2) = (suff1, suff2);

                    let leaf_ptr = get_new_ptr(&mut self.ptrs);
                    new_nodes.reserve(3);
                    new_nodes.push((leaf_ptr, DiffTrieNode::new_leaf(key1, value)));

                    // banch will point to the current extension child directly or to new extension node
                    // that will point to child

                    let branch_other_child = if !key2.is_empty() {
                        let new_ext_ptr = get_new_ptr(&mut self.ptrs);
                        let new_ext = DiffTrieNode::new_ext(key2, extension.child_with_rlp());
                        new_nodes.push((new_ext_ptr, new_ext));
                        DiffChildPtr::new(new_ext_ptr)
                    } else {
                        extension.child_with_rlp()
                    };

                    let branch_node = DiffTrieNode::new_branch(
                        n1,
                        DiffChildPtr::new(leaf_ptr),
                        n2,
                        branch_other_child,
                    );

                    let replace_current_node = if pref.is_empty() {
                        branch_node
                    } else {
                        let branch_ptr = get_new_ptr(&mut self.ptrs);
                        new_nodes.push((branch_ptr, branch_node));
                        DiffTrieNode::new_ext(pref, DiffChildPtr::new(branch_ptr))
                    };

                    *node = replace_current_node;
                    break;
                }
                DiffTrieNodeKind::Branch(branch) => {
                    assert!(
                        !c.path_left.is_empty(),
                        "inserting value into a branch node (key lengths must be constant)"
                    );
                    node.rlp_pointer = None;
                    let n = c.step_into_branch(&branch);

                    if branch.has_child(n) {
                        let child =
                            branch
                                .get_diff_child_mut(n)
                                .ok_or_else(|| ErrSparseNodeNotFound {
                                    path: c.current_path.clone(),
                                    ptr: u64::MAX,
                                })?;
                        child.mark_dirty();
                        continue;
                    } else {
                        let leaf_ptr = get_new_ptr(&mut self.ptrs);
                        new_nodes.push((leaf_ptr, DiffTrieNode::new_leaf(c.path_left, value)));
                        branch.insert_diff_child(n, DiffChildPtr::new(leaf_ptr));
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

    pub fn delete(&mut self, key: Bytes) -> Result<(), DeletionError> {
        let key = Nibbles::unpack(key);
        let mut c = NodeCursor::new(key, self.head);

        let mut walk_path: Vec<(u64, u8)> = Vec::new();

        loop {
            let node = try_get_node_mut(&mut self.nodes, c.current_node, &c.current_path)
                .map_err(|e| DeletionError::NodeNotFound(e))?;

            match &mut node.kind {
                DiffTrieNodeKind::Null => {
                    return Err(DeletionError::KeyNotFound);
                }
                DiffTrieNodeKind::Leaf(leaf) => {
                    if leaf.key() == &c.path_left {
                        walk_path.push((c.current_node, 0));
                        break;
                    } else {
                        return Err(DeletionError::KeyNotFound);
                    }
                }
                DiffTrieNodeKind::Extension(extension) => {
                    if !c.path_left.starts_with(&extension.key()) {
                        return Err(DeletionError::KeyNotFound);
                    }
                    walk_path.push((c.current_node, 0));
                    c.step_into_extension(&extension);

                    // pass deletion deeper
                    extension.child.mark_dirty();
                    node.rlp_pointer = None;
                    continue;
                }
                DiffTrieNodeKind::Branch(branch) => {
                    if c.path_left.is_empty() {
                        // trying to delete key from branch
                        return Err(DeletionError::KeyNotFound);
                    }

                    let branch_node_path = c.current_node;
                    let n = c.step_into_branch(&branch);

                    walk_path.push((branch_node_path, n));

                    if !branch.has_child(n) {
                        return Err(DeletionError::KeyNotFound);
                    }

                    let child = branch.get_diff_child_mut(n).ok_or_else(|| {
                        DeletionError::NodeNotFound(ErrSparseNodeNotFound {
                            path: c.current_path.clone(),
                            ptr: u64::MAX,
                        })
                    })?;
                    child.mark_dirty();
                    node.rlp_pointer = None;

                    // check if we are removing from the branch with one child and we don't have a child
                    // its important to do it here so we don't modify the trie
                    // @note, this may be too strict as we only need to check that for branches on the bottorm of the trie
                    let child_count = branch.child_count();
                    if child_count == 2 {
                        // check that other child exist in the trie and return error if its not
                        // todo!()
                    }
                    continue;
                }
            }
        }

        // now we walk our path back

        #[derive(Debug)]
        enum NodeDeletionResult {
            NodeDeleted,
            NodeUpdated,
            BranchBelowRemovedWithOneChild { child_nibble: u8, child_ptr: u64 },
        }

        let mut deletion_result = NodeDeletionResult::NodeDeleted;

        for (current_node, current_node_child) in walk_path.into_iter().rev() {
            match &mut deletion_result {
                NodeDeletionResult::NodeDeleted => {
                    let node = try_get_node_mut(&mut self.nodes, current_node, &Nibbles::new())
                        .expect("nodes must exist when walking back");
                    let should_remove = match &mut node.kind {
                        DiffTrieNodeKind::Null => unreachable!(),
                        DiffTrieNodeKind::Leaf(_) => {
                            deletion_result = NodeDeletionResult::NodeDeleted;
                            true
                        }
                        DiffTrieNodeKind::Extension(_) => {
                            // Only branch nodes can be children of the extension nodes
                            // to remove branch node in sec trie we must remove all of its children
                            // but when we remove the second last children and left with one branch node
                            // will trigger BranchBelowRemovedWithOneChild code path so this code path will never
                            // be reachable
                            unreachable!("Child of the extension node can't be deleted in sec trie")
                        }
                        DiffTrieNodeKind::Branch(branch) => {
                            let child_count = branch.child_count();
                            match child_count {
                                0..=1 => {
                                    unreachable!("removing last child or removing from branch without children")
                                }
                                2 => {
                                    // removing one but last child, remove branch node and bubble the deletion up
                                    let (other_child_ptr, other_child_nibble) = branch
                                        .other_child_ptr_and_nibble(current_node_child)
                                        .expect("other child must exist");
                                    deletion_result =
                                        NodeDeletionResult::BranchBelowRemovedWithOneChild {
                                            child_nibble: other_child_nibble,
                                            child_ptr: other_child_ptr,
                                        };
                                    true
                                }
                                3.. => {
                                    branch.delete_child(current_node_child);
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
                    let child_below = self
                        .nodes
                        .remove(&child_ptr)
                        .expect("orphaned child existance is checked when walking down");
                    let node_above =
                        try_get_node_mut(&mut self.nodes, current_node, &Nibbles::new())
                            .expect("nodes must exist when walking back");
                    let mut reinsert_nodes: Vec<(u64, DiffTrieNode)> = Vec::with_capacity(2);
                    match (&mut node_above.kind, child_below.kind) {
                        (
                            DiffTrieNodeKind::Extension(ext_above),
                            DiffTrieNodeKind::Leaf(leaf_below),
                        ) => {
                            // we just replace extension node by merging its path into leaf with child_nibble
                            let mut new_leaf_key = ext_above.key().clone();
                            new_leaf_key.push(*child_nibble);
                            new_leaf_key.extend_from_slice_unchecked(leaf_below.key());

                            let mut new_leaf = leaf_below;
                            new_leaf.changed_key = Some(new_leaf_key);
                            node_above.kind = DiffTrieNodeKind::Leaf(new_leaf);
                        }
                        (
                            DiffTrieNodeKind::Extension(ext_above),
                            DiffTrieNodeKind::Extension(ext_below),
                        ) => {
                            // we merge two extension nodes into current node with child_nibble
                            let ext_key = ext_above.key_mut();
                            ext_key.push(*child_nibble);
                            ext_key.extend_from_slice_unchecked(ext_below.key());

                            ext_above.child = ext_below.child_with_rlp();
                        }
                        (
                            DiffTrieNodeKind::Extension(ext_above),
                            DiffTrieNodeKind::Branch(branch),
                        ) => {
                            // we consume remove child nibble into extension node and reinsert branch into the trie
                            // but with a different path
                            ext_above.key_mut().push(*child_nibble);

                            let new_branch_ptr = get_new_ptr(&mut self.ptrs);
                            ext_above.child = DiffChildPtr::new(new_branch_ptr);

                            let new_child = DiffTrieNode {
                                kind: DiffTrieNodeKind::Branch(branch),
                                rlp_pointer: child_below.rlp_pointer,
                            };
                            reinsert_nodes.push((new_branch_ptr, new_child));
                        }
                        (
                            DiffTrieNodeKind::Branch(branch_above),
                            DiffTrieNodeKind::Leaf(mut leaf_below),
                        ) => {
                            // merge missing nibble into the leaf
                            leaf_below
                                .key_mut()
                                .as_mut_vec_unchecked()
                                .insert(0, *child_nibble);

                            let new_leaf_ptr = get_new_ptr(&mut self.ptrs);
                            let new_child = DiffTrieNode {
                                kind: DiffTrieNodeKind::Leaf(leaf_below),
                                rlp_pointer: None,
                            };
                            reinsert_nodes.push((new_leaf_ptr, new_child));

                            branch_above.insert_diff_child(
                                current_node_child,
                                DiffChildPtr::new(new_leaf_ptr),
                            );
                        }
                        (
                            DiffTrieNodeKind::Branch(branch_above),
                            DiffTrieNodeKind::Extension(mut ext_below),
                        ) => {
                            // merge missing nibble into the extension
                            ext_below
                                .key_mut()
                                .as_mut_vec_unchecked()
                                .insert(0, *child_nibble);
                            let new_child_ptr = get_new_ptr(&mut self.ptrs);
                            let new_child = DiffTrieNode {
                                kind: DiffTrieNodeKind::Extension(ext_below),
                                rlp_pointer: None,
                            };
                            reinsert_nodes.push((new_child_ptr, new_child));

                            branch_above.insert_diff_child(
                                current_node_child,
                                DiffChildPtr::new(new_child_ptr),
                            );
                        }
                        (
                            DiffTrieNodeKind::Branch(branch_above),
                            DiffTrieNodeKind::Branch(branch_below),
                        ) => {
                            let reinsert_branch_ptr = get_new_ptr(&mut self.ptrs);
                            // we leave branch in the trie but create extension node instead of the remove one child node
                            let new_ext_ptr = get_new_ptr(&mut self.ptrs);
                            let new_ext_node = DiffTrieNode::new_ext(
                                Nibbles::from_nibbles_unchecked(&[*child_nibble]),
                                DiffChildPtr::new(reinsert_branch_ptr),
                            );
                            branch_above.insert_diff_child(
                                current_node_child,
                                DiffChildPtr::new(new_ext_ptr),
                            );

                            let reinsert_branch_node = DiffTrieNode {
                                kind: DiffTrieNodeKind::Branch(branch_below),
                                rlp_pointer: child_below.rlp_pointer,
                            };

                            reinsert_nodes.push((new_ext_ptr, new_ext_node));
                            reinsert_nodes.push((reinsert_branch_ptr, reinsert_branch_node));
                        }
                        _ => unreachable!(),
                    }

                    for (ptr, node) in reinsert_nodes {
                        self.nodes.insert(ptr, node);
                    }

                    deletion_result = NodeDeletionResult::NodeUpdated;
                }
            }
        }

        // here we handle the case on top of the trie
        match deletion_result {
            NodeDeletionResult::NodeDeleted => {
                let ptr = get_new_ptr(&mut self.ptrs);
                // trie is emptry, insert the null node on top
                self.nodes.insert(ptr, DiffTrieNode::new_null());
                self.head = ptr;
            }
            NodeDeletionResult::BranchBelowRemovedWithOneChild {
                child_nibble,
                child_ptr,
            } => {
                let mut reinsert_nodes = Vec::with_capacity(0);

                let mut child_below = self
                    .nodes
                    .remove(&child_ptr)
                    .expect("orphaned child existence verif");
                match &mut child_below.kind {
                    DiffTrieNodeKind::Leaf(leaf) => {
                        leaf.key_mut()
                            .as_mut_vec_unchecked()
                            .insert(0, child_nibble);
                        child_below.rlp_pointer = None;
                    }
                    DiffTrieNodeKind::Extension(ext) => {
                        ext.key_mut().as_mut_vec_unchecked().insert(0, child_nibble);
                        child_below.rlp_pointer = None;
                    }
                    DiffTrieNodeKind::Branch(_) => {
                        // create extension node with the nibble and the child
                        let reinsert_branch_ptr = get_new_ptr(&mut self.ptrs);
                        reinsert_nodes.push((reinsert_branch_ptr, child_below.clone()));
                        child_below.kind = DiffTrieNodeKind::Extension(DiffExtensionNode {
                            fixed: None,
                            changed_key: Some(Nibbles::from_nibbles_unchecked(&[child_nibble])),
                            child: DiffChildPtr::new(reinsert_branch_ptr),
                        });
                        child_below.rlp_pointer = None;
                    }
                    DiffTrieNodeKind::Null => unreachable!(),
                };
                let ptr = get_new_ptr(&mut self.ptrs);
                self.head = ptr;
                self.nodes.insert(ptr, child_below);
                for (ptr, node) in reinsert_nodes {
                    self.nodes.insert(ptr, node);
                }
            }
            NodeDeletionResult::NodeUpdated => {}
        }

        Ok(())
    }

    pub fn root_hash(&mut self) -> Result<B256, ErrSparseNodeNotFound> {
        struct WaitStack {
            node: u64,
            stack_before: usize,
            need_elements: usize,
        }

        let mut task_stack: Vec<u64> = vec![self.head];
        let mut wait_stack: Vec<WaitStack> = Vec::new();
        let mut result_stack: Vec<Bytes> = Vec::new();

        let empty_path = Nibbles::new();

        while let Some(current_node) = task_stack.pop() {
            let node = try_get_node_mut(&mut self.nodes, current_node, &empty_path)?;

            match &mut node.kind {
                DiffTrieNodeKind::Null | DiffTrieNodeKind::Leaf(_) => {
                    result_stack.push(node.rlp_pointer_slow());
                }
                DiffTrieNodeKind::Extension(extension) => {
                    if node.rlp_pointer.is_none() && extension.child.rlp_pointer.is_none() {
                        let child_node = extension.child.ptr();
                        wait_stack.push(WaitStack {
                            node: current_node,
                            stack_before: result_stack.len(),
                            need_elements: 1,
                        });
                        task_stack.push(child_node);
                    } else {
                        result_stack.push(node.rlp_pointer_slow());
                    }
                }
                DiffTrieNodeKind::Branch(branch_node) => {
                    if node.rlp_pointer.is_none() {
                        let mut need_elements = 0;
                        for (_, child) in &branch_node.changed_children {
                            if let Some(child) = child {
                                if child.rlp_pointer.is_none() {
                                    need_elements += 1;
                                    task_stack.push(child.ptr());
                                }
                            }
                        }

                        if need_elements == 0 {
                            result_stack.push(node.rlp_pointer_slow());
                        } else {
                            wait_stack.push(WaitStack {
                                node: current_node,
                                stack_before: result_stack.len(),
                                need_elements,
                            });
                        }
                    } else {
                        result_stack.push(node.rlp_pointer_slow());
                    }
                }
            }

            loop {
                let wait = if let Some(w) = wait_stack.last() {
                    if result_stack.len() < w.need_elements + w.stack_before {
                        break;
                    }
                    wait_stack.pop().unwrap()
                } else {
                    break;
                };
                let node = try_get_node_mut(&mut self.nodes, wait.node, &empty_path)?;
                let idx = result_stack.len() - wait.need_elements;
                update_node_with_calculated_dirty_children(node, result_stack.drain(idx..).rev());

                result_stack.push(node.rlp_pointer_slow());
            }
        }

        assert!(task_stack.is_empty());
        assert!(wait_stack.is_empty());
        assert_eq!(result_stack.len(), 1);

        let head = try_get_node_mut(&mut self.nodes, self.head, &empty_path)?;
        Ok(keccak256(&head.rlp_encode()))
    }

    fn root_hash_parallel_nodes(&self, node: u64) -> Bytes {
        let node = self.nodes.get(&node).expect("node not found");
        match &node.kind {
            DiffTrieNodeKind::Null | DiffTrieNodeKind::Leaf(_) => {
                return node.rlp_encode();
            }
            DiffTrieNodeKind::Extension(extension) => {
                if node.rlp_pointer.is_none() && extension.child.rlp_pointer.is_none() {
                    let extension = extension.clone();
                    let child_node = extension.child.ptr();
                    let child_bytes = rlp_pointer(self.root_hash_parallel_nodes(child_node));
                    let mut node = DiffTrieNode {
                        kind: DiffTrieNodeKind::Extension(extension),
                        rlp_pointer: None,
                    };
                    update_node_with_calculated_dirty_children(
                        &mut node,
                        std::iter::once(child_bytes),
                    );
                    return node.rlp_encode();
                }
                return node.rlp_encode();
            }
            DiffTrieNodeKind::Branch(branch_node) => {
                if node.rlp_pointer.is_none() {
                    let mut need_elements = Vec::new();
                    for (_, child) in &branch_node.changed_children {
                        if let Some(child) = child {
                            if child.rlp_pointer.is_none() {
                                need_elements.push(child.ptr());
                            }
                        }
                    }

                    if need_elements.len() == 0 {
                        return node.rlp_encode();
                    } else {
                        let branch = branch_node.clone();

                        let results = if need_elements.len() <= 3 {
                            let mut res = Vec::with_capacity(need_elements.len());
                            for child in need_elements.into_iter().rev() {
                                res.push(rlp_pointer(self.root_hash_parallel_nodes(child)));
                            }
                            res
                        } else {
                            let res = Arc::new(Mutex::new(Vec::new()));
                            rayon::scope(|scope| {
                                for (idx, child) in need_elements.iter().enumerate() {
                                    let res = res.clone();
                                    scope.spawn(move |_| {
                                        let data =
                                            rlp_pointer(self.root_hash_parallel_nodes(*child));
                                        res.lock().unwrap().push((idx, data));
                                    });
                                }
                            });
                            let mut results = res.lock().unwrap().clone();
                            results.sort_by_key(|(i, _)| *i);
                            let mut results: Vec<_> = results.into_iter().map(|(_, b)| b).collect();
                            results.reverse();
                            results
                        };

                        let mut node = DiffTrieNode {
                            kind: DiffTrieNodeKind::Branch(branch),
                            rlp_pointer: None,
                        };
                        update_node_with_calculated_dirty_children(&mut node, results.into_iter());
                        return node.rlp_encode();
                    }
                } else {
                    return node.rlp_encode();
                }
            }
        }
    }

    // @todo: change dirty status of the nodes
    pub fn root_hash_parallel(&mut self) -> Result<B256, ErrSparseNodeNotFound> {
        let encode = self.root_hash_parallel_nodes(self.head);
        Ok(keccak256(&encode))
    }
}

fn update_node_with_calculated_dirty_children(
    node: &mut DiffTrieNode,
    mut dirty_branches: impl Iterator<Item = Bytes>,
) {
    match &mut node.kind {
        DiffTrieNodeKind::Extension(ext) => {
            let child_ptr = dirty_branches.next().expect("must have ext child");
            ext.child.rlp_pointer = Some(child_ptr);
        }
        DiffTrieNodeKind::Branch(branch) => {
            for (_, child) in &mut branch.changed_children {
                if let Some(child) = child {
                    if child.rlp_pointer.is_none() {
                        child.rlp_pointer =
                            Some(dirty_branches.next().expect("must have branch child"));
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}
