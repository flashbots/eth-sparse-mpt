use crate::utils::hash_map_with_capacity;
use crate::utils::HashMap;
use crate::utils::HashSet;
use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use alloy_trie::nodes::{
    BranchNode as AlloyBranchNode, ExtensionNode as AlloyExtensionNode, LeafNode as AlloyLeafNode,
    TrieNode as AlloyTrieNode,
};
use arrayvec::ArrayVec;
use reth_trie::Nibbles;
use std::sync::Arc;

use crate::sparse_mpt::strip_first_nibble_mut;

use super::get_new_ptr;
use super::NodeCursor;
use super::{
    DiffBranchNode, DiffChildPtr, DiffExtensionNode, DiffLeafNode, DiffTrie, DiffTrieNode,
    DiffTrieNodeKind,
};

#[derive(Debug, Clone)]
pub enum FixedTrieNode {
    Leaf(Arc<FixedLeafNode>),
    Extension {
        node: Arc<FixedExtensionNode>,
        child_ptr: Option<u64>,
    },
    Branch {
        node: Arc<FixedBranchNode>,
        child_ptrs: Vec<(u8, u64)>,
    },
    Null,
}

impl FixedTrieNode {
    fn create_diff_node(&self) -> DiffTrieNode {
        let kind = match self {
            FixedTrieNode::Leaf(leaf) => DiffTrieNodeKind::Leaf(DiffLeafNode {
                fixed: Some(Arc::clone(leaf)),
                changed_key: None,
                changed_value: None,
            }),
            FixedTrieNode::Extension { node, .. } => {
                DiffTrieNodeKind::Extension(DiffExtensionNode {
                    fixed: Some(Arc::clone(node)),
                    changed_key: None,
                    child: DiffChildPtr {
                        rlp_pointer: Some(node.child.clone()),
                        ptr: None,
                    },
                })
            }
            FixedTrieNode::Branch { node, .. } => {
                DiffTrieNodeKind::Branch(DiffBranchNode {
                    fixed: Some(Arc::clone(node)),
                    // changed_children: Vec::with_capacity(aux_bits.count_ones() as usize),
                    // changed_children: ArrayVec::new(),
		    changed_children: Vec::new(),
                    aux_bits: node.child_mask,
                })
            }
            FixedTrieNode::Null => DiffTrieNodeKind::Null,
        };
        DiffTrieNode {
            kind,
            rlp_pointer: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixedLeafNode {
    pub key: Nibbles,
    pub value: Bytes,
}

impl From<AlloyLeafNode> for FixedLeafNode {
    fn from(alloy_leaf_node: AlloyLeafNode) -> Self {
        Self {
            key: alloy_leaf_node.key,
            value: alloy_leaf_node.value.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixedBranchNode {
    pub children: Box<[Option<Bytes>; 16]>,
    pub child_mask: u16,
}

impl From<AlloyBranchNode> for FixedBranchNode {
    fn from(alloy_node: AlloyBranchNode) -> Self {
        const ARRAY_REPEAT_VALUE: Option<Bytes> = None;
        let mut children = Box::new([ARRAY_REPEAT_VALUE; 16]);
        let mut stack_iter = alloy_node.stack.into_iter();
        let mut child_mask = 0u16;
        for index in 0..16 {
            if alloy_node.state_mask.is_bit_set(index) {
                let rlp_data = stack_iter
                    .next()
                    .expect("stack must be the same size as mask");
                children[index as usize] = Some(rlp_data.into());
                child_mask |= 1 << index
            }
        }
        Self {
            children,
            child_mask,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixedExtensionNode {
    pub key: Nibbles,
    pub child: Bytes,
}

impl From<AlloyExtensionNode> for FixedExtensionNode {
    fn from(alloy_extension_node: AlloyExtensionNode) -> Self {
        Self {
            key: alloy_extension_node.key,
            child: alloy_extension_node.child.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FixedTrie {
    pub nodes: HashMap<u64, FixedTrieNode>,
    pub head: u64,
    pub ptrs: u64,
    pub nodes_inserted: HashSet<Nibbles>,
}

impl FixedTrie {
    /// Create fixed trie from a diff trie.
    /// used for tests
    /// Only works for diff trie created from scratch and hashed.
    pub fn from_hashed_diff_trie_test(diff_trie: &DiffTrie) -> Self {
        let mut result = Self::default();
        result.head = diff_trie.head;
        result.ptrs = diff_trie.ptrs;

        for (ptr, node) in &diff_trie.nodes {
            let fixed_node = match &node.kind {
                DiffTrieNodeKind::Leaf(leaf) => FixedTrieNode::Leaf(Arc::new(FixedLeafNode {
                    key: leaf.key().clone(),
                    value: leaf.value().clone(),
                })),
                DiffTrieNodeKind::Extension(ext) => FixedTrieNode::Extension {
                    node: Arc::new(FixedExtensionNode {
                        key: ext.key().clone(),
                        child: ext
                            .child
                            .rlp_pointer
                            .clone()
                            .expect("diff trie must be hashed"),
                    }),
                    child_ptr: Some(ext.child.ptr.expect("all children must be in diff trie")),
                },
                DiffTrieNodeKind::Branch(branch) => {
                    const ARRAY_REPEAT_VALUE: Option<Bytes> = None;
                    let mut children = Box::new([ARRAY_REPEAT_VALUE; 16]);
                    let mut child_ptrs = Vec::new();
                    let mut child_mask = 0u16;
                    for n in 0..16u8 {
                        if branch.has_child(n) {
                            let child = branch
                                .get_diff_child(n)
                                .expect("all children must be in diff trie");
                            children[n as usize] =
                                Some(child.rlp_pointer.clone().expect("diff trie must be hashed"));
                            child_ptrs.push((n, child.ptr.expect("diff trie must be complete")));
                            child_mask |= 1 << n;
                        }
                    }
                    FixedTrieNode::Branch {
                        node: Arc::new(FixedBranchNode {
                            children,
                            child_mask,
                        }),
                        child_ptrs,
                    }
                }
                DiffTrieNodeKind::Null => FixedTrieNode::Null,
            };
            result.nodes.insert(*ptr, fixed_node);
        }

        result
    }

    /// nodes must be sorted by key
    pub fn add_nodes(&mut self, nodes: &[(Nibbles, Bytes)]) -> alloy_rlp::Result<()> {
        // @todo less unwraps, maybe surface an error

        // when adding empty proof we init try to be empty
        if nodes.is_empty() && self.nodes.is_empty() {
            self.nodes.insert(0, FixedTrieNode::Null);
            self.head = 0;
            self.ptrs = 0;
            self.nodes_inserted.insert(Nibbles::new());
        }

        for (path, node) in nodes {
            if self.nodes_inserted.contains(path) {
                continue;
            }

            let alloy_trie_node = AlloyTrieNode::decode(&mut node.as_ref())?;
            let fixed_trie_node = match alloy_trie_node {
                AlloyTrieNode::Branch(node) => FixedTrieNode::Branch {
                    node: Arc::new(node.into()),
                    child_ptrs: Vec::new(),
                },
                AlloyTrieNode::Extension(node) => FixedTrieNode::Extension {
                    node: Arc::new(node.into()),
                    child_ptr: None,
                },
                AlloyTrieNode::Leaf(node) => FixedTrieNode::Leaf(Arc::new(node.into())),
            };

            // here we go to insert this node
            let mut current_path = Nibbles::new();
            let mut path_left = path.clone();
            let mut current_node = self.head;

            let mut parent: Option<u64> = None;
            let mut parent_child_idx: Option<u8> = None;
            // looking for parent
            loop {
                // parent was wound
                if path_left.is_empty() {
                    break;
                }
                let node = match self.nodes.get(&current_node) {
                    Some(node) => node,
                    None => panic!("current node not found"),
                };
                match node {
                    FixedTrieNode::Extension { node, child_ptr } => {
                        if path_left.starts_with(&node.key) {
                            parent = Some(current_node);
                            parent_child_idx = None;

                            let len = node.key.len();
                            current_path.extend_from_slice_unchecked(&path_left[..len]);
                            path_left.as_mut_vec_unchecked().drain(..len);

                            if path_left.is_empty() {
                                break;
                            }

                            current_node = child_ptr.unwrap();
                            continue;
                        }
                        unreachable!()
                    }
                    FixedTrieNode::Branch { child_ptrs, .. } => {
                        let nibble = strip_first_nibble_mut(&mut path_left);

                        parent = Some(current_node);
                        parent_child_idx = Some(nibble);

                        if path_left.is_empty() {
                            break;
                        }

                        current_path.push_unchecked(nibble);
                        current_node = get_child_ptr(child_ptrs, nibble).unwrap();
                    }
                    FixedTrieNode::Null | FixedTrieNode::Leaf(_) => unreachable!(),
                }
            }

            self.nodes_inserted.insert(path.clone());
            let ptr = get_new_ptr(&mut self.ptrs);
            self.nodes.insert(ptr, fixed_trie_node);

            if let Some(parent) = parent {
                let parent_node = self.nodes.get_mut(&parent).unwrap();
                match parent_node {
                    FixedTrieNode::Extension { child_ptr, .. } => {
                        *child_ptr = Some(ptr);
                    }
                    FixedTrieNode::Branch { child_ptrs, .. } => {
                        let child_nibble = parent_child_idx.unwrap();
                        assert!(get_child_ptr(child_ptrs, child_nibble).is_none());
                        child_ptrs.push((child_nibble, ptr));
                    }
                    FixedTrieNode::Null | FixedTrieNode::Leaf(_) => unreachable!(),
                }
            } else {
                assert_eq!(self.nodes.len(), 1);
                assert_eq!(self.head, 0);
                self.head = ptr;
            }
        }
        Ok(())
    }

    pub fn gather_subtrie(
        &self,
        changed_keys: &[Bytes],
        deleted_keys: &[Bytes],
    ) -> Result<DiffTrie, Vec<Nibbles>> {
        let mut missing_nodes = Vec::new();
        let mut result = DiffTrie::default();
        // @todo, this is not right, at least for account map
        result.nodes = hash_map_with_capacity(self.nodes.len());
        // result.nodes = HashMap::default();
        result.head = self.head;
        result.ptrs = self.ptrs;

        let additional_change = if changed_keys.is_empty() && deleted_keys.is_empty() {
            Some((Bytes::new(), false))
        } else {
            None
        };
        let additional_change_iter = additional_change.as_ref().map(|(p, b)| (p, *b));

        let iter = changed_keys
            .iter()
            .zip(std::iter::repeat(false))
            .chain(deleted_keys.iter().zip(std::iter::repeat(true)))
            .chain(additional_change_iter);

        for (changed_key, delete) in iter {
            let mut c = NodeCursor::new(Nibbles::unpack(changed_key), self.head);
            loop {
                let node = match self.nodes.get(&c.current_node) {
                    Some(node) => node,
                    None => {
                        missing_nodes.push(Nibbles::unpack(changed_key));
                        break;
                    }
                };
                let diff_node = result
                    .nodes
                    .entry(c.current_node)
                    .or_insert_with(|| node.create_diff_node());
                match (node, &mut diff_node.kind) {
                    (FixedTrieNode::Null, DiffTrieNodeKind::Null) => {
                        // this is empty trie, we have everything to return
                        return Ok(result);
                    }
                    (FixedTrieNode::Leaf(_), DiffTrieNodeKind::Leaf(_)) => {
                        break;
                    }
                    (
                        FixedTrieNode::Extension { child_ptr, .. },
                        DiffTrieNodeKind::Extension(extension),
                    ) => {
                        if c.path_left.starts_with(extension.key()) {
                            extension.child.ptr = *child_ptr;
                            // go deeper
                            c.step_into_extension(&extension);
                            continue;
                        }
                        break;
                    }
                    (
                        FixedTrieNode::Branch {
                            child_ptrs,
                            node: fixed_branch,
                        },
                        DiffTrieNodeKind::Branch(branch),
                    ) => {
                        if c.path_left.is_empty() {
                            break;
                        }
                        let nibble = c.next_nibble();
                        if fixed_branch.children[nibble as usize].is_none() {
                            break;
                        }
                        let fixed_child_ptr = get_child_ptr(child_ptrs, nibble);
                        branch.insert_diff_child(
                            nibble,
                            DiffChildPtr {
                                rlp_pointer: None,
                                ptr: fixed_child_ptr,
                            },
                        );
                        c.step_into_branch(&branch);
                        if delete {
                            branch.aux_bits &= !(1 << nibble);
                            if branch.aux_bits.count_ones() == 1 {
                                let orphan_nibble = branch.aux_bits.trailing_zeros() as u8;
                                if branch.get_diff_child(orphan_nibble).is_none() {
                                    // that means that might be orphan was not added to the diff trie
                                    if let Some(orphan_ptr) =
                                        get_child_ptr(child_ptrs, orphan_nibble)
                                    {
                                        branch.insert_diff_child(
                                            orphan_nibble,
                                            DiffChildPtr {
                                                rlp_pointer: None,
                                                ptr: Some(orphan_ptr),
                                            },
                                        );
                                        let orphan_node =
                                            self.nodes.get(&orphan_ptr).expect("must be in trie");
                                        result
                                            .nodes
                                            .insert(orphan_ptr, orphan_node.create_diff_node());
                                    } else {
                                        // orphan node is missing
                                        // we stepped into child above so the path is the path of current child and orphan child differs
                                        // only in last nibble
                                        let mut path = c.current_path.clone();
                                        path.as_mut_vec_unchecked()
                                            .last_mut()
                                            .map(|n| *n = orphan_nibble)
                                            .unwrap();
                                        missing_nodes.push(path);
                                    }
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }

        if missing_nodes.is_empty() {
            Ok(result)
        } else {
            Err(missing_nodes)
        }
    }
}

fn get_child_ptr(child_ptrs: &[(u8, u64)], nibble: u8) -> Option<u64> {
    child_ptrs
        .iter()
        .find_map(|(c, ptr)| if c == &nibble { Some(*ptr) } else { None })
}
