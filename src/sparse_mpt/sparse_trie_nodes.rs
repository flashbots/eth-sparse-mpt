use crate::utils::HashMap;
use alloy_primitives::keccak256;
use alloy_primitives::Bytes;
use alloy_rlp::{BufMut, Decodable, Encodable, Header, EMPTY_STRING_CODE};
use alloy_trie::nodes::word_rlp;
use alloy_trie::nodes::{
    BranchNode as AlloyBranchNode, ExtensionNode as AlloyExtensionNode, ExtensionNodeRef,
    LeafNode as AlloyLeafNode, LeafNodeRef, TrieNode as AlloyTrieNode,
};
use alloy_trie::Nibbles;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodePointer {
    // if Some than sparse trie contains the child
    // pub path: Option<Nibbles>,
    // rlp(node) or rpl(hash(node))
    pub rlp_pointer: Bytes,
    pub rlp_pointer_dirty: bool,
}

impl NodePointer {
    pub fn rlp_pointer(hash: Bytes) -> Self {
        Self {
            rlp_pointer: hash,
            rlp_pointer_dirty: false,
        }
    }

    pub fn empty_pointer() -> Self {
        Self {
            rlp_pointer: Bytes::new(),
            rlp_pointer_dirty: true,
        }
    }
}

impl Default for NodePointer {
    fn default() -> Self {
        Self {
            rlp_pointer: Bytes::new(),
            rlp_pointer_dirty: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SparseTrieNode {
    pub kind: SparseTrieNodeKind,
    pub rlp_pointer: Bytes,
    pub rlp_pointer_dirty: bool,
}

impl SparseTrieNode {
    pub fn new(kind: SparseTrieNodeKind) -> Self {
        Self {
            kind,
            rlp_pointer: Bytes::new(),
            rlp_pointer_dirty: true,
        }
    }

    pub fn null_node() -> Self {
        // todo: nit, can be not dirty
        Self {
            kind: SparseTrieNodeKind::NullNode,
            rlp_pointer: Bytes::new(),
            rlp_pointer_dirty: true,
        }
    }

    pub fn rlp_pointer(&mut self) -> Bytes {
        if self.rlp_pointer_dirty {
            self.rlp_pointer = self.kind.rlp_pointer_slow();
            self.rlp_pointer_dirty = false;
        }
        self.rlp_pointer.clone()
    }

    pub fn rlp_pointer_cached(&mut self, cache: &mut HashMap<SparseTrieNodeKind, Bytes>) -> Bytes {
        if self.rlp_pointer_dirty {
            if let Some(cached) = cache.get(&self.kind) {
                self.rlp_pointer = cached.clone();
                self.rlp_pointer_dirty = false;
            } else {
                let value = self.kind.rlp_pointer_slow();
                cache.insert(self.kind.clone(), value.clone());
                self.rlp_pointer = value;
                self.rlp_pointer_dirty = false;
            }
        }
        self.rlp_pointer.clone()
    }

    pub fn new_leaf_node(key: Nibbles, value: Bytes) -> Self {
        Self {
            kind: SparseTrieNodeKind::LeafNode(LeafNode { key, value }),
            rlp_pointer: Bytes::new(),
            rlp_pointer_dirty: true,
        }
    }

    pub fn new_ext_node(key: Nibbles, child_rpl_pointer: Option<Bytes>) -> Self {
        Self {
            kind: SparseTrieNodeKind::ExtensionNode(ExtensionNode {
                key,
                child: NodePointer {
                    rlp_pointer_dirty: child_rpl_pointer.is_none(),
                    rlp_pointer: child_rpl_pointer.unwrap_or_else(|| Bytes::new()),
                },
            }),
            rlp_pointer: Bytes::new(),
            rlp_pointer_dirty: true,
        }
    }

    pub fn new_branch_node(
        n1: u8,
        n1_rlp_pointer: Option<Bytes>,
        n2: u8,
        n2_rlp_pointer: Option<Bytes>,
    ) -> Self {
        const ARRAY_REPEAT_VALUE: Option<NodePointer> = None;
        let mut children = Box::new([ARRAY_REPEAT_VALUE; 16]);
        children[n1 as usize] = Some(NodePointer {
            rlp_pointer_dirty: n1_rlp_pointer.is_none(),
            rlp_pointer: n1_rlp_pointer.unwrap_or_else(|| Bytes::new()),
        });
        children[n2 as usize] = Some(NodePointer {
            rlp_pointer_dirty: n2_rlp_pointer.is_none(),
            rlp_pointer: n2_rlp_pointer.unwrap_or_else(|| Bytes::new()),
        });
        Self {
            kind: SparseTrieNodeKind::BranchNode(BranchNode {
                children,
                aux_bits: 0,
            }),
            rlp_pointer: Bytes::new(),
            rlp_pointer_dirty: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SparseTrieNodeKind {
    NullNode,
    LeafNode(LeafNode),
    ExtensionNode(ExtensionNode),
    BranchNode(BranchNode),
}

impl SparseTrieNodeKind {
    pub fn rlp_pointer_slow(&self) -> Bytes {
        let mut rlp = Vec::new();
        match self {
            SparseTrieNodeKind::BranchNode(node) => node.encode(&mut rlp),
            SparseTrieNodeKind::LeafNode(node) => node.encode(&mut rlp),
            SparseTrieNodeKind::ExtensionNode(node) => node.encode(&mut rlp),
            SparseTrieNodeKind::NullNode => return Bytes::copy_from_slice(&[EMPTY_STRING_CODE]),
        }
        if rlp.len() < 32 {
            rlp.into()
        } else {
            word_rlp(&keccak256(&rlp)).into()
        }
    }
}

impl Default for SparseTrieNodeKind {
    fn default() -> Self {
        SparseTrieNodeKind::NullNode
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct LeafNode {
    pub key: Nibbles,
    pub value: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct ExtensionNode {
    pub key: Nibbles,
    pub child: NodePointer,
}

impl ExtensionNode {
    pub fn new(key: Nibbles) -> Self {
        Self {
            key,
            child: NodePointer::empty_pointer(),
        }
    }

    pub fn child_path(&self, node_path: &Nibbles) -> Nibbles {
        let mut res = Nibbles::with_capacity(node_path.len() + self.key.len());
        res.extend_from_slice(&node_path);
        res.extend_from_slice(&self.key);
        res
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct BranchNode {
    pub children: Box<[Option<NodePointer>; 16]>,
    pub aux_bits: u16,
}

impl BranchNode {
    pub fn child_path(node_path: &Nibbles, nibble: u8) -> Nibbles {
        let mut res = Nibbles::with_capacity(node_path.len() + 1);
        res.extend_from_slice(&node_path);
        res.push_unchecked(nibble);
        res
    }

    pub fn child_count(&self) -> usize {
        self.children.iter().filter(|c| c.is_some()).count()
    }

    pub fn other_child(&self, child: usize) -> Option<usize> {
        let res = self
            .children
            .iter()
            .enumerate()
            .find(|(idx, c)| c.is_some() && *idx != child)
            .map(|(idx, _)| idx);
        res
    }

    pub fn children_bits(&self) -> u16 {
        let mut res = 0;
        for (idx, child) in self.children.iter().enumerate() {
            if child.is_some() {
                res |= 1 << idx
            }
        }
        res
    }
}

// RLP encoding / decoding

impl From<AlloyLeafNode> for LeafNode {
    fn from(alloy_leaf_node: AlloyLeafNode) -> Self {
        Self {
            key: alloy_leaf_node.key,
            value: alloy_leaf_node.value.into(),
        }
    }
}

impl LeafNode {
    pub fn encode(&self, out: &mut dyn BufMut) {
        encode_leaf(&self.key, &self.value, out)
    }
}

impl From<AlloyExtensionNode> for ExtensionNode {
    fn from(alloy_extension_node: AlloyExtensionNode) -> Self {
        Self {
            key: alloy_extension_node.key,
            child: NodePointer::rlp_pointer(alloy_extension_node.child.into()),
        }
    }
}

impl ExtensionNode {
    pub fn encode(&self, out: &mut dyn BufMut) {
        assert!(!self.child.rlp_pointer_dirty);
        encode_extension(&self.key, &self.child.rlp_pointer, out);
    }
}

impl From<AlloyBranchNode> for BranchNode {
    fn from(alloy_node: AlloyBranchNode) -> Self {
        const ARRAY_REPEAT_VALUE: Option<NodePointer> = None;
        let mut children = Box::new([ARRAY_REPEAT_VALUE; 16]);
        let mut stack_iter = alloy_node.stack.into_iter();
        for index in 0..16 {
            if alloy_node.state_mask.is_bit_set(index) {
                let rlp_data = stack_iter
                    .next()
                    .expect("stack must be the same size as mask");
                children[index as usize] = Some(NodePointer::rlp_pointer(rlp_data.into()));
            }
        }
        Self {
            children,
            aux_bits: 0,
        }
    }
}

impl BranchNode {
    pub fn encode(&self, out: &mut dyn BufMut) {
        let mut input = [None; 16];
        for i in 0..16 {
            if let Some(child) = &self.children[i] {
                assert!(!child.rlp_pointer_dirty);
                input[i] = Some(child.rlp_pointer.as_ref());
            }
        }
        encode_branch_node(&input, out)
    }
}

impl Decodable for SparseTrieNode {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let alloy_trie_node = AlloyTrieNode::decode(buf)?;
        let kind = match alloy_trie_node {
            AlloyTrieNode::Branch(node) => SparseTrieNodeKind::BranchNode(node.into()),
            AlloyTrieNode::Extension(node) => SparseTrieNodeKind::ExtensionNode(node.into()),
            AlloyTrieNode::Leaf(node) => SparseTrieNodeKind::LeafNode(node.into()),
        };

        Ok(SparseTrieNode {
            kind,
            rlp_pointer: Bytes::new(),
            rlp_pointer_dirty: true,
        })
    }
}

impl SparseTrieNode {
    pub fn encode(&self, out: &mut dyn BufMut) {
        match &self.kind {
            SparseTrieNodeKind::BranchNode(node) => {
                node.encode(out);
            }
            SparseTrieNodeKind::ExtensionNode(node) => {
                node.encode(out);
            }
            SparseTrieNodeKind::LeafNode(node) => {
                node.encode(out);
            }
            SparseTrieNodeKind::NullNode => {
                out.put_bytes(EMPTY_STRING_CODE, 1);
            }
        }
    }
}

pub fn encode_leaf(key: &Nibbles, value: &[u8], out: &mut dyn BufMut) {
    LeafNodeRef { key, value }.encode(out)
}

pub fn encode_extension(key: &Nibbles, child_rlp_pointer: &[u8], out: &mut dyn BufMut) {
    ExtensionNodeRef {
        key,
        child: child_rlp_pointer,
    }
    .encode(out)
}

pub fn encode_branch_node(child_rlp_pointers: &[Option<&[u8]>; 16], out: &mut dyn BufMut) {
    let mut payload_length = 1;
    for i in 0..16 {
        if let Some(child) = child_rlp_pointers[i] {
            payload_length += child.len();
        } else {
            payload_length += 1;
        }
    }

    Header {
        list: true,
        payload_length,
    }
    .encode(out);

    for i in 0..16 {
        if let Some(child) = child_rlp_pointers[i] {
            out.put_slice(child);
        } else {
            out.put_u8(EMPTY_STRING_CODE);
        }
    }
    out.put_u8(EMPTY_STRING_CODE);
}
