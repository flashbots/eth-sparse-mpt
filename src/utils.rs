use alloy_primitives::{keccak256, Address, Bytes, B256};
use alloy_rlp::Decodable;
use alloy_trie::nodes::{BranchNode, ExtensionNode, LeafNode, TrieNode};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct KeccakHasher {}

impl hash_db::Hasher for KeccakHasher {
    type Out = B256;
    type StdHasher = ahash::AHasher;
    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> Self::Out {
        keccak256(x)
    }
}

pub fn pretty_print_trie_nodes(nodes: &[TrieNode]) {
    println!("=== BEGIN ===");
    for node in nodes {
        println!(" TrieNode: {:#?}", node);
    }
    println!("=== END ===");
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProof {
    pub address: Address,
    pub proof: Vec<Bytes>,
}

impl StoredProof {
    pub fn nodes(&self) -> Vec<TrieNode> {
        self.proof
            .iter()
            .map(|node| TrieNode::decode(&mut node.as_ref()).expect("trie node decode"))
            .collect()
    }

    pub fn load_known_proofs() -> Vec<StoredProof> {
        let data = include_str!("../proofs.json");
        serde_json::from_str(data).expect("failed to load proofs.json")
    }
}

pub fn clone_trie_node(node: &TrieNode) -> TrieNode {
    match node {
        TrieNode::Branch(branch) => TrieNode::Branch(BranchNode {
            stack: branch.stack.clone(),
            state_mask: branch.state_mask,
        }),
        TrieNode::Extension(extension) => TrieNode::Extension(ExtensionNode {
            key: extension.key.clone(),
            child: extension.child.clone(),
        }),
        TrieNode::Leaf(leaf) => TrieNode::Leaf(LeafNode {
            key: leaf.key.clone(),
            value: leaf.value.clone(),
        }),
    }
}
