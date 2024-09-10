use alloy_primitives::{keccak256, B256};

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

pub fn reference_trie_hash(data: &[(Vec<u8>, Vec<u8>)]) -> B256 {
    triehash::trie_root::<KeccakHasher, _, _, _>(data.to_vec())
}
