use alloy_primitives::{keccak256, Bytes, B256};
use reth_trie::word_rlp;
use rustc_hash::FxBuildHasher;

// pub type HashMap<K, V> = std::collections::HashMap::<K, V, ahash::RandomState>;
// pub type HashSet<K> = std::collections::HashSet::<K, ahash::RandomState>;

// pub fn hash_map_with_capacity<K, V>(capacity: usize) -> HashMap<K, V> {
//     HashMap::with_capacity_and_hasher(capacity, ahash::RandomState::default())
// }

pub type HashMap<K, V> = std::collections::HashMap<K, V, FxBuildHasher>;
pub type HashSet<K> = std::collections::HashSet<K, FxBuildHasher>;

pub fn hash_map_with_capacity<K, V>(capacity: usize) -> HashMap<K, V> {
    HashMap::with_capacity_and_hasher(capacity, FxBuildHasher)
}

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

pub fn reference_trie_hash2(data: &[(Bytes, Bytes)]) -> B256 {
    triehash::trie_root::<KeccakHasher, _, _, _>(data.to_vec())
}

pub fn rlp_pointer(rlp_encode: Bytes) -> Bytes {
    if rlp_encode.len() < 32 {
        rlp_encode
    } else {
        word_rlp(&keccak256(&rlp_encode)).into()
    }
}
