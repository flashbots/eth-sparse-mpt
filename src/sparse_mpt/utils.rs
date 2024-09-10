use alloy_trie::Nibbles;

pub fn concat_path(p1: &Nibbles, p2: &[u8]) -> Nibbles {
    let mut result = Nibbles::with_capacity(p1.len() + p2.len());
    result.extend_from_slice_unchecked(&p1);
    result.extend_from_slice_unchecked(&p2);
    result
}

pub fn strip_first_nibble_mut(p: &mut Nibbles) -> u8 {
    let nibble = p[0];
    let vec = p.as_mut_vec_unchecked();
    vec.remove(0);
    nibble
}

pub fn extract_prefix_and_suffix(p1: &Nibbles, p2: &Nibbles) -> (Nibbles, Nibbles, Nibbles) {
    let prefix_len = p1.common_prefix_length(p2);
    let prefix = Nibbles::from_nibbles_unchecked(&p1[..prefix_len]);
    let suffix1 = Nibbles::from_nibbles_unchecked(&p1[prefix_len..]);
    let suffix2 = Nibbles::from_nibbles_unchecked(&p2[prefix_len..]);

    (prefix, suffix1, suffix2)
}
