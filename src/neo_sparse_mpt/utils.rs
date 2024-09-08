use alloy_trie::Nibbles;

pub fn concat_path(p1: &Nibbles, p2: &[u8]) -> Nibbles {
    // let mut path = p1.clone();
    // path.extend_from_slice_unchecked(p2.as_ref());
    // path
    let mut result = Nibbles::with_capacity(p1.len() + p2.len());
    result.extend_from_slice_unchecked(&p1);
    result.extend_from_slice_unchecked(&p2);
    result
}

pub fn strip_first_nibble(p: Nibbles) -> (u8, Nibbles) {
    (p[0], Nibbles::from_nibbles_unchecked(&p[1..]))
}

pub fn strip_first_nibble_mut(p: &mut Nibbles) -> u8 {
    let nibble = p[0];
    let vec = p.as_mut_vec_unchecked();
    vec.remove(0);
    nibble
}
