use alloy_trie::Nibbles;

pub fn concat_path(p1: &Nibbles, p2: impl AsRef<[u8]>) -> Nibbles {
    let mut path = p1.clone();
    path.extend_from_slice_unchecked(p2.as_ref());
    path
}

pub fn strip_first_nibble(p: Nibbles) -> (u8, Nibbles) {
    (p[0], Nibbles::from_nibbles_unchecked(&p[1..]))
}
