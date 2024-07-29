mod toy_trie_tests;

/// Copied form reth `Proof` and modified to fetch all nodes for some path
use alloy_rlp::{BufMut, Encodable};
use reth::primitives::{
    constants::EMPTY_ROOT_HASH,
    trie::{HashBuilder, Nibbles, StorageProof, TrieAccount},
    B256,
};
use reth_db::{tables, transaction::DbTx};
use reth_interfaces::trie::{StateRootError, StorageRootError};
use reth_trie::hashed_cursor::{HashedCursorFactory, HashedStorageCursor};
use reth_trie::node_iter::{AccountNode, AccountNodeIter, StorageNode, StorageNodeIter};
use reth_trie::prefix_set::PrefixSetMut;
use reth_trie::trie_cursor::{DatabaseAccountTrieCursor, DatabaseStorageTrieCursor};
use reth_trie::walker::TrieWalker;

#[derive(Debug)]
pub struct TrieFetcher<'a, TX, H> {
    /// A reference to the database transaction.
    tx: &'a TX,
    /// The factory for hashed cursors.
    hashed_cursor_factory: H,
}

impl<'a, TX> TrieFetcher<'a, TX, &'a TX> {
    /// Create a new [TrieFetcher] instance.
    pub fn new(tx: &'a TX) -> Self {
        Self {
            tx,
            hashed_cursor_factory: tx,
        }
    }
}

impl<'a, TX, H> TrieFetcher<'a, TX, H>
where
    TX: DbTx,
    H: HashedCursorFactory + Clone,
{
    pub fn account_proof_path(
        &self,
        target_nibbles: Nibbles,
    ) -> Result<Vec<Vec<u8>>, StateRootError> {
        let hashed_account_cursor = self.hashed_cursor_factory.hashed_account_cursor()?;
        let trie_cursor =
            DatabaseAccountTrieCursor::new(self.tx.cursor_read::<tables::AccountsTrie>()?);

        // Create the walker.
        let mut prefix_set = PrefixSetMut::default();
        prefix_set.insert(target_nibbles.clone());
        let walker = TrieWalker::new(trie_cursor, prefix_set.freeze());

        // Create a hash builder to rebuild the root node since it is not available in the database.
        let mut hash_builder =
            HashBuilder::default().with_proof_retainer(Vec::from([target_nibbles]));

        let mut account_rlp = Vec::with_capacity(128);
        let mut account_node_iter = AccountNodeIter::new(walker, hashed_account_cursor);
        while let Some(account_node) = account_node_iter.try_next()? {
            match account_node {
                AccountNode::Branch(node) => {
                    hash_builder.add_branch(node.key, node.value, node.children_are_in_trie);
                }
                AccountNode::Leaf(hashed_address, account) => {
                    let storage_root = self.storage_root(hashed_address)?;

                    account_rlp.clear();
                    let account = TrieAccount::from((account, storage_root));
                    account.encode(&mut account_rlp as &mut dyn BufMut);

                    hash_builder.add_leaf(Nibbles::unpack(hashed_address), &account_rlp);
                }
            }
        }

        let _ = hash_builder.root();

        let proofs = hash_builder.take_proofs();
        Ok(proofs.values().map(|v| v.to_vec()).collect())
    }

    pub fn storage_proof_paths(
        &self,
        hashed_address: B256,
        slots: &[Nibbles],
    ) -> Result<(B256, Vec<Vec<u8>>), StorageRootError> {
        let mut hashed_storage_cursor = self.hashed_cursor_factory.hashed_storage_cursor()?;

        // short circuit on empty storage
        if hashed_storage_cursor.is_storage_empty(hashed_address)? {
            return Ok((EMPTY_ROOT_HASH, Vec::new()));
        }

        let target_nibbles = slots.iter().cloned().collect::<Vec<_>>();
        let prefix_set = PrefixSetMut::from(target_nibbles.clone()).freeze();
        let trie_cursor = DatabaseStorageTrieCursor::new(
            self.tx.cursor_dup_read::<tables::StoragesTrie>()?,
            hashed_address,
        );
        let walker = TrieWalker::new(trie_cursor, prefix_set);

        let mut hash_builder = HashBuilder::default().with_proof_retainer(target_nibbles);
        let mut storage_node_iter =
            StorageNodeIter::new(walker, hashed_storage_cursor, hashed_address);
        while let Some(node) = storage_node_iter.try_next()? {
            match node {
                StorageNode::Branch(node) => {
                    hash_builder.add_branch(node.key, node.value, node.children_are_in_trie);
                }
                StorageNode::Leaf(hashed_slot, value) => {
                    let nibbles = Nibbles::unpack(hashed_slot);
                    hash_builder.add_leaf(nibbles, alloy_rlp::encode_fixed_size(&value).as_ref());
                }
            }
        }

        let root = hash_builder.root();

        let all_proof_nodes = hash_builder.take_proofs();

        Ok((
            root,
            all_proof_nodes
                .values()
                .into_iter()
                .map(|v| v.to_vec())
                .collect(),
        ))
    }

    /// Compute storage root.
    fn storage_root(&self, hashed_address: B256) -> Result<B256, StorageRootError> {
        let (storage_root, _) = self.storage_root_with_proofs(hashed_address, &[])?;
        Ok(storage_root)
    }

    /// Compute the storage root and retain proofs for requested slots.
    fn storage_root_with_proofs(
        &self,
        hashed_address: B256,
        slots: &[B256],
    ) -> Result<(B256, Vec<StorageProof>), StorageRootError> {
        let mut hashed_storage_cursor = self.hashed_cursor_factory.hashed_storage_cursor()?;

        let mut proofs = slots
            .iter()
            .copied()
            .map(StorageProof::new)
            .collect::<Vec<_>>();

        // short circuit on empty storage
        if hashed_storage_cursor.is_storage_empty(hashed_address)? {
            return Ok((EMPTY_ROOT_HASH, proofs));
        }

        let target_nibbles = proofs.iter().map(|p| p.nibbles.clone()).collect::<Vec<_>>();
        let prefix_set = PrefixSetMut::from(target_nibbles.clone()).freeze();
        let trie_cursor = DatabaseStorageTrieCursor::new(
            self.tx.cursor_dup_read::<tables::StoragesTrie>()?,
            hashed_address,
        );
        let walker = TrieWalker::new(trie_cursor, prefix_set);

        let mut hash_builder = HashBuilder::default().with_proof_retainer(target_nibbles);
        let mut storage_node_iter =
            StorageNodeIter::new(walker, hashed_storage_cursor, hashed_address);
        while let Some(node) = storage_node_iter.try_next()? {
            match node {
                StorageNode::Branch(node) => {
                    hash_builder.add_branch(node.key, node.value, node.children_are_in_trie);
                }
                StorageNode::Leaf(hashed_slot, value) => {
                    let nibbles = Nibbles::unpack(hashed_slot);
                    if let Some(proof) = proofs.iter_mut().find(|proof| proof.nibbles == nibbles) {
                        proof.set_value(value);
                    }
                    hash_builder.add_leaf(nibbles, alloy_rlp::encode_fixed_size(&value).as_ref());
                }
            }
        }

        let root = hash_builder.root();

        let all_proof_nodes = hash_builder.take_proofs();
        for proof in proofs.iter_mut() {
            // Iterate over all proof nodes and find the matching ones.
            // The filtered results are guaranteed to be in order.
            let matching_proof_nodes = all_proof_nodes
                .iter()
                .filter(|(path, _)| proof.nibbles.starts_with(path))
                .map(|(_, node)| node.clone());
            proof.set_proof(matching_proof_nodes.collect());
        }

        Ok((root, proofs))
    }
}
