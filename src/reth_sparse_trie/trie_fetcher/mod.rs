mod toy_trie_tests;

use reth_db_api::transaction::DbTx;
use reth_trie::proof::Proof;
use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};

#[derive(Debug)]
pub struct TrieFetcher<'a, TX> {
    tx: &'a TX,
}

impl<'a, TX> TrieFetcher<'a, TX>
where
    TX: DbTx,
{
    pub fn new(tx: &'a TX) -> Self {
        Self { tx }
    }

    pub fn foo(&self) {
        let mut proof = Proof::new(
            DatabaseTrieCursorFactory::new(self.tx),
            DatabaseHashedCursorFactory::new(self.tx),
        );
        proof.with_targets(todo!());
        proof.multiproof();
    }
}
