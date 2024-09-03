mod toy_trie_tests;

use reth_trie::proof::Proof;
use reth_db_api::transaction::DbTx;


#[derive(Debug)]
pub struct TrieFetcher<'a, TX> {
    tx: &'a TX
}


impl<'a, TX> TrieFetcher<'a, TX>
where
    TX: DbTx,
{
    pub fn new(tx: &'a TX) -> Self {
        Self {
            tx,
        }
    }

    pub fn foo(&self) {
	let mut proof = Proof::from_tx(self.tx);
	proof.with_targets(todo!());

    }
}
