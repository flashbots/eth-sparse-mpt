use super::change_set::ETHTrieChangeSet;
use crate::neo_sparse_mpt::SparseTrieError;
use crate::neo_sparse_mpt::SparseTrieNodes;
use ahash::HashMap;
use alloy_primitives::hex_literal::hex;
use alloy_primitives::{Bytes, B256};
use alloy_rlp::Encodable;
use eyre::WrapErr;
use reth_trie::TrieAccount;

#[derive(Default)]
pub struct EthSparseTries {
    pub account_trie: SparseTrieNodes,
    pub storage_tries: HashMap<Bytes, SparseTrieNodes>,
}

impl EthSparseTries {
    pub fn calculate_root_hash(&mut self, changes: ETHTrieChangeSet) -> eyre::Result<B256> {
        // @parallel consider parallel since storage hashed can be calculated in parallel

        let mut account_hashes = HashMap::default();

        for (idx, account) in changes.account_trie_updates.iter().enumerate() {
            // let test_account = Bytes::from(hex!("07dbc2fd98c6f6265f2b5c8ebddf898b06ff1b3d74b54abf9c68ec2cb61f46f1"));
            // let print = account == &test_account;

            let updated_slots = &changes.storage_trie_updated_keys[idx];
            let updated_value = &changes.storage_trie_updated_values[idx];
            let deleted_slots = &changes.storage_trie_deleted_keys[idx];

            let storage_trie = self
                .storage_tries
                .get_mut(account)
                .ok_or_else(|| eyre::eyre!("account trie not found: {:?}", account))?;
            // if print {
            // 	println!("test trie freshly gathered account: {:?} {:#?}", account, storage_trie);
            // }
            for (key, value) in updated_slots.iter().zip(updated_value) {
                // if print {
                //     println!("test account updating key: {:?} {:?}", account, key);
                // }
                storage_trie
                    .insert(key.clone(), value.clone())
                    .with_context(|| format!("Inserting into strorage trie: {:?}", account))?;
            }
            for key in deleted_slots {
                // if print {
                //     println!("test account deleting key: {:?} {:?}", account, key);
                // }
                storage_trie
                    .delete(key.clone())
                    .with_context(|| format!("Deleting from strorage trie: {:?}", account))?;
            }
            // if print {
            // 	println!("test trie updated trie: {:?} {:#?}", account, storage_trie);
            // }
            let storage_hash = storage_trie
                .root_hash()
                .with_context(|| format!("Calculating root hash: {:?}", account))?;
            account_hashes.insert(account.clone(), storage_hash);
        }

        let mut encoded_account = Vec::new();
        for (account, updated_info) in changes
            .account_trie_updates
            .into_iter()
            .zip(changes.account_trie_updates_info)
        {
            let hash = account_hashes
                .remove(&account)
                .ok_or_else(|| eyre::eyre!("account trie hash not found: {:?}", account))?;
            let trie_account: TrieAccount = (updated_info, hash).into();
            encoded_account.clear();
            trie_account.encode(&mut encoded_account);

            self.account_trie
                .insert(account.clone(), Bytes::copy_from_slice(&encoded_account))
                .with_context(|| format!("Inserting into account trie trie: {:?}", account))?;
        }

        for account in changes.account_trie_deletes {
            self.account_trie.delete(account)?;
        }
        Ok(self.account_trie.root_hash()?)
    }
}
