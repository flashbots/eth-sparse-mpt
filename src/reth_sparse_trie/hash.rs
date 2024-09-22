use super::change_set::ETHTrieChangeSet;
use crate::sparse_mpt::DiffTrie;
use crate::utils::HashMap;
use alloy_primitives::{Bytes, B256};
use alloy_rlp::Encodable;
use eyre::WrapErr;
use rayon::prelude::*;
use reth_trie::TrieAccount;

#[derive(Default, Clone)]
pub struct EthSparseTries {
    pub account_trie: DiffTrie,
    pub storage_tries: HashMap<Bytes, DiffTrie>,
}

impl EthSparseTries {
    pub fn calculate_root_hash(
        &mut self,
        changes: ETHTrieChangeSet,
        parallel_storage: bool,
        parallel_main_trie: bool,
    ) -> eyre::Result<B256> {
        let mut account_hashes = if parallel_storage {
            self.calculate_account_hashes_parallel(&changes)?
        } else {
            self.calculate_account_hashes_seq(&changes)?
        };

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
        let hash = if parallel_main_trie {
            self.account_trie.root_hash_parallel()?
        } else {
            self.account_trie.root_hash()?
        };
        Ok(hash)
    }

    fn calculate_account_hashes_seq(
        &mut self,
        changes: &ETHTrieChangeSet,
    ) -> eyre::Result<HashMap<Bytes, B256>> {
        let mut account_hashes = HashMap::default();

        for (idx, account) in changes.account_trie_updates.iter().enumerate() {
            let updated_slots = &changes.storage_trie_updated_keys[idx];
            let updated_value = &changes.storage_trie_updated_values[idx];
            let deleted_slots = &changes.storage_trie_deleted_keys[idx];

            let storage_trie = self
                .storage_tries
                .get_mut(account)
                .ok_or_else(|| eyre::eyre!("account trie not found: {:?}", account))?;
            for (key, value) in updated_slots.iter().zip(updated_value) {
                storage_trie
                    .insert(key.clone(), value.clone())
                    .with_context(|| format!("Inserting into strorage trie: {:?}", account))?;
            }
            for key in deleted_slots {
                storage_trie
                    .delete(key.clone())
                    .with_context(|| format!("Deleting from strorage trie: {:?}", account))?;
            }
            let storage_hash = storage_trie
                .root_hash()
                .with_context(|| format!("Calculating root hash: {:?}", account))?;
            account_hashes.insert(account.clone(), storage_hash);
        }
        Ok(account_hashes)
    }

    fn calculate_account_hashes_parallel(
        &mut self,
        changes: &ETHTrieChangeSet,
    ) -> eyre::Result<HashMap<Bytes, B256>> {
        let mut input = Vec::with_capacity(changes.account_trie_updates.len());

        for (idx, account) in changes.account_trie_updates.iter().enumerate() {
            let updated_slots = &changes.storage_trie_updated_keys[idx];
            let updated_value = &changes.storage_trie_updated_values[idx];
            let deleted_slots = &changes.storage_trie_deleted_keys[idx];

            let storage_trie = self
                .storage_tries
                .remove(account)
                .ok_or_else(|| eyre::eyre!("account trie not found: {:?}", account))?;
            input.push((
                account,
                storage_trie,
                updated_slots,
                updated_value,
                deleted_slots,
            ));
        }

        let account_hashes = input.into_par_iter().map(|(account, mut storage_trie, updated_slots, updated_value, deleted_slots)| -> eyre::Result<_> {
            for (key, value) in updated_slots.iter().zip(updated_value) {
		storage_trie
                    .insert(key.clone(), value.clone())
                    .with_context(|| format!("Inserting into strorage trie: {:?}", account))?;
            }
            for key in deleted_slots {
		storage_trie
                    .delete(key.clone())
                    .with_context(|| format!("Deleting from strorage trie: {:?}", account))?;
            }
            let storage_hash = storage_trie
		.root_hash()
		.with_context(|| format!("Calculating root hash: {:?}", account))?;
   	    Ok((account.clone(), storage_hash))
	}).collect::<Result<HashMap<_, _>, _>>()?;
        Ok(account_hashes)
    }
}
