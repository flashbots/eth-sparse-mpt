// use crate::reth_sparse_trie::trie_fetcher::TrieFetcher;
// use crate::sparse_mpt::{NodeNotFound, SparseMPT, SparseTrieError, SparseTrieStore};
// use ahash::HashMap;
// use alloy_primitives::bytes::BufMut;
// use alloy_primitives::{keccak256, Address, B256};
// use alloy_rlp::Encodable;
// use alloy_trie::Nibbles;
// use reth::primitives::trie::TrieAccount;
// use reth::providers::providers::ConsistentDbView;
// use reth::providers::{BundleStateWithReceipts, ProviderFactory};
// use reth_db::database::Database;
// use std::sync::{Arc, Mutex};
//
pub mod trie_fetcher;
//
// #[derive(Debug)]
// pub struct RethSparseTrieSharedCache {
//     account_trie_store: SparseTrieStore,
//     storage_tries_store: Arc<Mutex<HashMap<Address, SparseTrieStore>>>,
// }
//
// impl Default for RethSparseTrieSharedCache {
//     fn default() -> Self {
//         Self {
//             account_trie_store: SparseTrieStore::new(),
//             storage_tries_store: Arc::new(Mutex::new(HashMap::default())),
//         }
//     }
// }
//
// impl RethSparseTrieSharedCache {
//     fn account_trie_store(&self) -> SparseTrieStore {
//         self.account_trie_store.clone()
//     }
//
//     fn storage_trie_store(&self, address: Address) -> SparseTrieStore {
//         let mut storage_tries_store = self.storage_tries_store.lock().unwrap();
//         storage_tries_store
//             .entry(address)
//             .or_insert_with(|| SparseTrieStore::new())
//             .clone()
//     }
// }
//
// #[derive(Debug)]
// pub struct RethSparseTrieRootHashCalc<DB> {
//     shared_cache: RethSparseTrieSharedCache,
//     consistent_db_view: ConsistentDbView<DB, ProviderFactory<DB>>,
// }
//
// #[derive(Debug)]
// enum TrieUpdate {
//     Update(Nibbles, Vec<u8>),
//     Delete(Nibbles),
// }
//
// impl TrieUpdate {
//     fn path(&self) -> Nibbles {
//         match self {
//             TrieUpdate::Update(path, _) => path.clone(),
//             TrieUpdate::Delete(path) => path.clone(),
//         }
//     }
// }
//
// impl<DB: Database> RethSparseTrieRootHashCalc<DB> {
//     pub fn root_hash(&self, bundle: &BundleStateWithReceipts) -> eyre::Result<B256> {
//         let provider_ro = self.consistent_db_view.provider_ro()?;
//         let trie_fetcher = TrieFetcher::new(provider_ro.tx_ref());
//
//         let mut account_changes = Vec::new();
//
//         // let mut pending_account_updates = HashMap::default();
//         //
//         // // what should we do with account storages
//         // // 1. if account is destroyed we use empty storage root hash
//         // // 2. if account storage is not modified we should use old account storage root hash
//         // // 3. if account storage is modified we fetch all the data needed to update it
//
//         for (address, bundle_account) in bundle.bundle_accounts_iter() {
//             if bundle_account.status.is_not_modified() {
//                 continue;
//             }
//
//             let hashed_address = keccak256(address.as_slice());
//             let hashed_address_path = Nibbles::unpack(&hashed_address);
//
//             if bundle_account.status.was_destroyed() {
//                 account_changes.push(TrieUpdate::Delete(hashed_address_path));
//                 continue;
//             }
//
//             // pending_account_updates.insert(hashed_address.clone(), bundle_account.info.clone().expect("account updates but account info is empty"));
//
//             let mut storage_trie_updates = Vec::new();
//             for (storage_key, value) in &bundle_account.storage {
//                 if !value.is_changed() {
//                     continue;
//                 }
//
//                 let hashed_storage_key = keccak256(B256::from(*storage_key).as_slice());
//                 let hashed_storage_key = Nibbles::unpack(&hashed_storage_key);
//
//                 if value.present_value.is_zero() {
//                     storage_trie_updates.push(TrieUpdate::Delete(hashed_storage_key));
//                 } else {
//                     let updated_value = alloy_rlp::encode(value.present_value);
//                     storage_trie_updates
//                         .push(TrieUpdate::Update(hashed_storage_key, updated_value));
//                 }
//             }
//
//             let storage_trie = self.shared_cache.storage_trie_store(address);
//             let storage_root =
//                 calc_trie_root_from_updates(storage_trie_updates, storage_trie, |slots| {
//                     trie_fetcher
//                         .storage_proof_paths(hashed_address, slots)
//                         .expect("TODO trie fetcher error")
//                         .1
//                 });
//
//             let mut account_rlp = Vec::new();
//             let trie_account = TrieAccount::from((
//                 bundle_account.info.clone().expect("account info empty"),
//                 storage_root,
//             ));
//             account_rlp.clear();
//             trie_account.encode(&mut account_rlp as &mut dyn BufMut);
//             account_changes.push(TrieUpdate::Update(hashed_address_path, account_rlp));
//         }
//
//         let account_trie = self.shared_cache.account_trie_store();
//         let root_hash = calc_trie_root_from_updates(account_changes, account_trie, |accounts| {
//             let mut result = Vec::new();
//             for account in accounts {
//                 let mut path = trie_fetcher
//                     .account_proof_path(account.clone())
//                     .expect("TODO trie fetcher error");
//                 result.append(&mut path);
//             }
//             result
//         });
//
//         Ok(root_hash)
//     }
// }
//
// fn calc_trie_root_from_updates<F>(
//     updates: Vec<TrieUpdate>,
//     sparse_trie_store: SparseTrieStore,
//     fetch: F,
// ) -> B256
// where
//     F: Fn(&[Nibbles]) -> Vec<Vec<u8>>,
// {
//     if !sparse_trie_store.is_initialised() {
//         let path_to_prove = Nibbles::from_nibbles_unchecked(&[0u8]);
//         let path = fetch(&[path_to_prove.clone()]);
//         sparse_trie_store.add_sparse_nodes_from_raw_proof(path, vec![path_to_prove]);
//     }
//
//     let mut paths_to_fetch = {
//         let updated_leafs = updates
//             .iter()
//             .map(|update| update.path())
//             .collect::<Vec<_>>();
//         sparse_trie_store.get_unfetched_leafs(&updated_leafs)
//     };
//     let mut fetch_iter = 0;
//
//     loop {
//         if fetch_iter > 5 {
//             panic!("Something wrong, can't finish fetch loop");
//         }
//         fetch_iter += 1;
//
//         let fetched_paths = fetch(&paths_to_fetch);
//         sparse_trie_store.add_sparse_nodes_from_raw_proof(fetched_paths, paths_to_fetch.clone());
//         let mut trie = SparseMPT::with_sparse_store(sparse_trie_store.clone())
//             .expect("storage_trie is initialised");
//
//         paths_to_fetch.clear();
//
//         for update in &updates {
//             let result = match update {
//                 TrieUpdate::Update(path, value) => trie.insert(&path.pack(), &value),
//                 TrieUpdate::Delete(path) => trie.delete(&path.pack()),
//             };
//
//             match result {
//                 Ok(()) => {}
//                 Err(SparseTrieError::KeyNotFound) => {
//                     panic!("Key not found")
//                 }
//                 Err(SparseTrieError::NodeNotFound(NodeNotFound { path, .. })) => {
//                     paths_to_fetch.push(path);
//                 }
//                 Err(SparseTrieError::SparseStoreNotInitialised) => {
//                     unreachable!("sparse store must be initialised here")
//                 }
//             }
//         }
//
//         if paths_to_fetch.is_empty() {
//             return trie.root_hash();
//         }
//     }
// }
