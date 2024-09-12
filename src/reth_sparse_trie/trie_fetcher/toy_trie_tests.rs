use super::*;
use crate::reth_sparse_trie::shared_cache::MissingNodes;
use crate::sparse_mpt::SparseTrieNodes;
use ahash::HashMap;
use alloy_primitives::{hex, keccak256, Bytes, B256, U256};
use alloy_rlp::Encodable;
use alloy_trie::{Nibbles, EMPTY_ROOT_HASH};
use reth::primitives::{Account, StorageEntry};
use reth::providers::test_utils::create_test_provider_factory;
use reth::providers::ProviderFactory;
use reth::providers::TrieWriter;
use reth_db::cursor::DbCursorRW;
use reth_db::database::Database;
use reth_db::tables;
use reth_db::transaction::DbTxMut;
use reth_provider::providers::ConsistentDbView;
use reth_trie::{StateRoot, TrieAccount};
use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};

#[derive(Debug)]
struct ToyTrieAccount {
    hashed_address: B256,
    account: Account,
    storage_keys: HashMap<B256, U256>,
}

fn toy_trie_accounts() -> Vec<ToyTrieAccount> {
    let mut result = Vec::new();

    {
        let storage_key1 = B256::new(hex!(
            "1000000000000000000000000000000000000000000000000000000000000000"
        ));
        let storage_value1 = U256::from(1u64);
        let storage_key2 = B256::new(hex!(
            "2000000000000000000000000000000000000000000000000000000000000000"
        ));
        let storage_value2 = U256::from(2u64);
        result.push(ToyTrieAccount {
            hashed_address: B256::new(hex!(
                "30af561000000000000000000000000000000000000000000000000000000000"
            )),
            account: Account {
                nonce: 0,
                balance: U256::from(1u64),
                bytecode_hash: Some(keccak256(&[0])),
            },
            storage_keys: vec![
                (storage_key1, storage_value1),
                (storage_key2, storage_value2),
            ]
            .into_iter()
            .collect(),
        });
    }
    result.push(ToyTrieAccount {
        hashed_address: B256::new(hex!(
            "30af569000000000000000000000000000000000000000000000000000000000"
        )),
        account: Account {
            nonce: 0,
            balance: U256::from(1u64),
            bytecode_hash: Some(keccak256(&[1])),
        },
        storage_keys: Default::default(),
    });
    result.push(ToyTrieAccount {
        hashed_address: B256::new(hex!(
            "30af650000000000000000000000000000000000000000000000000000000000"
        )),
        account: Account {
            nonce: 0,
            balance: U256::from(1u64),
            bytecode_hash: Some(keccak256(&[2])),
        },
        storage_keys: Default::default(),
    });
    result.push(ToyTrieAccount {
        hashed_address: B256::new(hex!(
            "30af6f0000000000000000000000000000000000000000000000000000000000"
        )),
        account: Account {
            nonce: 0,
            balance: U256::from(1u64),
            bytecode_hash: Some(keccak256(&[3])),
        },
        storage_keys: Default::default(),
    });
    result.push(ToyTrieAccount {
        hashed_address: B256::new(hex!(
            "30af8f0000000000000000000000000000000000000000000000000000000000"
        )),
        account: Account {
            nonce: 0,
            balance: U256::from(1u64),
            bytecode_hash: Some(keccak256(&[4])),
        },
        storage_keys: Default::default(),
    });
    result.push(ToyTrieAccount {
        hashed_address: B256::new(hex!(
            "3100000000000000000000000000000000000000000000000000000000000000"
        )),
        account: Account {
            nonce: 0,
            balance: U256::from(1u64),
            bytecode_hash: None,
        },
        storage_keys: Default::default(),
    });

    result
}

fn create_toy_trie<DB: Database>(provider_factory: ProviderFactory<DB>) -> B256 {
    let tx = provider_factory.provider_rw().unwrap();

    {
        let mut hashed_accounts = tx
            .tx_ref()
            .cursor_write::<tables::HashedAccounts>()
            .unwrap();

        for account in toy_trie_accounts() {
            hashed_accounts
                .upsert(account.hashed_address, account.account)
                .unwrap();
        }
    }

    {
        let mut hashed_storage_cursor = tx
            .tx_ref()
            .cursor_dup_write::<tables::HashedStorages>()
            .unwrap();
        for account in toy_trie_accounts() {
            for (key, value) in account.storage_keys {
                hashed_storage_cursor
                    .upsert(account.hashed_address, StorageEntry { key, value })
                    .unwrap();
            }
        }

        // StorageRoot::new()
    }

    let (root_hash, updates) = StateRoot::new(
        DatabaseTrieCursorFactory::new(tx.tx_ref()),
        DatabaseHashedCursorFactory::new(tx.tx_ref()),
    )
    .root_with_updates()
    .unwrap();
    tx.commit().unwrap();

    provider_factory
        .provider_rw()
        .unwrap()
        .write_trie_updates(&updates)
        .unwrap();

    root_hash
}

#[test]
fn test_toy_trie_hash_from_scratch() {
    let factory = create_test_provider_factory();
    let reference_root_hash = create_toy_trie(factory.clone());

    let mut trie = SparseTrieNodes::empty_trie();
    for account in toy_trie_accounts() {
        let mut storage_trie = SparseTrieNodes::empty_trie();
        for (storage_key, storage_value) in account.storage_keys {
            let value = alloy_rlp::encode(storage_value);
            storage_trie
                .insert(Bytes::copy_from_slice(storage_key.as_slice()), value.into())
                .unwrap();
        }
        let computed_storage_root_hash = storage_trie.root_hash().expect("storage trie hash");

        let key = Bytes::copy_from_slice(account.hashed_address.as_slice());
        let value = encode_account(account.account, Some(computed_storage_root_hash));

        trie.insert(key, value.into()).unwrap();
    }
    let got_root_hash = trie.root_hash().expect("account trie hash");
    assert_eq!(got_root_hash, reference_root_hash);
}

#[test]
fn fetch_multiproof() {
    let factory = create_test_provider_factory();
    let reference_root_hash = create_toy_trie(factory.clone());

    let consisent_db_view = ConsistentDbView::new_with_latest_tip(factory).unwrap();

    let fetcher = TrieFetcher::new(consisent_db_view);

    let account = toy_trie_accounts().remove(0);

    let account_path = Nibbles::unpack(account.hashed_address.as_slice());
    let missing_nodes = fetcher
        .fetch_missing_nodes(MissingNodes {
            account_trie_nodes: vec![account_path],
            storage_trie_nodes: Default::default(),
        })
        .expect("fetch error");

    let mut sparse_trie = SparseTrieNodes::uninit_trie();
    sparse_trie
        .add_nodes(missing_nodes.account_subtree.into_iter())
        .expect("must add nodes");

    let got_root_hash = sparse_trie.root_hash().expect("must hash");

    assert_eq!(got_root_hash, reference_root_hash);

    let got_root_hash = sparse_trie.root_hash().expect("must hash");

    assert_eq!(got_root_hash, reference_root_hash);
}

fn encode_account(account: Account, storage_root: Option<B256>) -> Vec<u8> {
    let account = TrieAccount::from((account, storage_root.unwrap_or(EMPTY_ROOT_HASH)));
    let mut account_rlp = Vec::with_capacity(account.length());
    account.encode(&mut account_rlp);
    account_rlp
}
