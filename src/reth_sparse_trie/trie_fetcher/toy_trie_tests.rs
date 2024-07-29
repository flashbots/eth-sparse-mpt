use crate::reth_sparse_trie::trie_fetcher::TrieFetcher;
use crate::sparse_mpt::SparseMPT;
use crate::utils::{pretty_print_trie_nodes, reference_trie_hash};
use ahash::HashMap;
use alloy_primitives::{hex, keccak256, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::nodes::TrieNode;
use alloy_trie::{HashBuilder, Nibbles, EMPTY_ROOT_HASH};
use reth::primitives::trie::TrieAccount;
use reth::primitives::{Account, StorageEntry};
use reth::providers::test_utils::create_test_provider_factory;
use reth::providers::ProviderFactory;
use reth_db::cursor::DbCursorRW;
use reth_db::database::Database;
use reth_db::tables;
use reth_db::transaction::DbTxMut;
use reth_trie::{StateRoot, StorageRoot};

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

    let (root_hash, updates) = StateRoot::from_tx(tx.tx_ref()).root_with_updates().unwrap();
    updates.flush(tx.tx_ref()).unwrap();

    tx.commit().unwrap();
    root_hash
}

#[test]
fn test_toy_trie_hash_from_scratch() {
    let factory = create_test_provider_factory();
    let reference_root_hash = create_toy_trie(factory.clone());

    let mut trie = SparseMPT::new_empty();
    for account in toy_trie_accounts() {
        let mut storage_trie = SparseMPT::new_empty();
        for (storage_key, storage_value) in account.storage_keys {
            let value = alloy_rlp::encode(storage_value);
            storage_trie.insert(storage_key.as_slice(), &value).unwrap();
        }
        let computed_storage_root_hash = storage_trie.root_hash();

        let key = account.hashed_address.as_slice();
        let value = encode_account(account.account, Some(computed_storage_root_hash));

        trie.insert(key, &value).unwrap();
    }
    let got_root_hash = trie.root_hash();
    assert_eq!(got_root_hash, reference_root_hash);
}

#[test]
fn test_print_toy_trie() {
    let factory = create_test_provider_factory();
    create_toy_trie(factory.clone());

    let tx = factory.db_ref().tx().unwrap();

    let trie_fetcher = TrieFetcher::new(&tx);

    let hashed_address = B256::new(hex!(
        "30af561000000000000000000000000000000000000000000000000000000000"
    ));
    //
    // let target = Nibbles::unpack(hashed_address);
    // let path = trie_fetcher.account_proof_path(target).unwrap();
    // print_path(&path);

    let slot1 = Nibbles::unpack(hex!(
        "1000000000000000000000000000000000000000000000000000000000000000"
    ));

    let (_, path) = trie_fetcher
        .storage_proof_paths(hashed_address, &[slot1])
        .unwrap();
    print_path(&path);
}

fn print_path(path: &[Vec<u8>]) {
    let mut node_path = Vec::new();
    for node in path {
        let node = TrieNode::decode(&mut node.as_slice()).unwrap();
        node_path.push(node);
    }
    pretty_print_trie_nodes(&node_path);
}

fn encode_account(account: Account, storage_root: Option<B256>) -> Vec<u8> {
    let account = TrieAccount::from((account, storage_root.unwrap_or(EMPTY_ROOT_HASH)));
    let mut account_rlp = Vec::with_capacity(account.length());
    account.encode(&mut account_rlp);
    account_rlp
}
