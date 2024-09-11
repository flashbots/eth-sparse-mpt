use ahash::HashMap;
use alloy_primitives::keccak256;
use alloy_primitives::Bytes;
use alloy_primitives::B256;
use alloy_rlp::Encodable;

use super::*;

fn update_node_with_calculated_dirty_children(
    node: &mut SparseTrieNode,
    mut dirty_branches: impl Iterator<Item = Bytes>,
) {
    match &mut node.kind {
        SparseTrieNodeKind::ExtensionNode(ext) => {
            let child_ptr = dirty_branches.next().expect("must have ext child");
            ext.child.rlp_pointer = child_ptr;
            ext.child.rlp_pointer_dirty = false;
        }
        SparseTrieNodeKind::BranchNode(branch) => {
            for child in branch.children.iter_mut() {
                if let Some(child) = child {
                    if child.rlp_pointer_dirty {
                        child.rlp_pointer = dirty_branches.next().expect("must have branch child");
                        child.rlp_pointer_dirty = false;
                    }
                }
            }
        }
        SparseTrieNodeKind::NullNode | SparseTrieNodeKind::LeafNode(_) => unreachable!(),
    }
}

type HashCache = HashMap<SparseTrieNodeKind, Bytes>;

impl SparseTrieNodes {
    pub fn root_hash(&mut self) -> Result<B256, SparseTrieError> {
        // self.root_hash_advanced(false, None).map(|(h, _)| h)
        self.root_hash_no_recursion(None)
    }

    pub fn root_hash_no_recursion(
        &mut self,
        mut hash_cache: Option<&mut HashCache>,
    ) -> Result<B256, SparseTrieError> {
        struct WaitStack {
            node: Nibbles,
            stack_before: usize,
            need_elements: usize,
        }

        let mut task_stack: Vec<Nibbles> = vec![Nibbles::new()];
        let mut wait_stack: Vec<WaitStack> = Vec::new();
        let mut result_stack: Vec<Bytes> = Vec::new();

        fn push_result_value<'a>(
            node: &mut SparseTrieNode,
            result_stack: &mut Vec<Bytes>,
            mut hash_cache: Option<&'a mut HashCache>,
        ) -> Option<&'a mut HashCache> {
            if let Some(cache) = &mut hash_cache {
                result_stack.push(node.rlp_pointer_cached(cache));
            } else {
                result_stack.push(node.rlp_pointer());
            }
            return hash_cache;
        }

        while let Some(current_node) = task_stack.pop() {
            let node = self.try_get_node_mut(&current_node)?;

            match &mut node.kind {
                SparseTrieNodeKind::NullNode | SparseTrieNodeKind::LeafNode(_) => {
                    hash_cache = push_result_value(node, &mut result_stack, hash_cache);
                }
                SparseTrieNodeKind::ExtensionNode(extension) => {
                    if node.rlp_pointer_dirty && extension.child.rlp_pointer_dirty {
                        let child_path = extension.child_path(&current_node);
                        wait_stack.push(WaitStack {
                            node: current_node,
                            stack_before: result_stack.len(),
                            need_elements: 1,
                        });
                        task_stack.push(child_path);
                    } else {
                        hash_cache = push_result_value(node, &mut result_stack, hash_cache);
                    }
                }
                SparseTrieNodeKind::BranchNode(branch_node) => {
                    if node.rlp_pointer_dirty {
                        let mut need_elements = 0;
                        for (n, child) in branch_node.children.iter().enumerate() {
                            if let Some(child) = child {
                                if child.rlp_pointer_dirty {
                                    need_elements += 1;
                                    let child_path = BranchNode::child_path(&current_node, n as u8);
                                    task_stack.push(child_path);
                                }
                            }
                        }

                        if need_elements == 0 {
                            hash_cache = push_result_value(node, &mut result_stack, hash_cache);
                        } else {
                            wait_stack.push(WaitStack {
                                node: current_node,
                                stack_before: result_stack.len(),
                                need_elements,
                            });
                        }
                    } else {
                        hash_cache = push_result_value(node, &mut result_stack, hash_cache);
                    }
                }
            }

            loop {
                let wait = if let Some(w) = wait_stack.last() {
                    if result_stack.len() < w.need_elements + w.stack_before {
                        break;
                    }
                    wait_stack.pop().unwrap()
                } else {
                    break;
                };
                let node = self.try_get_node_mut(&wait.node)?;
                let idx = result_stack.len() - wait.need_elements;
                update_node_with_calculated_dirty_children(node, result_stack.drain(idx..).rev());

                hash_cache = push_result_value(node, &mut result_stack, hash_cache);
            }
        }

        assert!(task_stack.is_empty());
        assert!(wait_stack.is_empty());
        assert_eq!(result_stack.len(), 1);

        let root_node = Nibbles::new();
        let root_node = self.try_get_node(&root_node)?;
        let mut tmp_result = Vec::new();
        root_node.encode(&mut tmp_result);
        Ok(keccak256(&tmp_result))
    }

    pub fn root_hash_advanced(
        &mut self,
        rehash_all: bool,
        hash_cache: Option<&mut HashMap<SparseTrieNodeKind, Bytes>>,
    ) -> Result<(B256, usize), SparseTrieError> {
        // @todo do without recursion and not hash map allocation
        let mut updates = HashMap::default();
        let root_node = Nibbles::new();
        self.update_rlp_pointers(root_node.clone(), &mut updates, rehash_all, hash_cache)?;
        let updated_nodes = updates.len();
        for (path, updated) in updates {
            self.nodes.insert(path, updated);
        }
        let root_node = self.try_get_node(&root_node)?;
        let mut tmp_result = Vec::new();
        root_node.encode(&mut tmp_result);
        Ok((keccak256(&tmp_result), updated_nodes))
    }

    fn update_rlp_pointers<'a>(
        &self,
        node_path: Nibbles,
        updates: &mut HashMap<Nibbles, SparseTrieNode>,
        rehash_all: bool,
        mut hash_cache: Option<&'a mut HashMap<SparseTrieNodeKind, Bytes>>,
    ) -> Result<Option<&'a mut HashMap<SparseTrieNodeKind, Bytes>>, SparseTrieError> {
        let node = self.try_get_node(&node_path)?;
        if !node.rlp_pointer_dirty && !rehash_all {
            return Ok(hash_cache);
        }

        let mut new_node = node.clone();

        match &mut new_node.kind {
            SparseTrieNodeKind::NullNode => {}
            SparseTrieNodeKind::LeafNode(_) => {}
            SparseTrieNodeKind::ExtensionNode(ext) => {
                if ext.child.rlp_pointer_dirty || rehash_all {
                    let child_path = ext.child_path(&node_path);

                    let skip_child = rehash_all
                        && !self.nodes.contains_key(&child_path)
                        && !ext.child.rlp_pointer_dirty;

                    if !skip_child {
                        hash_cache = self.update_rlp_pointers(
                            child_path.clone(),
                            updates,
                            rehash_all,
                            hash_cache,
                        )?;
                        let updated_child = if let Some(updated_child) = updates.get(&child_path) {
                            assert!(!updated_child.rlp_pointer_dirty);
                            updated_child.rlp_pointer.clone()
                        } else {
                            let child_in_trie = self.try_get_node(&child_path)?;
                            assert!(
                                !child_in_trie.rlp_pointer_dirty,
                                "update must happen or child should be not dirty"
                            );
                            child_in_trie.rlp_pointer.clone()
                        };
                        ext.child.rlp_pointer = updated_child;
                        ext.child.rlp_pointer_dirty = false;
                    }
                }
            }
            SparseTrieNodeKind::BranchNode(branch) => {
                for (idx, child) in branch.children.iter_mut().enumerate() {
                    let child = if let Some(child) = child {
                        child
                    } else {
                        continue;
                    };
                    if !child.rlp_pointer_dirty && !rehash_all {
                        continue;
                    }
                    let child_path = BranchNode::child_path(&node_path, idx as u8);
                    let skip_child = rehash_all
                        && !self.nodes.contains_key(&child_path)
                        && !child.rlp_pointer_dirty;
                    if !skip_child {
                        hash_cache = self.update_rlp_pointers(
                            child_path.clone(),
                            updates,
                            rehash_all,
                            hash_cache,
                        )?;
                        let updated_child = if let Some(updated_child) = updates.get(&child_path) {
                            assert!(!updated_child.rlp_pointer_dirty);
                            updated_child.rlp_pointer.clone()
                        } else {
                            let child_in_trie = self.try_get_node(&child_path)?;
                            assert!(
                                !child_in_trie.rlp_pointer_dirty,
                                "update must happen or child should be not dirty"
                            );
                            child_in_trie.rlp_pointer.clone()
                        };
                        child.rlp_pointer = updated_child;
                        child.rlp_pointer_dirty = false;
                    }
                }
            }
        };
        if let Some(cache) = &mut hash_cache {
            let value = if let Some(cached) = cache.get(&new_node.kind) {
                cached.clone()
            } else {
                let value = new_node.rlp_pointer();
                cache.insert(new_node.kind.clone(), value.clone());
                value
            };
            new_node.rlp_pointer = value;
            new_node.rlp_pointer_dirty = false;
        } else {
            new_node.rlp_pointer();
            new_node.rlp_pointer_dirty = false;
        }
        updates.insert(node_path, new_node);
        Ok(hash_cache)
    }
}
