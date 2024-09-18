use crate::utils::HashMap;
use alloy_primitives::keccak256;
use alloy_primitives::Bytes;
use alloy_primitives::B256;

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
}
