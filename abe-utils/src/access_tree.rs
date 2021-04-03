use heapless::{self, Vec, consts, FnvIndexMap};

pub type S = consts::U8;

pub type SSystem = consts::U32;

/// represents nodes of the access tree
/// 
/// This is passed to keygen() by the KGC, and then embedded in the private key issued to the user.
#[derive(Debug)]
pub enum AccessNode<'attr> {
  Node(u64, Vec<u8, S>), // threshold, children
  Leaf(&'attr str),
}

/// Represents an access structure defined as a threshold-tree
/// 
// Implementation: Array of 256 AccessNodes, the first one is the root
// size of this is 10248 bytes (!)
// pub type AccessStructure<'a> = Vec<AccessNode<'a>, consts::U256>; 
pub type AccessStructure<'attr, 'own> = &'own [AccessNode<'attr>];


/// Pre-calculates a minimal subset of attributes that satisfies a subtree
/// 
/// This is used during decryption to eliminate unnecessary pairing evaluations. 
/// Goes through the tree and figures out a subset of the tree that can be satisfied by the given attributes while requiring the least number of leaf nodes.
/// This reduces the number of pairings to a minimum and also reduces the degree of interpolated polynomials (i.e. speeds up lagrange).
pub fn prune_dec<'attr, 'key, T> (
    tree_arr: AccessStructure<'attr, 'key>,
    tree_ptr: u8,
    att_es: &FnvIndexMap<& 'attr str, T, SSystem>,
  ) -> Option<(u8, Vec<u8, SSystem>)>
  where 'attr: 'key
  {
    let own_node = &tree_arr[tree_ptr as usize];
    match own_node {
      AccessNode::Leaf(name) => {
        // terminate recursion - we have reached a leaf node containing a secret share. Encryption can only be successful if
        // the matching remaining part of the secret is embedded within the ciphertext (that is the case iff the ciphertext
        // was encrypted under the attribute that our current Leaf node represents)
        match att_es.get(name) {
          Some(_) => Some((1, Vec::from_slice(&[0]).unwrap())),
          None => None,
        }
      },
      AccessNode::Node(thresh, children) => {
        // continue recursion - call for all children and then, if enough children decrypt successfully, reconstruct the secret share for 
        // this intermediate node.

        // this contains tuples (index, no. of pairings required) for each child node that is satisfied
        let mut children_result: Vec<(u8, u8), S> = children.into_iter().enumerate()
          .filter_map(|(index, child_ptr)| match prune_dec(tree_arr, *child_ptr, att_es) { Some((pairings, _)) => Some(((index + 1) as u8, pairings)), None => None })
          .collect();
        // we can only reconstruct our secret share if at least `thresh` children decrypted successfully (interpolation of `thresh-1`-degree polynomial)
        if children_result.len() < *thresh as usize { return None }
        // an arbitrary subset omega with |omega| = thresh is enough to reconstruct the secret. We choose that with the minimal number of pairings
        children_result[..].sort_unstable_by(|(_, n1), (_, n2)| n1.partial_cmp(n2).unwrap());
        let relevant_children: Vec<(u8, u8), S> = children_result.into_iter().take(*thresh as usize).collect();
        return Some((relevant_children.iter().map(|(_, p) | p).sum(), relevant_children.iter().map(|(i, _)| *i).collect()));
      }
    }
  }