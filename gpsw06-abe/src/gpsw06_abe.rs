use rabe_bn::{self, Group};
// use ccm::{Ccm};
// use aes::Aes256;
// use ccm::aead::{self, Tag, AeadInPlace, Key, NewAead, generic_array::GenericArray};

use heapless::{FnvIndexMap, Vec, consts};
use rand::{Rng, RngCore};
use abe_utils::{kem, polynomial::Polynomial};
pub use abe_utils::access_tree::{AccessNode, AccessStructure, S as STree};

pub use ccm::aead::Error;

pub type S = consts::U32;

pub type G1 = rabe_bn::G2;
pub type G2 = rabe_bn::G1;
pub type Gt = rabe_bn::Gt;
pub type F = rabe_bn::Fr;

///
/// Differences to the original paper by Goyal, Pandey, Sahai and Waters:
/// - use of asymmetric pairing (G1 x G2 -> Gt instead of G1 x G1 -> G2)
///   - when decrypting, the leaf node secret shares are combined with that of the attribute 
///   - for less computational cost when encrypting, swap the pairing arguments in decryptNode
///   - i.e. the ciphertext's attributes are elements of G1, and the secret shares are elements of G2
///   - G1 has 96 Bytes, G2 has 192 Bytes and Gt 384 Bytes -> makes a big difference for runtimes and ciphertext size.
/// 
/// with G1 and G2 swapped (S = 16):
/// sizeof(GpswAbeCiphertext) = 2376
/// sizeof(GpswAbePrivate) = 40
/// sizeof(GpswAbePublic) = 680
/// sizeof(PrivateKey) = 3288
/// 
/// without swapping (S = 16):
/// sizeof(GpswAbeCiphertext) = 3912
/// sizeof(GpswAbePrivate) = 40
/// sizeof(GpswAbePublic) = 680
/// sizeof(PrivateKey) = 1752



/// Represents the full parameters of an ABE scheme, known in full only to the KGC
#[derive(Debug)]
pub struct GpswAbePrivate<'attr, 'own> {
  atts: &'own FnvIndexMap<&'attr str, F, S>,
  // pk: G,
  master_secret: F,
}
  
/// represents the public ABE parameters, known to all participants and used for encryption, decryption and the like
#[derive(Debug)]
pub struct GpswAbePublic<'attr, 'own> {
  g1: G1,
  g2: G2,
  atts: &'own FnvIndexMap<&'attr str, G2, S>,
  pk: Gt,
}
  
/// Represents a ciphertext as obtained by encrypt() and consumed by decrypt()
/// Contains both the actual (symetrically) encrypted data and all data required to reconstruct the 
/// symmetric keys given a private key created under a matching access structure.
#[derive(Debug, PartialEq, Eq)]
struct GpswAbeGroupCiphertext<'attr> {
  e: Gt, // actual encrypted group element
//   mac: Tag<aead::consts::U10>, // mac over the cleartext (TODO better encrypt-then-mac?)
//   nonce: [u8; 13],
  e_i: FnvIndexMap<&'attr str, G2, S>, // attributes and their respective curve elements
}

#[derive(Debug, PartialEq, Eq)]
pub struct GpswAbeCiphertext<'attr, 'data>(GpswAbeGroupCiphertext<'attr>, kem::Ciphertext<'data>);

/// Represents a private key obtained by keygen() and used to decrypt ABE-encrypted data
/// This data structure mirrors the recursive nature of access structures to ease implementation
/// of decryption. The secret shared (D_u in the original paper) allowing decryption are embedded
/// in the leaves of the tree.
//#[derive(Debug)]
pub struct PrivateKey<'attr, 'own>(AccessStructure<'attr, 'own>, FnvIndexMap<u8, G1, S>);

impl<'attr: 'es, 'es: 'key, 'key> GpswAbePrivate<'attr, 'es> {

    /// Corresponds to the `(A) Setup` phase in the original paper. Sets up an encryption scheme with a fixed set of attributes and 
    /// generates both public and private parameter structs. This is typically run exactly once by the KGC.
    pub fn setup(
      att_names: &[&'attr str],
      public_map: &'es mut FnvIndexMap<&'attr str, G2, S>,
      private_map: &'es mut FnvIndexMap<&'attr str, F, S>,
      rng: &mut dyn RngCore,
    ) -> (Self, GpswAbePublic<'attr, 'es>) 
    where 'attr: 'es
    {
        let master_secret: F = rng.gen(); // corresponds to "y" in the original paper
        let g1: G1 = rng.gen();
        let g2: G2 = rng.gen();
        
        // for each attribute, choose a private field element s_i and make G * s_i public
        for attr in att_names {
            let si: F = rng.gen();
            let mut gi = g2 * si;
            gi.normalize();
            private_map.insert(attr, si).unwrap();
            public_map.insert(attr, gi).unwrap();
      }
      
      let pk = rabe_bn::pairing(g2, g1).pow(master_secret); // master public key, corresponds to `PK`
  
      (
        GpswAbePrivate {
            atts: private_map,
            // pk,
            master_secret,
        },
        GpswAbePublic {
            g1,
            g2,
            atts: public_map,
            pk,
        })
    }


  /// Generate a private key for a given access structure, which allows a user holding the key to decrypt a ciphertext iff its 
  /// attributes satisfy the given access structure.
  pub fn keygen(
    &self,
    pubkey: &GpswAbePublic,
    access_structure: AccessStructure<'attr, 'key>,
    rng: &mut dyn RngCore,
  ) ->
    PrivateKey<'attr, 'key>
  where 'es: 'key
  { 
    let tuple_arr = self.keygen_node(
      pubkey,
      &access_structure,
      0,
      &Polynomial::randgen(self.master_secret, 1, rng),
      F::zero(), // this is the only node ever to have index 0, all others have index 1..n
      rng,
    );
    return PrivateKey(access_structure, tuple_arr.into_iter().collect());
  }

  /// internal recursive helper to ease key generation
  fn keygen_node (&self,
    pubkey: &GpswAbePublic,
    tree_arr: AccessStructure<'key, 'key>,
    tree_ptr: u8,
    parent_poly: &Polynomial,
    index: F,
    rng: &mut dyn RngCore,
  ) ->
    Vec<(u8, G1), consts::U30>
  {
    // own polynomial at x = 0. Exactly q_parent(index).
    let q_of_zero = parent_poly.eval(index);
    let own_node = &tree_arr[tree_ptr as usize];
    match own_node {
      AccessNode::Leaf(attr_name) => {
        // terminate recursion, embed secret share in the leaf
        let q_of_zero = parent_poly.eval(index);
        let t = self.atts.get(*attr_name).unwrap();
        let t_inv = t.inverse().unwrap();
        return Vec::from_slice(&[(tree_ptr, pubkey.g1 * (q_of_zero * t_inv))]).unwrap();
      },
      AccessNode::Node(thresh, children) => {
        // continue recursion, call recursively for all children and return a key node that contains children's key subtrees
        let own_poly = Polynomial::randgen(q_of_zero, thresh.clone(), rng); // `thres`-degree polynomial determined by q_of_zero and `thresh` random coefficients
        let children_res: Vec<(u8, G1), consts::U30> = children.iter().enumerate().
          map(|(i, child_ptr)| self.keygen_node(pubkey, tree_arr, *child_ptr, &own_poly, F::from((i+1) as u64), rng))
          .flatten()
          .collect();
        return children_res;
      }
    }
  }
}


impl<'data, 'key, 'es, 'attr> GpswAbePublic<'attr, 'es> {

    /// Encrypt a plaintext under a set of attributes so that it can be decrypted only with a matching key
    /// TODO for now this does not actually encrypt any data. It just generates a random curve element c_prime (whose
    /// coordinates would be used as encryption and message authentication key), which is then reconstructible under a 
    /// matching key.
    /// This is the only part of our cryptosystem that needs to run on the Cortex M4 in the end.
    
    pub fn encrypt(
      &self,
      atts: &[&'attr str],
      data: &'data mut [u8],
      rng: &mut dyn RngCore,
    ) -> Result<GpswAbeCiphertext<'attr, 'data>, ()>
    where 'attr: 'es, 'es: 'key, 'key: 'data
    {
      let gt: Gt = rng.gen();
      let payload_ciphertext = match kem::encrypt(&gt, data, rng) {
        Ok(c) => c,
        Err(_) => return Err(())
      };
      let key_encapsulation = self.encrypt_group_element(atts, gt, rng)?;
      Ok(GpswAbeCiphertext(key_encapsulation, payload_ciphertext))
    }

    fn encrypt_group_element(
        &self,
        atts: &[&'attr str],
        data: Gt,
        rng: &mut dyn RngCore,
    ) -> Result<GpswAbeGroupCiphertext<'attr>, ()>
    where 'attr: 'es, 'es: 'key, 'key: 'data
    {
      // choose a C', which is then used to encrypt the actual plaintext with a symmetric cipher
        let s: F = rng.gen();

        let mut att_cs: FnvIndexMap<&str, G2, S> = FnvIndexMap::new();
        
        let c = data * self.pk.pow(s);

        for att_name in atts {
            let t_i = self.atts.get(att_name).unwrap();
            att_cs.insert(att_name, *t_i * s).unwrap();
        }
        Ok(GpswAbeGroupCiphertext {
            e: c,
            e_i: att_cs,
        })
    }


  /// Recursive helper function for decryption
  fn decrypt_node(
    tree_arr: AccessStructure<'attr, 'key>,
    tree_ptr: u8,
    secret_shares: &FnvIndexMap<u8, G1, S>,
    att_es: &FnvIndexMap<& 'attr str, G2, S>
  ) -> Option<Gt> 
  where 'attr: 'es, 'es: 'key, 'key: 'data
  {
    let own_node = &tree_arr[tree_ptr as usize];
    match own_node {
      AccessNode::Leaf(name) => {
        // terminate recursion - we have reached a leaf node containing a secret share. Encryption can only be successful if
        // the matching remaining part of the secret is embedded within the ciphertext (that is the case iff the ciphertext
        // was encrypted under the attribute that our current Leaf node represents)
        let d_u = match secret_shares.get(&tree_ptr) {
          None => return None,
          Some(d_u) => d_u,
        };
        match att_es.get(name) {
          None => return None,
          Some(e_i) => return Some(rabe_bn::pairing(*e_i, *d_u)),
        }
      },
      AccessNode::Node(thresh, children) => {
        // continue recursion - call for all children and then, if enough children decrypt successfully, reconstruct the secret share for 
        // this intermediate node.
        let pruned = match abe_utils::access_tree::prune_dec(tree_arr, tree_ptr, att_es) {
          Some((_, children)) => children,
          None => return None,
        };

        // std::println!("pruned at {}: {:?}", tree_ptr, pruned);
        let children_result: Vec<(F, Gt), S> = pruned.into_iter()
          .map(|i| (F::from((i) as u64), Self::decrypt_node(tree_arr, children[(i-1) as usize], secret_shares, att_es))) // node indexes start at one, enumerate() starts at zero! 
          .filter_map(|(i, x)| match x { None => None, Some(y) => Some((i, y))}) // filter out all children that couldn't decrypt because of missing ciphertext secret shares
          .collect();

        // std::println!("children_result: {:?}", children_result);
        // we can only reconstruct our secret share if at least `thresh` children decrypted successfully (interpolation of `thresh-1`-degree polynomial)
        if children_result.len() < *thresh as usize { return None }
        // an arbitrary subset omega with |omega| = thresh is enough to reconstruct the secret. To make it easy, we just take the first `thresh` in our list.
        let relevant_children: Vec<(F, Gt), STree> = children_result.into_iter().take(*thresh as usize).collect();
        let relevant_indexes: Vec<F, STree> = relevant_children.iter()
          .map(|(i, _)| i.clone()).collect(); // our langrange helper function wants this vector of field elements
        let result: Gt = relevant_children.into_iter()
          .map(|(i, dec_res)| { dec_res.pow(Polynomial::lagrange_of_zero(&i, &relevant_indexes)) } )
          .fold(Gt::one(), |acc, g| g * acc);
        // //println!("node got result: {:?}\n at node {:?}\n", result, key);
        return Some(result);
      }
    }
  }


  /// Decrypt a ciphertext using a given private key. At this point, doesn't actually do any decryption, it just reconstructs the point used as encryption/mac key.
  fn decrypt_group_element(
    ciphertext: &GpswAbeGroupCiphertext<'attr>,
    key: &PrivateKey<'attr, 'key>,
  ) -> Result<Gt, ()>
  where 'attr: 'es, 'es: 'key, 'key: 'data
  {
    let PrivateKey(access_structure, secret_shares) = key;

    let res = Self::decrypt_node(&access_structure, 0, &secret_shares, &ciphertext.e_i);
    let y_to_s = match res {
      None => return Err(()),
      Some(p) => p,
    };
    Ok(ciphertext.e * y_to_s.inverse())
  }

  pub fn decrypt(
    ciphertext: GpswAbeCiphertext<'attr, 'data>, key: &PrivateKey<'attr, 'key>
  ) -> Result<&'data [u8], GpswAbeCiphertext<'attr, 'data>>
  where 'attr: 'es, 'es: 'key, 'key: 'data
  {
    let gt = match Self::decrypt_group_element(&ciphertext.0, key) {
      Ok(gt) => gt,
      Err(_) => return Err(ciphertext),
    };
    match kem::decrypt(&gt, ciphertext.1) {
      Ok(data) => return Ok(data),
      Err(ct) => return Err(GpswAbeCiphertext(ciphertext.0, ct)), // reconstruct the same ciphertext again
    };
  }
}


#[cfg(test)]
mod tests {
  extern crate std;
  use super::*;

  #[test]
  fn leaf_only_access_tree() {
    let mut access_structure_vec: Vec<AccessNode, consts::U64> = Vec::new();
    access_structure_vec.push(AccessNode::Leaf("student")).unwrap();
    let access_structure = &access_structure_vec[..];

    let mut public_map: FnvIndexMap<&str, G2, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, F, S> = FnvIndexMap::new();

    let mut rng = rand::thread_rng();
    let mut plaintext_original = [0; 8192];
    rng.fill_bytes(&mut plaintext_original);
    let mut plaintext = plaintext_original.clone();

    let attributes_1: Vec<&str, consts::U64> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let attributes_2: Vec<&str, consts::U64> = Vec::from_slice(&["tum", "over21"]).unwrap();

    let system_atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let (private, public) = GpswAbePrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    // println!("private map: {:?}", private);
    let priv_key = private.keygen(&public, &access_structure, &mut rng);


    let ciphertext =  public.encrypt(&attributes_1, &mut plaintext, &mut rng).unwrap();
    
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key).unwrap();  

    assert_eq!(plaintext_original, res);

    let mut plaintext = plaintext_original.clone();

    let ciphertext = public.encrypt(&attributes_2, &mut plaintext, &mut rng).unwrap();
    let _res = GpswAbePublic::decrypt(ciphertext, &priv_key).unwrap_err();
    // assert_ne!(res.1.data, plaintext_original);
  }


  #[test]
  fn flat_access_tree() {

    let access_structure: AccessStructure = &[
      AccessNode::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
      AccessNode::Leaf("tum"),
      AccessNode::Leaf("student"),
      AccessNode::Leaf("has_bachelor"),
      AccessNode::Leaf("over21"),
    ];


    let attributes_1 = &["student", "tum", "has_bachelor", "over21"][..];
    let attributes_2 = &["tum"][..];

    let mut public_map: FnvIndexMap<&str, G2, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, F, S> = FnvIndexMap::new();

    let mut rng = rand::thread_rng();
    let mut plaintext_original = [0; 8192];
    rng.fill_bytes(&mut plaintext_original);
    
    let system_atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();


    let (es, public) = GpswAbePrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    //println!("{:#?}", es);
    //println!("\n public params:\n{:#?}", public);
  
      
  
    let priv_key = es.keygen(&public, &access_structure, &mut rng);
    //println!("private key:\n{:?}", priv_key)

    let mut plaintext = plaintext_original.clone();
  
    let ciphertext = public.encrypt(&attributes_1, &mut plaintext, &mut rng).unwrap();
  
    // println!("ciphertext:\n{:?}", ciphertext);
    
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key).unwrap();
    
    assert_eq!(plaintext_original, res);
    
    // failing decryption
    let mut plaintext = plaintext_original.clone();
    let ciphertext = public.encrypt(&attributes_2, &mut plaintext, &mut rng).unwrap();
    let _res = GpswAbePublic::decrypt(ciphertext, &priv_key).unwrap_err();
    // assert_eq!(Err(()), res);
  }


  #[test]
  fn deep_access_tree() {
    let mut public_map: FnvIndexMap<&str, G2, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, F, S> = FnvIndexMap::new();
    
    let mut rng = rand::thread_rng();

    let mut plaintext_original = [0; 8192];
    rng.fill_bytes(&mut plaintext_original);

    let system_atts = ["student", "tum", "over21", "over25", "has_bachelor", "cs"];
    let (es, public) = GpswAbePrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    
    let attributes = &["student", "tum"][..];
    let mut plaintext = plaintext_original.clone();
    let ciphertext = public.encrypt(&attributes, &mut plaintext, &mut rng).unwrap();

    // this represents the following logical access structure:
    // (tum AND student) OR (cs AND has_bachelor AND (over21 OR over25))
    let access_structure: AccessStructure = &[
      AccessNode::Node(1, Vec::from_slice(&[1, 2]).unwrap()), // 0
      AccessNode::Node(2, Vec::from_slice(&[3, 4]).unwrap()), // 1
      AccessNode::Node(3, Vec::from_slice(&[5, 6, 7]).unwrap()),// 2
      AccessNode::Leaf("student"),                            // 3
      AccessNode::Leaf("tum"),                                // 4
      AccessNode::Leaf("cs"),                                 // 5
      AccessNode::Leaf("has_bachelor"),                       // 6
      AccessNode::Node(1, Vec::from_slice(&[8, 9]).unwrap()), // 7
      AccessNode::Leaf("over21"),                             // 8
      AccessNode::Leaf("over25"),                             // 9
    ];


    let priv_key = es.keygen(&public, &access_structure, &mut rng);
    //println!("private key:\n{:?}", priv_key);
  

    // example 1 - shall decrypt (defined above)
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key).unwrap();
    assert_eq!(plaintext_original, res);

    // example 2 - shall decrypt 
    let mut plaintext = plaintext_original.clone();
    let attributes = &["student", "has_bachelor", "cs", "over21"][..];
    let ciphertext = public.encrypt(&attributes, &mut plaintext, &mut rng).unwrap();
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key).unwrap();
    assert_eq!(plaintext_original, res);
    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    // assert_eq!(decrypted, data);

    // example 2 - shall not decrypt 
    let mut plaintext = plaintext_original.clone();
    let attributes = &["student", "cs", "over21"][..];
    let ciphertext = public.encrypt(&attributes, &mut plaintext, &mut rng).unwrap();
    let _res = GpswAbePublic::decrypt(ciphertext, &priv_key).unwrap_err();
    // assert_eq!(Err(()), res);
    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key);
    // assert_eq!(None, decrypted);
  }
}