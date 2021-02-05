use rabe_bn::{self, Group};
use ccm::{Ccm};
use aes::Aes256;
use ccm::aead::{self, Tag, AeadInPlace, Key, NewAead, generic_array::GenericArray};

use heapless::{IndexMap, FnvIndexMap, Vec, consts};
use rand::{Rng, RngCore};

pub use ccm::aead::Error;

pub type S = consts::U16;

pub type G1 = rabe_bn::G1;
pub type G2 = rabe_bn::G2;
pub type Gt = rabe_bn::Gt;
pub type F = rabe_bn::Fr;


/// Represents the full parameters of an ABE scheme, known in full only to the KGC
#[derive(Debug)]
pub struct GpswAbePrivate<'attr, 'own> {
    g1: G1, 
    g2: G2,
    atts: &'own FnvIndexMap<&'attr str, (F, G2), S>,
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
    
  /// represents an access structure that defines the powers of a key.
  /// This is passed to keygen() by the KGC, and then embedded in the private key issued to the user.
  #[derive(Debug)]
  pub enum AccessNode<'attr> {
    Node(u64, Vec<u8, consts::U16>), // threshold, children
    Leaf(&'attr str),
  }


/// Represents an access structure defined as a threshold-tree
// Implementation: Array of 256 AccessNodes, the first one is the root
// size of this is 10248 bytes (!)
// pub type AccessStructure<'a> = Vec<AccessNode<'a>, consts::U256>; 
pub type AccessStructure<'attr, 'own> = &'own [AccessNode<'attr>];

/// Represents a ciphertext as obtained by encrypt() and consumed by decrypt()
/// Contains both the actual (symetrically) encrypted data and all data required to reconstruct the 
/// symmetric keys given a private key created under a matching access structure.
// #[derive(Debug)]
pub struct GpswAbeGroupCiphertext<'attr> {
  e: Gt, // actual encrypted group element
//   mac: Tag<aead::consts::U10>, // mac over the cleartext (TODO better encrypt-then-mac?)
//   nonce: [u8; 13],
  e_i: FnvIndexMap<&'attr str, G2, S>, // attributes and their respective curve elements
}


/// Represents a private key obtained by keygen() and used to decrypt ABE-encrypted data
/// This data structure mirrors the recursive nature of access structures to ease implementation
/// of decryption. The secret shared (D_u in the original paper) allowing decryption are embedded
/// in the leaves of the tree.
//#[derive(Debug)]
pub struct PrivateKey<'attr, 'own>(AccessStructure<'attr, 'own>, FnvIndexMap<u8, G1, consts::U64>);

/// Polynomial p(x) = a0 + a1 * x + a2 * x^2 + ... defined by a vector of coefficients [a0, a1, a2, ...]
//#[derive(Debug)]
struct Polynomial(Vec<F, consts::U16>);

impl Polynomial {
  /// Evaluates the polynomial p(x) at a given x
  fn eval(&self, x: F) -> F {
    self.0.iter().rev().fold(F::zero(), |acc, c| *c + (x * acc))
  }

  /// Generates a random polynomial p(x) of degree `coeffs` coefficients, where p(0) = `a0`
  fn randgen(a0: F, coeffs: u64, mut rng: &mut dyn RngCore) -> Polynomial {
    let mut coefficients: Vec<F, consts::U16> = Vec::from_slice(&[a0]).unwrap();
    coefficients.extend((1..coeffs).map(|_| -> F { rng.gen() }));
    assert_eq!(coefficients.len() as u64, coeffs);
    Polynomial(coefficients)
  }

  /// Calculates the langrage base polynomials l_i(x) for given set of indices omega and the index i.
  /// As we only ever need to interpolate p(0), no value for x may be passed.
  fn lagrange_of_zero(i: &F, omega: &Vec<F, consts::U16>) -> F {
    //println!("LAGRANGE: {:?}\n{:?}", i, omega);
    let r = omega.iter()
      .filter(|x| *x != i)
      // .map(|x| { println!("{:?}", x); x} )
      .map(|j| -*j * (*i-*j).inverse().unwrap())
      .fold(F::one(), |acc, x| acc * x);
    //println!("\n");
    r
  }
}


impl<'attr: 'es, 'es: 'key, 'key> GpswAbePrivate<'attr, 'es> {

    /// Corresponds to the `(A) Setup` phase in the original paper. Sets up an encryption scheme with a fixed set of attributes and 
    /// generates both public and private parameter structs. This is typically run exactly once by the KGC.
    pub fn setup(
      att_names: &[&'attr str],
      public_map: &'es mut FnvIndexMap<&'attr str, G2, S>,
      private_map: &'es mut FnvIndexMap<&'attr str, (F, G2), S>,
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
            private_map.insert(attr, (si, gi)).unwrap();
            public_map.insert(attr, gi).unwrap();
      }
      
      let pk = rabe_bn::pairing(g1, g2).pow(master_secret); // master public key, corresponds to `PK`
  
      (
        GpswAbePrivate {
            g1,
            g2,
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
    access_structure: AccessStructure<'attr, 'key>,
    rng: &mut dyn RngCore,
  ) ->
    PrivateKey<'attr, 'key>
  where 'es: 'key
  { 
    println!("master secret: {:?}", self.master_secret);
    let tuple_arr = self.keygen_node(
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
    tree_arr: AccessStructure<'key, 'key>,
    tree_ptr: u8,
    parent_poly: &Polynomial,
    index: F,
    rng: &mut dyn RngCore,
  ) ->
    Vec<(u8, G1), consts::U64>
  {
    // own polynomial at x = 0. Exactly q_parent(index).
    let q_of_zero = parent_poly.eval(index);
    println!("q_of_zero: {:?}", q_of_zero);
    let own_node = &tree_arr[tree_ptr as usize];
    match own_node {
      AccessNode::Leaf(attr_name) => {
        // terminate recursion, embed secret share in the leaf
        let q_of_zero = parent_poly.eval(index);
        println!("q_of_zero: {:?}", q_of_zero);
        let (t, _) = self.atts.get(*attr_name).unwrap();
        println!("t: {:?}", t);
        let t_inv = t.inverse().unwrap();
        return Vec::from_slice(&[(tree_ptr, self.g1 * (q_of_zero * t_inv))]).unwrap();
      },
      AccessNode::Node(thresh, children) => {
        // continue recursion, call recursively for all children and return a key node that contains children's key subtrees
        let own_poly = Polynomial::randgen(q_of_zero, thresh.clone(), rng); // `thres`-degree polynomial determined by q_of_zero and `thresh` random coefficients
        let children_res: Vec<(u8, G1), consts::U64> = children.iter().enumerate().
          map(|(i, child_ptr)| self.keygen_node(tree_arr, *child_ptr, &own_poly, F::from((i+1) as u64), rng))
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
    secret_shares: &FnvIndexMap<u8, G1, consts::U64>,
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
          Some(e_i) => return Some(rabe_bn::pairing(*d_u, *e_i)),
        }
      },
      AccessNode::Node(thresh, children) => {
        // continue recursion - call for all children and then, if enough children decrypt successfully, reconstruct the secret share for 
        // this intermediate node.
        let children_result: Vec<(F, Gt), consts::U16> = children.into_iter().enumerate()
          .map(|(i, child_ptr)| (F::from((i + 1) as u64), Self::decrypt_node(tree_arr, *child_ptr, secret_shares, att_es))) // node indexes start at one, enumerate() starts at zero! 
          .filter_map(|(i, x)| match x { None => None, Some(y) => Some((i, y))}) // filter out all children that couldn't decrypt because of missing ciphertext secret shares
          .collect();
        // we can only reconstruct our secret share if at least `thresh` children decrypted successfully (interpolation of `thresh-1`-degree polynomial)
        if children_result.len() < *thresh as usize { return None }
        // an arbitrary subset omega with |omega| = thresh is enough to reconstruct the secret. To make it easy, we just take the first `thresh` in our list.
        let relevant_children: Vec<(F, Gt), consts::U16> = children_result.into_iter().take(*thresh as usize).collect();
        let relevant_indexes: Vec<F, consts::U16> = relevant_children.iter()
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
  pub fn decrypt(
    ciphertext: GpswAbeGroupCiphertext<'attr>,
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
    let mut private_map: FnvIndexMap<&str, (F, G2), S> = FnvIndexMap::new();

    let mut rng = rand::thread_rng();
    let plaintext: Gt = rng.gen();

    let attributes_1: Vec<&str, consts::U64> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let attributes_2: Vec<&str, consts::U64> = Vec::from_slice(&["tum", "over21"]).unwrap();

    let system_atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let (private, public) = GpswAbePrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    println!("private map: {:?}", private);
    let priv_key = private.keygen(&access_structure, &mut rng);


    let ciphertext =  public.encrypt(&attributes_1, plaintext, &mut rng).unwrap();
    
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key);  

    assert_eq!(Ok(plaintext), res);

    let ciphertext = public.encrypt(&attributes_2, plaintext, &mut rng).unwrap();
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key);
    assert_eq!(Err(()), res);
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
    let mut private_map: FnvIndexMap<&str, (F, G2), S> = FnvIndexMap::new();

    let mut rng = rand::thread_rng();
    let gt: Gt = rng.gen();
    
    let system_atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();


    let (es, public) = GpswAbePrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    //println!("{:#?}", es);
    //println!("\n public params:\n{:#?}", public);
  
      
  
    let priv_key = es.keygen(&access_structure, &mut rng);
    //println!("private key:\n{:?}", priv_key)

  
    let ciphertext = public.encrypt(&attributes_1, gt, &mut rng).unwrap();
  
    // println!("ciphertext:\n{:?}", ciphertext);
    
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key);
    
    assert_eq!(Ok(gt), res);
    
    // failing decryption
    let ciphertext = public.encrypt(&attributes_2, gt, &mut rng).unwrap();
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key);
    assert_eq!(Err(()), res);
  }


  #[test]
  fn deep_access_tree() {
    let mut public_map: FnvIndexMap<&str, G2, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, (F, G2), S> = FnvIndexMap::new();
    
    let mut rng = rand::thread_rng();
    let data_orig: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();

    let system_atts = ["student", "tum", "over21", "over25", "has_bachelor", "cs"];
    let (es, public) = GpswAbePrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    
    let attributes = &["student", "tum"][..];
    let gt: Gt = rng.gen();
    let mut ciphertext = public.encrypt(&attributes, gt, &mut rng).unwrap();

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


    let priv_key = es.keygen(&access_structure, &mut rng);
    //println!("private key:\n{:?}", priv_key);
  

    // example 1 - shall decrypt (defined above)
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key);
    assert_eq!(Ok(gt), res);

    // example 2 - shall decrypt 
    let attributes = &["student", "has_bachelor", "cs", "over21"][..];
    let mut data = data_orig.clone();
    let mut ciphertext = public.encrypt(&attributes, gt, &mut rng).unwrap();
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key);
    assert_eq!(Ok(gt), res);
    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    // assert_eq!(decrypted, data);

    // example 2 - shall not decrypt 
    let attributes = &["student", "cs", "over21"][..];
    let mut data = data_orig.clone();
    let mut ciphertext = public.encrypt(&attributes, gt, &mut rng).unwrap();
    let res = GpswAbePublic::decrypt(ciphertext, &priv_key);
    assert_eq!(Err(()), res);
    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key);
    // assert_eq!(None, decrypted);
  }
}