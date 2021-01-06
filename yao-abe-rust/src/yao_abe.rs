// use rabe_bn::{Group, Fr, G};
use elliptic_curve::{Group, Field, sec1::ToEncodedPoint, generic_array::sequence::Split};
use k256::{Scalar, ProjectivePoint, AffinePoint};
use heapless::{IndexMap, FnvIndexMap, Vec, consts};
use rand::{Rng, RngCore};

use ccm::{Ccm};
use aes::Aes256;
use ccm::aead::{self, Tag, AeadInPlace, Key, NewAead, generic_array::GenericArray};

pub use ccm::aead::Error;

pub type S = consts::U64;

pub type G = ProjectivePoint;
pub type F = Scalar;

/// Represents the full parameters of an ABE scheme, known in full only to the KGC
//#[derive(Debug)]
pub struct YaoABEPrivate<'attr, 'own> {
    // gen: G,
    atts: &'own FnvIndexMap<&'attr str, (F, G), S>,
    // pk: G,
    master_secret: F,
  }
  
  /// represents the public ABE parameters, known to all participants and used for encryption, decryption and the like
  //#[derive(Debug)]
  pub struct YaoABEPublic<'attr, 'own> {
    // gen: G,
    atts: &'own FnvIndexMap<&'attr str, G, S>,
    pk: G,
  }
  
  /// represents an access structure that defines the powers of a key.
  /// This is passed to keygen() by the KGC, and then embedded in the private key issued to the user.
  #[derive(Debug)]
  pub enum AccessNode<'a> {
    Node(u64, Vec<u8, consts::U16>), // threshold, children
    Leaf(&'a str),
  }

  /// Represents an access structure defined as a threshold-tree
  // Implementation: Array of 256 AccessNodes, the first one is the root
  // size of this is 10248 bytes (!)
  // pub type AccessStructure<'a> = Vec<AccessNode<'a>, consts::U256>; 
  pub type AccessStructure<'a> = &'a [AccessNode<'a>];
  
  /// Represents a ciphertext as obtained by encrypt() and consumed by decrypt()
  /// Contains both the actual (symetrically) encrypted data and all data required to reconstruct the 
  /// symmetric keys given a private key created under a matching access structure.
  // #[derive(Debug)]
  pub struct YaoABECiphertext<'a> {
    c: &'a mut [u8], // actual ciphertext (output of AES)
    pub mac: Tag<aead::consts::U10>, // mac over the cleartext (TODO better encrypt-then-mac?)
    nonce: [u8; 13],
    c_i: FnvIndexMap<&'a str, G, S>, // attributes and their respective curve elements
  }
  
  /// Represents a private key obtained by keygen() and used to decrypt ABE-encrypted data
  /// This data structure mirrors the recursive nature of access structures to ease implementation
  /// of decryption. The secret shared (D_u in the original paper) allowing decryption are embedded
  /// in the leaves of the tree.
  //#[derive(Debug)]
  pub struct PrivateKey<'attr, 'own>(&'own AccessStructure<'attr>, FnvIndexMap<u8, F, consts::U64>);
  
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
      coefficients.extend((1..coeffs).map(|_| -> F { F::random(&mut rng) }));
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
        .map(|j| -*j * (*i-*j).invert().unwrap())
        .fold(F::one(), |acc, x| acc * x);
      //println!("\n");
      r
    }
  }
  
  impl<'attr: 'es, 'es: 'key, 'key> YaoABEPrivate<'attr, 'es> {

    pub fn setup_do_nothing(
      att_names: &Vec<&'es str, consts::U256>,
      mut rng: &mut dyn RngCore
    ) -> F
    {
      let att_map: FnvIndexMap<&str, (F, G), consts::U64> = IndexMap::new();
      let atts_public: FnvIndexMap<&str, G, consts::U64> = IndexMap::new(); //att_map.iter().map(|(k, (_, p))| (k.clone(), p.clone())).collect();
      F::random(&mut rng) + F::from(att_names.len() as u64) + F::from(atts_public.len() as u64 + att_map.len() as u64)
    }
  
    /// Corresponds to the `(A) Setup` phase in the original paper. Sets up an encryption scheme with a fixed set of attributes and 
    /// generates both public and private parameter structs. This is typically run exactly once by the KGC.
    pub fn setup(
      att_names: &[&'attr str],
      public_map: &'es mut FnvIndexMap<&'attr str, G, S>,
      private_map: &'es mut FnvIndexMap<&'attr str, (F, G), S>,
      mut rng: &mut dyn RngCore,
    ) -> (Self, YaoABEPublic<'attr, 'es>) 
    where 'attr: 'es
    {
      let master_secret: F = F::random(&mut rng); // corresponds to "s" in the original paper
      let g: G = G::random(&mut rng);
      
      // save all attributes with their corresponding public and private parameters (private is needed by kgc for key generation)
      let mut att_map: FnvIndexMap<&str, (F, G), consts::U4> = IndexMap::new();
  
      // for each attribute, choose a private field element s_i and make G * s_i public
      for attr in att_names {
        let si: F = F::random(&mut rng);
        let gi = g * si;
        private_map.insert(attr, (si, gi)).unwrap();
        public_map.insert(attr, gi).unwrap();
      }
      
      let pk = g * master_secret; // master public key, corresponds to `PK`
  
      // create equivalend HashMap for public parameters, but of course remove the private parameters for each attribute
      let atts_public: FnvIndexMap<&str, G, consts::U4> = att_map.iter().map(|(k, (_, p))| (k.clone(), p.clone())).collect();
  
      (
        YaoABEPrivate {
          // gen: g,
          atts: private_map,
          // pk,
          master_secret,
        },
        YaoABEPublic {
          // gen: g,
          atts: public_map,
          pk,
        })
    }
  
    /// Generate a private key for a given access structure, which allows a user holding the key to decrypt a ciphertext iff its 
    /// attributes satisfy the given access structure.
    pub fn keygen(
      &self,
      access_structure: &'key AccessStructure<'attr>,
      rng: &mut dyn RngCore,
    ) ->
      PrivateKey<'attr, 'key>
    where 'es: 'key
    { 
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
      tree_arr: AccessStructure<'key>,
      tree_ptr: u8,
      parent_poly: &Polynomial,
      index: F,
      rng: &mut dyn RngCore,
    ) ->
      Vec<(u8, F), consts::U64>
    {
      // own polynomial at x = 0. Exactly q_parent(index).
      let q_of_zero = parent_poly.eval(index);
      let own_node = &tree_arr[tree_ptr as usize];
      match own_node {
        AccessNode::Leaf(attr_name) => {
          // terminate recursion, embed secret share in the leaf
          let q_of_zero = parent_poly.eval(index);
          let (s, _) = self.atts.get(*attr_name).unwrap();
          let s_inverse = s.invert().unwrap();
          return Vec::from_slice(&[(tree_ptr, q_of_zero * s_inverse)]).unwrap();
        },
        AccessNode::Node(thresh, children) => {
          // continue recursion, call recursively for all children and return a key node that contains children's key subtrees
          let own_poly = Polynomial::randgen(q_of_zero, thresh.clone(), rng); // `thres`-degree polynomial determined by q_of_zero and `thresh` random coefficients
          let children_res: Vec<(u8, F), consts::U64> = children.iter().enumerate().
            map(|(i, child_ptr)| self.keygen_node(tree_arr, *child_ptr, &own_poly, F::from((i+1) as u64), rng))
            .flatten()
            .collect();
          return children_res;
        }
      }
    }
  }
  
  impl<'data, 'key, 'es, 'attr> YaoABEPublic<'attr, 'es> {
  
    /// Encrypt a plaintext under a set of attributes so that it can be decrypted only with a matching key
    /// TODO for now this does not actually encrypt any data. It just generates a random curve element c_prime (whose
    /// coordinates would be used as encryption and message authentication key), which is then reconstructible under a 
    /// matching key.
    /// This is the only part of our cryptosystem that needs to run on the Cortex M4 in the end.
    pub fn encrypt(
      &self,
      atts: &[&'attr str],
      data: &'data mut [u8],
      mut rng: &mut dyn RngCore,
      ) -> Result<YaoABECiphertext<'data>, aead::Error>
    where 'attr: 'es, 'es: 'key, 'key: 'data
    {
      // choose a C', which is then used to encrypt the actual plaintext with a symmetric cipher
      let (k, c_prime) = loop {
        let k: F = F::random(&mut rng);
        let cprime = self.pk * k;
        if !bool::from(cprime.is_identity()) { break (k, cprime) };
      };
  
      // Store the information needed to reconstruct C' under a matching key. For each attribute, only a single point
      // multiplication is calculated.
      let mut att_cs: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
      for att in atts {
        let att_pubkey: &G = self.atts.get(att).unwrap();
        let c_i = *att_pubkey * k;
        att_cs.insert(att, c_i).unwrap();
      }

      //println!("---------- ENCRYPT: encrypting with point ------------\n{:?}", c_prime.to_affine());
      let x = c_prime.to_affine().to_encoded_point(false).to_untagged_bytes().unwrap();
      let (x,_) = Split::split(x);
      // let x_arr = <[u8; 8 * 4]>::from(x);
      // let y_arr = <[u8; 8 * 4]>::from(y);
    //   println!("Encryption with x {:x?}\narray: {:x?}", x, x_arr);
    //   println!("Encryption with y {:x?}\narray: {:x?}", y, y_arr);
      
      type YaoCcm = Ccm<Aes256, ccm::consts::U10, ccm::consts::U13>;

      let key: Key<YaoCcm> = x;
      let ccm = YaoCcm::new(&key);
      
      let nonce: [u8; 13] = rng.gen();
      let nonce_ga = GenericArray::from(nonce);
      let mac = ccm.encrypt_in_place_detached(&nonce_ga, &[], data)?;
      Ok(YaoABECiphertext {
        c: data,
        mac,
        nonce,
        c_i: att_cs,
      })
    }
  
    /// Recursive helper function for decryption
    fn decrypt_node(
      tree_arr: &AccessStructure<'key>,
      tree_ptr: u8,
      secret_shares: &FnvIndexMap<u8, F, consts::U64>,
      att_cs: &FnvIndexMap<& 'data str, G, S>
    ) -> Option<G> 
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
          match att_cs.get(name) {
            None => return None,
            Some(c_i) => return Some(c_i.clone() * *d_u),
          }
        },
        AccessNode::Node(thresh, children) => {
          // continue recursion - call for all children and then, if enough children decrypt successfully, reconstruct the secret share for 
          // this intermediate node.
          let children_result: Vec<(F, G), consts::U16> = children.into_iter().enumerate()
            .map(|(i, child_ptr)| (F::from((i + 1) as u64), Self::decrypt_node(tree_arr, *child_ptr, secret_shares, att_cs))) // node indexes start at one, enumerate() starts at zero! 
            .filter_map(|(i, x)| match x { None => None, Some(y) => Some((i, y))}) // filter out all children that couldn't decrypt because of missing ciphertext secret shares
            .collect();
          // we can only reconstruct our secret share if at least `thresh` children decrypted successfully (interpolation of `thresh-1`-degree polynomial)
          if children_result.len() < *thresh as usize { return None }
          // an arbitrary subset omega with |omega| = thresh is enough to reconstruct the secret. To make it easy, we just take the first `thresh` in our list.
          let relevant_children: Vec<(F, G), consts::U16> = children_result.into_iter().take(*thresh as usize).collect();
          let relevant_indexes: Vec<F, consts::U16> = relevant_children.iter()
            .map(|(i, _)| i.clone()).collect(); // our langrange helper function wants this vector of field elements
          let result: G = relevant_children.into_iter()
            .map(|(i, dec_res)| { dec_res * Polynomial::lagrange_of_zero(&i, &relevant_indexes) } )
            .fold(G::identity(), |acc, g| g + acc);
          // //println!("node got result: {:?}\n at node {:?}\n", result, key);
          return Some(result);
        }
      }
    }
  
    /// Decrypt a ciphertext using a given private key. At this point, doesn't actually do any decryption, it just reconstructs the point used as encryption/mac key.
    pub fn decrypt(
      &self,
      ciphertext: &mut YaoABECiphertext<'data>,
      key: &PrivateKey<'attr, 'key>,
    ) -> Result<(), aead::Error>
    where 'attr: 'es, 'es: 'key, 'key: 'data
    {
      let PrivateKey(access_structure, secret_shares) = key;

      let res = Self::decrypt_node(&access_structure, 0, &secret_shares, &ciphertext.c_i);
      let c_prime = match res {
        None => return Err(aead::Error),
        Some(p) => p,
      };
      let x = c_prime.to_affine().to_encoded_point(false).to_untagged_bytes().unwrap();
      let (x,_) = Split::split(x);
      let nonce = GenericArray::from(ciphertext.nonce);
      

      type YaoCcm = Ccm<Aes256, ccm::consts::U10, ccm::consts::U13>;

      let key: Key<YaoCcm> = x;
      let ccm = YaoCcm::new(&key);
      
      ccm.decrypt_in_place_detached(&nonce, &[], ciphertext.c, &ciphertext.mac)
    }
  }



#[cfg(test)]
mod tests {

  // extern crate test;
  // extern crate std;
  
  use crate::*;
  use rand::{self, Rng};
  use rabe_bn::{F, G};

  use heapless::{Vec, consts};

  use super::*;

  // use test::Bencher;

  #[test]
  fn leaf_only_access_tree() {
    let mut access_structure_vec: Vec<AccessNode, consts::U64> = Vec::new();
    access_structure_vec.push(AccessNode::Leaf("student")).unwrap();
    let access_structure = &access_structure_vec[..];

    let mut public_map: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, (F, G), S> = FnvIndexMap::new();



    let mut rng = rand::thread_rng();
    let data_orig: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();
    let mut data = data_orig.clone();

    let attributes_1: Vec<&str, consts::U64> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let attributes_2: Vec<&str, consts::U64> = Vec::from_slice(&["tum", "over21"]).unwrap();

    let system_atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let (private, public) = crate::YaoABEPrivate::setup(&system_atts, &mut public_map, &mut private_map);
    // println!("{:#?}", es);
    // println!("\n public params:\n{:?}", public);

    
    

    // println!("access structure:\n{:#?}", access_structure);

    let priv_key = private.keygen(&access_structure);
    //println!("private key:\n{:?}", priv_key);


    let mut ciphertext =  public.encrypt(&attributes_1, &mut data).unwrap();

    // //println!("ciphertext:\n{:?}", ciphertext);
    
    public.decrypt(&mut ciphertext, &priv_key).unwrap();  

    assert_eq!(data_orig, ciphertext.c);

    // match priv_key { 
    //   crate::PrivateKey::Leaf(d, name) =>  {
    //     let c_i = ciphertext.c_i.get(name).unwrap();
    //     let (s_i, _) = es.atts.get(name).unwrap();
    //     let c_i2 = public.gen * ciphertext.secret_k * *s_i;
    //     let d2 = es.master_secret * s_i.inverse().unwrap();
    //     assert_eq!(*c_i, c_i2);
    //     assert_eq!(d, d2);
    //     assert_eq!(public.pk, public.gen * es.master_secret);
    //     // let manual_decryption = (C_i2 * d2).to_affine();
    //     let manual_decryption = (es.pk * ciphertext.secret_k);
    //     //println!("------------ manual leaf dec ------------\n{:?}", manual_decryption);
    //     assert_eq!(ciphertext.secret_c, manual_decryption);
    //   },
    //   _ => assert!(false),
    // }
    let mut data = data_orig.clone();

    let mut ciphertext = public.encrypt(&attributes_2, &mut data).unwrap();
    let decrypted = public.decrypt(&mut ciphertext, &priv_key);
    assert_eq!(Err(Error), decrypted);
  }


//   #[test]
//   fn flat_access_tree() {

//     let access_structure: AccessStructure = &[
//       AccessNode::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
//       AccessNode::Leaf("tum"),
//       AccessNode::Leaf("student"),
//       AccessNode::Leaf("has_bachelor"),
//       AccessNode::Leaf("over21"),
//     ];


//     let attributes_1 = &["student", "tum", "has_bachelor", "over21"][..];
//     let attributes_2 = &["tum"][..];

//     let mut rng = rand::thread_rng();
//     let data_orig: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();
//     let mut data = data_orig.clone();
    
//     let system_atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();


//     let (es, public) = crate::YaoABEPrivate::setup(&system_atts);
//     //println!("{:#?}", es);
//     //println!("\n public params:\n{:#?}", public);
  
      
  
//     let priv_key = es.keygen(&access_structure);
//     //println!("private key:\n{:?}", priv_key)

  
//     let mut ciphertext = public.encrypt(&attributes_1, &mut data).unwrap();
  
//     // println!("ciphertext:\n{:?}", ciphertext);
    
//     public.decrypt(&mut ciphertext, &priv_key).unwrap();
    
//     assert_eq!(data_orig, ciphertext.c);
    
//     // failing decryption
//     let mut data = data_orig.clone();
//     let mut ciphertext = public.encrypt(&attributes_2, &mut data).unwrap();
//     let res = public.decrypt(&mut ciphertext, &priv_key);
//     assert_eq!(Err(Error), res);
//   }


//   #[test]
//   fn malleability() {


//     let access_structure: AccessStructure = &[
//       AccessNode::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
//       AccessNode::Leaf("tum"),
//       AccessNode::Leaf("student"),
//       AccessNode::Leaf("has_bachelor"),
//       AccessNode::Leaf("over21"),
//     ];

    // let mut public_map: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
    // let mut private_map: FnvIndexMap<&str, (F, G), S> = FnvIndexMap::new();

//     let attributes = &["student", "tum", "has_bachelor", "over21"][..];

//     let mut rng = rand::thread_rng();
//     let data_orig: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();
//     let mut data = data_orig.clone();

//     let atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
//     let (es, public) = crate::YaoABEPrivate::setup(&atts);
//     //println!("{:#?}", es);
//     //println!("\n public params:\n{:#?}", public);
  
  
//     let priv_key = es.keygen(&access_structure);
//     //println!("private key:\n{:?}", priv_key);
  
//     // let mut data: Vec<u8> = (0..500).map(|_| 0).collect();
  
//     let mut ciphertext = public.encrypt(&attributes, &mut data).unwrap();

//     // assert_eq!(data, public.decrypt(&ciphertext, &priv_key).unwrap());

//     ciphertext.c[16] ^= 0xaf; // skip IV
  
//     // println!("ciphertext:\n{:?}", ciphertext);
    
//     let res = public.decrypt(&mut ciphertext, &priv_key);
    
//     // decryption should fail because MAC is wrong
//     assert_eq!(res, Err(Error));
//   }

//   #[test]
//   fn deep_access_tree() {

//     // this represents the following logical access structure:
//     // (tum AND student) OR (cs AND has_bachelor AND (over21 OR over25))
//     let access_structure: AccessStructure = &[
//       AccessNode::Node(1, Vec::from_slice(&[1, 2]).unwrap()), // 0
//       AccessNode::Node(2, Vec::from_slice(&[3, 4]).unwrap()), // 1
//       AccessNode::Node(3, Vec::from_slice(&[5, 6, 7]).unwrap()),// 2
//       AccessNode::Leaf("student"),                            // 3
//       AccessNode::Leaf("tum"),                                // 4
//       AccessNode::Leaf("cs"),                                 // 5
//       AccessNode::Leaf("has_bachelor"),                       // 6
//       AccessNode::Node(1, Vec::from_slice(&[8, 9]).unwrap()), // 7
//       AccessNode::Leaf("over21"),                             // 8
//       AccessNode::Leaf("over25"),                             // 9
//     ];
    
    // let mut public_map: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
    // let mut private_map: FnvIndexMap<&str, (F, G), S> = FnvIndexMap::new();
    
//     let mut rng = rand::thread_rng();
//     let data_orig: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();

//     let system_atts = Vec::from_slice(&["student", "tum", "over21", "over25", "has_bachelor", "cs"]).unwrap();
//     let (es, public) = crate::YaoABEPrivate::setup(&system_atts);

//     //println!("{:#?}", es);
//     //println!("\n public params:\n{:?}", public);
  
//     let priv_key = es.keygen(&access_structure);
//     //println!("private key:\n{:?}", priv_key);
  

//     // example 1 - shall decrypt
//     let attributes = &["student", "tum"][..];
//     let mut data = data_orig.clone();
//     let mut ciphertext = public.encrypt(&attributes, &mut data).unwrap();
//     let res = public.decrypt(&mut ciphertext, &priv_key);
//     assert_eq!(Ok(()), res);
//     assert_eq!(data_orig, ciphertext.c);

//     // example 2 - shall decrypt
//     let attributes = &["student", "has_bachelor", "cs", "over21"][..];
//     let mut data = data_orig.clone();
//     let mut ciphertext = public.encrypt(&attributes, &mut data).unwrap();
//     let res = public.decrypt(&mut ciphertext, &priv_key);
//     assert_eq!(Ok(()), res);
//     assert_eq!(data_orig, ciphertext.c);
//     // let ciphertext = public.encrypt(&attributes, &data);
//     // let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
//     // assert_eq!(decrypted, data);

//     // example 2 - shall not decrypt
//     let attributes = &["student", "cs", "over21"][..];
//     let mut data = data_orig.clone();
//     let mut ciphertext = public.encrypt(&attributes, &mut data).unwrap();
//     let res = public.decrypt(&mut ciphertext, &priv_key);
//     assert_eq!(Err(Error), res);
//     assert_ne!(data_orig, ciphertext.c);
//     // let ciphertext = public.encrypt(&attributes, &data);
//     // let decrypted = public.decrypt(&ciphertext, &priv_key);
//     // assert_eq!(None, decrypted);
//   }


//   #[test]
//   fn curve_operations_dry_run() {
//     let mut rng = rand::thread_rng();

//     let s: F = rng.gen();
//     let s_inv = s.inverse().unwrap();

//     let g: G = rng.gen();

//     let c = g * s;

//     let c_dec = c * s_inv;
//     assert_eq!(g, c_dec);

//   }
}
