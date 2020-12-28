use rabe_bn::{Group, Fr, G1};
use heapless::{IndexMap, FnvIndexMap, Vec, consts};
use rand::Rng;
use crypto::{aes, mac::{Mac, MacResult}, hmac, sha2};


/// Represents the full parameters of an ABE scheme, known in full only to the KGC
//#[derive(Debug)]
pub struct YaoABEPrivate<'a> {
    gen: G1,
    atts: FnvIndexMap<&'a str, (Fr, G1), consts::U256>,
    pk: G1,
    master_secret: Fr,
  }
  
  /// represents the public ABE parameters, known to all participants and used for encryption, decryption and the like
  //#[derive(Debug)]
  pub struct YaoABEPublic<'a> {
    gen: G1,
    atts: FnvIndexMap<&'a str, G1, consts::U256>,
    pk: G1,
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
  pub type AccessStructure<'a> = Vec<AccessNode<'a>, consts::U256>; 
  
  /// Represents a ciphertext as obtained by encrypt() and consumed by decrypt()
  /// Contains both the actual (symetrically) encrypted data and all data required to reconstruct the 
  /// symmetric keys given a private key created under a matching access structure.
  // #[derive(Debug)]
  pub struct YaoABECiphertext<'a> {
    c: Vec<u8, consts::U4096>, // actual ciphertext (output of AES)
    mac: MacResult, // mac over the cleartext (TODO better encrypt-then-mac?)
    c_i: FnvIndexMap<&'a str, G1, consts::U64>, // attributes and their respective curve elements
  }
  
  /// Represents a private key obtained by keygen() and used to decrypt ABE-encrypted data
  /// This data structure mirrors the recursive nature of access structures to ease implementation
  /// of decryption. The secret shared (D_u in the original paper) allowing decryption are embedded
  /// in the leaves of the tree.
  //#[derive(Debug)]
  pub struct PrivateKey(AccessStructure<'static>, FnvIndexMap<u8, Fr, consts::U64>);
  
  /// Polynomial p(x) = a0 + a1 * x + a2 * x^2 + ... defined by a vector of coefficients [a0, a1, a2, ...]
  //#[derive(Debug)]
  struct Polynomial(Vec<Fr, consts::U16>);
  
  impl Polynomial {
    /// Evaluates the polynomial p(x) at a given x
    fn eval(&self, x: Fr) -> Fr {
      self.0.iter().rev().fold(Fr::zero(), |acc, c| *c + (x * acc))
    }
  
    /// Generates a random polynomial p(x) of degree `coeffs` coefficients, where p(0) = `a0`
    fn randgen(a0: Fr, coeffs: u64) -> Polynomial {
      let mut coefficients: Vec<Fr, consts::U16> = Vec::from_slice(&[a0]).unwrap();
      let mut rng = rand::thread_rng();
      coefficients.extend((1..coeffs).map(|_| -> Fr { rng.gen() }));
      assert_eq!(coefficients.len() as u64, coeffs);
      Polynomial(coefficients)
    }
  
    /// Calculates the langrage base polynomials l_i(x) for given set of indices omega and the index i.
    /// As we only ever need to interpolate p(0), no value for x may be passed.
    fn lagrange_of_zero(i: &Fr, omega: &Vec<Fr, consts::U16>) -> Fr {
      //println!("LAGRANGE: {:?}\n{:?}", i, omega);
      let r = omega.iter()
        .filter(|x| *x != i)
        // .map(|x| { println!("{:?}", x); x} )
        .map(|j| -*j * (*i-*j).inverse().unwrap())
        .fold(Fr::one(), |acc, x| acc * x);
      //println!("\n");
      r
    }
  }
  
  impl<'a> YaoABEPrivate<'a> {
  
    /// Corresponds to the `(A) Setup` phase in the original paper. Sets up an encryption scheme with a fixed set of attributes and 
    /// generates both public and private parameter structs. This is typically run exactly once by the KGC.
    pub fn setup(att_names: &Vec<&'static str, consts::U256>) -> (Self, YaoABEPublic<'a>) {
      let mut rng = rand::thread_rng();
      let master_secret: Fr = rng.gen(); // corresponds to "s" in the original paper
      let g: G1 = rng.gen();
      
      // save all attributes with their corresponding public and private parameters (private is needed by kgc for key generation)
      let mut att_map: FnvIndexMap<&str, (Fr, G1), consts::U256> = IndexMap::new();
  
      // for each attribute, choose a private field element s_i and make G * s_i public
      for attr in att_names {
        let si: Fr = rng.gen();
        let gi = g * si;
        att_map.insert(attr, (si, gi)).unwrap();
      }
      
      let pk = g * master_secret; // master public key, corresponds to `PK`
  
      // create equivalend HashMap for public parameters, but of course remove the private parameters for each attribute
      let atts_public: FnvIndexMap<&str, G1, consts::U256> = att_map.iter().map(|(k, (_, p))| (k.clone(), p.clone())).collect();
  
      (
        YaoABEPrivate {
          gen: g,
          atts: att_map,
          pk,
          master_secret,
        },
        YaoABEPublic {
          gen: g,
          atts: atts_public,
          pk,
        })
    }
  
    /// Generate a private key for a given access structure, which allows a user holding the key to decrypt a ciphertext iff its 
    /// attributes satisfy the given access structure.
    pub fn keygen(
      &self,
      access_structure: &'static AccessStructure<'static>
    ) ->
      PrivateKey
    { 
      let tuple_arr = self.keygen_node(
        &access_structure,
        0,
        &Polynomial::randgen(self.master_secret, 1),
        Fr::zero(), // this is the only node ever to have index 0, all others have index 1..n
      );
      return PrivateKey(*access_structure, tuple_arr.into_iter().collect());
    }
  
    /// internal recursive helper to ease key generation
    fn keygen_node (&self,
      tree_arr: &AccessStructure<'static>,
      tree_ptr: u8,
      parent_poly: &Polynomial,
      index: Fr
    ) ->
      Vec<(u8, Fr), consts::U64>
    {
      // own polynomial at x = 0. Exactly q_parent(index).
      let q_of_zero = parent_poly.eval(index);
      let own_node = &tree_arr[tree_ptr as usize];
      match own_node {
        AccessNode::Leaf(attr_name) => {
          // terminate recursion, embed secret share in the leaf
          let q_of_zero = parent_poly.eval(index);
          let (s, _) = self.atts.get(attr_name).unwrap();
          let s_inverse = s.inverse().unwrap();
          return Vec::from_slice(&[(tree_ptr, q_of_zero * s_inverse)]).unwrap();
        },
        AccessNode::Node(thresh, children) => {
          // continue recursion, call recursively for all children and return a key node that contains children's key subtrees
          let own_poly = Polynomial::randgen(q_of_zero, thresh.clone()); // `thres`-degree polynomial determined by q_of_zero and `thresh` random coefficients
          let children_res: Vec<(u8, Fr), consts::U64> = children.iter().enumerate().
            map(|(i, child_ptr)| self.keygen_node(tree_arr, *child_ptr, &own_poly, Fr::from((i+1) as u64)))
            .flatten()
            .collect();
          return children_res;
        }
      }
    }
  }
  
  impl<'a> YaoABEPublic<'a> {
  
    /// Encrypt a plaintext under a set of attributes so that it can be decrypted only with a matching key
    /// TODO for now this does not actually encrypt any data. It just generates a random curve element c_prime (whose
    /// coordinates would be used as encryption and message authentication key), which is then reconstructible under a 
    /// matching key.
    /// This is the only part of our cryptosystem that needs to run on the Cortex M4 in the end.
    pub fn encrypt(
      &self,
      atts: &'a Vec<&'a str, consts::U64>,
      plaintext: &'a Vec<u8, consts::U2048>,
      ) -> YaoABECiphertext<'a>
    {
      let mut rng = rand::thread_rng();
      // choose a C', which is then used to encrypt the actual plaintext with a symmetric cipher
      let (k, c_prime) = loop {
        let k: Fr = rng.gen();
        let cprime = self.pk * k;
        if !cprime.is_zero() { break (k, cprime) };
      };
  
      // Store the information needed to reconstruct C' under a matching key. For each attribute, only a single point
      // multiplication is calculated.
      let mut att_cs: FnvIndexMap<&str, G1, consts::U64> = FnvIndexMap::new();
      for att in atts {
        let att_pubkey: &G1 = self.atts.get(att).unwrap();
        let c_i = *att_pubkey * k;
        att_cs.insert(att, c_i).unwrap();
      }
      //println!("---------- ENCRYPT: encrypting with point ------------\n{:?}", c_prime.to_affine());
      let (x, y) = c_prime.coordinates();
      let x_arr = <[u8; 8 * 4]>::from(x);
      let y_arr = <[u8; 8 * 4]>::from(y);
    //   println!("Encryption with x {:x?}\narray: {:x?}", x, x_arr);
    //   println!("Encryption with y {:x?}\narray: {:x?}", y, y_arr);
  
      let sha256_hasher = sha2::Sha256::new();
      let mut mac_maker = hmac::Hmac::new(sha256_hasher, &y_arr);
      mac_maker.input(&plaintext);
      let mac = mac_maker.result();
  
      let mut encrypted: Vec<u8, consts::U2048> = plaintext.clone(); // todo make more fitting size
      let iv: [u8; 16] = rng.gen();
      let mut aes_ctr = aes::ctr(aes::KeySize::KeySize256, &x_arr, &iv);
      aes_ctr.process(&plaintext, &mut encrypted);
  
      let mut full_ciphertext: Vec<u8, consts::U4096> = Vec::from_slice(&iv).unwrap();
      full_ciphertext.extend_from_slice(&encrypted).unwrap();
  
      YaoABECiphertext {
        c: full_ciphertext,
        mac,
        c_i: att_cs,
      }
    }
  
    /// Recursive helper function for decryption
    fn decrypt_node(
      tree_arr: &AccessStructure<'a>,
      tree_ptr: u8,
      secret_shares: &FnvIndexMap<u8, Fr, consts::U64>,
      att_cs: &FnvIndexMap<& 'a str, G1, consts::U64>
    ) -> Option<G1> {
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
          let children_result: Vec<(Fr, G1), consts::U16> = children.into_iter().enumerate()
            .map(|(i, child_ptr)| (Fr::from((i + 1) as u64), Self::decrypt_node(tree_arr, *child_ptr, secret_shares, att_cs))) // node indexes start at one, enumerate() starts at zero! 
            .filter_map(|(i, x)| match x { None => None, Some(y) => Some((i, y))}) // filter out all children that couldn't decrypt because of missing ciphertext secret shares
            .collect();
          // we can only reconstruct our secret share if at least `thresh` children decrypted successfully (interpolation of `thresh-1`-degree polynomial)
          if children_result.len() < *thresh as usize { return None }
          // an arbitrary subset omega with |omega| = thresh is enough to reconstruct the secret. To make it easy, we just take the first `thresh` in our list.
          let relevant_children: Vec<(Fr, G1), consts::U16> = children_result.into_iter().take(*thresh as usize).collect();
          let relevant_indexes: Vec<Fr, consts::U16> = relevant_children.iter()
            .map(|(i, _)| i.clone()).collect(); // our langrange helper function wants this vector of field elements
          let result: G1 = relevant_children.into_iter()
            .map(|(i, dec_res)| { dec_res * Polynomial::lagrange_of_zero(&i, &relevant_indexes) } )
            .fold(G1::zero(), |acc, g| g + acc);
          // //println!("node got result: {:?}\n at node {:?}\n", result, key);
          return Some(result);
        }
      }
    }
  
    /// Decrypt a ciphertext using a given private key. At this point, doesn't actually do any decryption, it just reconstructs the point used as encryption/mac key.
    pub fn decrypt(
      &self,
      ciphertext: &'a YaoABECiphertext<'a>,
      key: &PrivateKey,
    ) -> Option<Vec<u8, consts::U2048>> {
      let PrivateKey(access_structure, secret_shares) = key;

      let res = Self::decrypt_node(&access_structure, 0, &secret_shares, &ciphertext.c_i);
      let c_prime = match res {
        None => return None,
        Some(p) => p,
      };
      let (x, y) = c_prime.coordinates();
      let mut iv: Vec<u8, consts::U16> = ciphertext.c.iter().take(16).map(|x| x.clone()).collect();
      let mut aes_ctr = aes::ctr(aes::KeySize::KeySize256, &(<[u8; 4 * 8]>::from(x)), &mut iv);
      let mut plaintext: Vec<u8, consts::U2048> = Vec::new();
      plaintext.resize(ciphertext.c.len() - 16, 0);
      aes_ctr.process(&ciphertext.c[16..], &mut plaintext);
  
      let sha256_hasher = sha2::Sha256::new();
      let mut mac_maker = hmac::Hmac::new(sha256_hasher, &(<[u8; 4 * 8]>::from(y)));
      mac_maker.input(&plaintext);
      let mac_ = mac_maker.result();
  
      if mac_ == ciphertext.mac {
        return Some(plaintext);
      } else {
        return None;
      }
    }
  }



#[cfg(test)]
mod tests {

  // extern crate test;
  use crate::*;
  use rand::{self, Rng};
  use rabe_bn::{Fr, G1};

  use heapless::{Vec, consts};

  // use test::Bencher;

  #[test]
  fn leaf_only_access_tree() {
    let mut access_structure: AccessStructure = Vec::new();
    access_structure.push(AccessNode::Leaf("student"));


    let mut rng = rand::thread_rng();
    let data: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();

    let attributes_1: Vec<&str, consts::U64> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let attributes_2 = Vec::from_slice(&["tum", "over21"]).unwrap();

    let system_atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let (private, public) = crate::YaoABEPrivate::setup(&system_atts);
    //println!("{:#?}", es);
    //println!("\n public params:\n{:?}", public);

    
    

    println!("access structure:\n{:#?}", access_structure);

    let priv_key = private.keygen(&access_structure);
    //println!("private key:\n{:?}", priv_key);


    let ciphertext =  public.encrypt(&attributes_1, &data);

    // //println!("ciphertext:\n{:?}", ciphertext);
    
    let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();  

    assert_eq!(decrypted, data);

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

    let ciphertext = public.encrypt(&attributes_2, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }


  // #[test]
  // fn flat_access_tree() {
  //   let atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
  //   let (es, public) = crate::YaoABEPrivate::setup(&atts);
  //   //println!("{:#?}", es);
  //   //println!("\n public params:\n{:#?}", public);
  
  //   let inner_vec: Vec<AccessStructure, consts::U16> = Vec::new();
  //   inner_vec.push(AccessStructure::Leaf("tum"));

  //   let access_structure = AccessStructure::Node(
  //     2,
  //     inner_vec,
  //   );
  //     // Vec::from_slice(&[
  //     //   AccessStructure::Leaf("tum"),
  //     //   AccessStructure::Leaf("student"),
  //     //   AccessStructure::Leaf("has_bachelor"),
  //     //   AccessStructure::Leaf("over21"),
  //     // ]).unwrap());
  
  
  //   let priv_key = es.keygen(&access_structure);
  //   //println!("private key:\n{:?}", priv_key);
  
  //   let mut rng = rand::thread_rng();
  //   let data: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();

  //   let attributes = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
  
  //   let ciphertext = public.encrypt(&attributes, &data);
  
  //   // println!("ciphertext:\n{:?}", ciphertext);
    
  //   let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    
  //   assert_eq!(decrypted, data);
    
  //   // failing decryption
  //   let attributes = Vec::from_slice(&["tum"]).unwrap();
  //   let ciphertext = public.encrypt(&attributes, &data);
  //   let decrypted = public.decrypt(&ciphertext, &priv_key);
  //   assert_eq!(None, decrypted);
  // }


  // #[test]
  // fn malleability() {
  //   let atts: Vec<&str, consts::U256> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
  //   let (es, public) = crate::YaoABEPrivate::setup(&atts);
  //   //println!("{:#?}", es);
  //   //println!("\n public params:\n{:#?}", public);
  
  //   let access_structure = AccessStructure::Node(
  //     2,
  //     vec![
  //       AccessStructure::Leaf("tum"),
  //       AccessStructure::Leaf("student"),
  //       AccessStructure::Leaf("has_bachelor"),
  //       AccessStructure::Leaf("over21"),
  //     ]);
  
  
  //   let priv_key = es.keygen(&access_structure);
  //   //println!("private key:\n{:?}", priv_key);
  
  //   let mut rng = rand::thread_rng();
  //   let data: Vec<u8> = (0..500).map(|_| rng.gen()).collect();
  //   // let mut data: Vec<u8> = (0..500).map(|_| 0).collect();

  //   let attributes = vec!["student", "tum", "has_bachelor", "over21"];
  
  //   let mut ciphertext = public.encrypt(&attributes, &data);

  //   assert_eq!(data, public.decrypt(&ciphertext, &priv_key).unwrap());

  //   ciphertext.c[16] ^= 0xaf; // skip IV
  //   let mut data2 = data.clone();
  //   data2[0] ^= 0xaf;

  
  //   // println!("ciphertext:\n{:?}", ciphertext);
    
  //   let decrypted = public.decrypt(&ciphertext, &priv_key);
    
  //   // decryption should fail because MAC is wrong
  //   assert_eq!(decrypted, None);
  // }

  // #[test]
  // fn deep_access_tree() {

  //   let atts = vec!["student", "tum", "over21", "over25", "has_bachelor", "cs"];
  //   let (es, public) = crate::YaoABEPrivate::setup(&atts);

  //   //println!("{:#?}", es);
  //   //println!("\n public params:\n{:?}", public);
  
  //   // this represents the following logical access structure
  //   // (tum AND student) OR (cs AND has_bachelor AND (over21 OR over25))
  //   let access_structure = AccessStructure::Node(
  //     1,
  //     vec![
  //       AccessStructure::Node(2,
  //         vec![
  //           AccessStructure::Leaf("student"),
  //           AccessStructure::Leaf("tum"),
  //         ]),
  //       AccessStructure::Node(3,
  //         vec![
  //           AccessStructure::Leaf("cs"),
  //           AccessStructure::Node(1,
  //             vec![
  //               AccessStructure::Leaf("over21"),
  //               AccessStructure::Leaf("over25"),
  //             ]),
  //           AccessStructure::Leaf("has_bachelor"),
  //         ]),
  //     ]); 
  
  //   let priv_key = es.keygen(&access_structure);
  //   //println!("private key:\n{:?}", priv_key);
  
  //   let mut rng = rand::thread_rng();
  //   let data: Vec<u8> = (0..500).map(|_| rng.gen()).collect();

  //   // example 1 - shall decrypt
  //   let attributes = vec!["student", "tum"];
  //   let ciphertext = public.encrypt(&attributes, &data);
  //   let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
  //   assert_eq!(decrypted, data);

  //   // example 2 - shall decrypt
  //   let attributes = vec!["student", "has_bachelor", "cs", "over21"];
  //   let ciphertext = public.encrypt(&attributes, &data);
  //   let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
  //   assert_eq!(decrypted, data);

  //   // example 2 - shall not decrypt
  //   let attributes = vec!["student", "cs", "over21"];
  //   let ciphertext = public.encrypt(&attributes, &data);
  //   let decrypted = public.decrypt(&ciphertext, &priv_key);
  //   assert_eq!(None, decrypted);
  // }

  // #[bench]
  // fn benchmark_deeptree(b: &mut Bencher) {

  // }

  #[test]
  fn curve_operations_dry_run() {
    let mut rng = rand::thread_rng();

    let s: Fr = rng.gen();
    let s_inv = s.inverse().unwrap();

    let g: G1 = rng.gen();

    let c = g * s;

    let c_dec = c * s_inv;
    assert_eq!(g, c_dec);

  }
}