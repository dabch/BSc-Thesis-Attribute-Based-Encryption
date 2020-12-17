use rabe_bn::{Group, Fr, G1};
use std::collections::HashMap;
use std::convert::TryInto;
use rand::Rng;
use crypto::{aes, mac::{Mac, MacResult}, hmac, sha2};

// mod aes;


fn main() {
  
  
  let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
  let (es, public) = YaoABEPrivate::setup(&atts);
  //println!("{:#?}", es);
  //println!("\n public params:\n{:#?}", public);

  let access_structure = AccessStructure::Node(
    2,
    vec![
      AccessStructure::Leaf("tum"),
      AccessStructure::Node(2,
        vec![
          AccessStructure::Leaf("student"),
          AccessStructure::Leaf("has_bachelor"),
        ]),
    ]); 

  let priv_key = es.keygen(&access_structure);
  //println!("private key:\n{:?}", priv_key);

  
  let mut rng = rand::thread_rng();
  let data: Vec<u8> = (0..500).map(|_| rng.gen()).collect();

  let attributes = vec!["student", "tum", "has_bachelor", "over21"];

  let ciphertext = public.encrypt(&attributes, &data);

  
  let decrypted = public.decrypt(&ciphertext, &priv_key);
  
  assert_eq!(data, decrypted.unwrap());
}

/// Represents the full parameters of an ABE scheme, known in full only to the KGC
//#[derive(Debug)]
struct YaoABEPrivate<'a> {
  gen: G1,
  atts: HashMap<&'a str, (Fr, G1)>,
  pk: G1,
  master_secret: Fr,
}

/// represents the public ABE parameters, known to all participants and used for encryption, decryption and the like
//#[derive(Debug)]
struct YaoABEPublic<'a> {
  gen: G1,
  atts: HashMap<&'a str, G1>,
  pk: G1,
}

/// represents an access structure that defines the powers of a key.
/// This is passed to keygen() by the KGC, and then embedded in the private key issued to the user.
//#[derive(Debug)]
enum AccessStructure<'a> {
  Node(u64, Vec<AccessStructure<'a>>), // threshold, children
  Leaf(&'a str),
}

/// Represents a ciphertext as obtained by encrypt() and consumed by decrypt()
/// Contains both the actual (symetrically) encrypted data and all data required to reconstruct the 
/// symmetric keys given a private key created under a matching access structure.
// #[derive(Debug)]
struct YaoABECiphertext<'a> {
  c: Vec<u8>, // actual ciphertext (output of AES)
  mac: MacResult, // mac over the cleartext (TODO better encrypt-then-mac?)
  c_i: HashMap<&'a str, G1>, // attributes and their respective curve elements
}

/// Represents a private key obtained by keygen() and used to decrypt ABE-encrypted data
/// This data structure mirrors the recursive nature of access structures to ease implementation
/// of decryption. The secret shared (D_u in the original paper) allowing decryption are embedded
/// in the leaves of the tree.
//#[derive(Debug)]
enum PrivateKey<'a> {
  Node(u64, Vec<PrivateKey<'a>>),
  Leaf(Fr, &'a str),
}

/// Polynomial p(x) = a0 + a1 * x + a2 * x^2 + ... defined by a vector of coefficients [a0, a1, a2, ...]
//#[derive(Debug)]
struct Polynomial(Vec<Fr>);

impl Polynomial {
  /// Evaluates the polynomial p(x) at a given x
  fn eval(&self, x: Fr) -> Fr {
    self.0.iter().rev().fold(Fr::zero(), |acc, c| *c + (x * acc))
  }

  /// Generates a random polynomial p(x) of degree `coeffs` coefficients, where p(0) = `a0`
  fn randgen(a0: Fr, coeffs: u64) -> Polynomial {
    let mut coefficients: Vec<Fr> = vec![a0];
    let mut rng = rand::thread_rng();
    coefficients.extend((1..coeffs).map(|_| -> Fr { rng.gen() }));
    assert_eq!(coefficients.len() as u64, coeffs);
    Polynomial(coefficients)
  }

  /// Calculates the langrage base polynomials l_i(x) for given set of indices omega and the index i.
  /// As we only ever need to interpolate p(0), no value for x may be passed.
  fn lagrange_of_zero(i: &Fr, omega: &Vec<Fr>) -> Fr {
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
  fn setup(att_names: &Vec<&'static str>) -> (Self, YaoABEPublic<'a>) {
    let mut rng = rand::thread_rng();
    let master_secret: Fr = rng.gen(); // corresponds to "s" in the original paper
    let g: G1 = rng.gen();
    
    // save all attributes with their corresponding public and private parameters (private is needed by kgc for key generation)
    let mut att_map: HashMap<&str, (Fr, G1)> = HashMap::new();

    // for each attribute, choose a private field element s_i and make G * s_i public
    for attr in att_names {
      let si: Fr = rng.gen();
      let gi = g * si;
      att_map.insert(attr, (si, gi));
    }
    
    let pk = g * master_secret; // master public key, corresponds to `PK`

    // create equivalend HashMap for public parameters, but of course remove the private parameters for each attribute
    let atts_public: HashMap<&str, G1> = att_map.iter().map(|(k, (_, p))| (k.clone(), p.clone())).collect();

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
  fn keygen(
    &self,
    access_structure: &'a AccessStructure
  ) ->
    PrivateKey
  { 
    self.keygen_node(
      &access_structure,
      &Polynomial::randgen(self.master_secret, 1),
      Fr::zero(), // this is the only node ever to have index 0, all others have index 1..n
    )
  }

  /// internal recursive helper to ease key generation
  fn keygen_node (&self,
    tree: &'a AccessStructure,
    parent_poly: &Polynomial,
    index: Fr
  ) ->
    PrivateKey
  {
    // own polynomial at x = 0. Exactly q_parent(index).
    let q_of_zero = parent_poly.eval(index);
    match tree {
      AccessStructure::Leaf(attr_name) => {
        // terminate recursion, embed secret share in the leaf
        let q_of_zero = parent_poly.eval(index);
        let (s, _) = self.atts.get(attr_name).unwrap();
        let s_inverse = s.inverse().unwrap();
        return PrivateKey::Leaf(q_of_zero * s_inverse, attr_name.clone());
      },
      AccessStructure::Node(thresh, children) => {
        // continue recursion, call recursively for all children and return a key node that contains children's key subtrees
        let own_poly = Polynomial::randgen(q_of_zero, thresh.clone()); // `thres`-degree polynomial determined by q_of_zero and `thresh` random coefficients
        let children_res: Vec<PrivateKey> = children.iter().enumerate().
          map(|(i, child)| self.keygen_node(child, &own_poly, Fr::from((i+1) as u64)))
          .collect();
        return PrivateKey::Node(*thresh, children_res);
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
  fn encrypt(
    &self,
    atts: &'a Vec<&'a str>,
    plaintext: &'a Vec<u8>,
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
    let mut att_cs: HashMap<&str, G1> = HashMap::new();
    for att in atts {
      let att_pubkey: &G1 = self.atts.get(att).unwrap();
      let c_i = *att_pubkey * k;
      att_cs.insert(att, c_i);
    }
    //println!("---------- ENCRYPT: encrypting with point ------------\n{:?}", c_prime.to_affine());
    let (x, y) = c_prime.coordinates();
    let x_arr = <[u8; 8 * 4]>::from(x);
    let y_arr = <[u8; 8 * 4]>::from(y);
    println!("Encryption with x {:x?}\narray: {:x?}", x, x_arr);
    println!("Encryption with y {:x?}\narray: {:x?}", y, y_arr);

    let mut sha256_hasher = sha2::Sha256::new();
    let mut mac_maker = hmac::Hmac::new(sha256_hasher, &y_arr);
    mac_maker.input(&plaintext);
    let mac = mac_maker.result();

    let mut encrypted: Vec<u8> = plaintext.clone();
    let iv: [u8; 16] = rng.gen();
    let mut aes_ctr = aes::ctr(aes::KeySize::KeySize256, &x_arr, &iv);
    aes_ctr.process(&plaintext, &mut encrypted);

    let mut full_ciphertext = Vec::from(iv);
    full_ciphertext.append(&mut encrypted);

    YaoABECiphertext {
      c: full_ciphertext,
      mac,
      c_i: att_cs,
    }
  }

  /// Recursive helper function for decryption
  fn decrypt_node(
    key: &PrivateKey,
    att_cs: &HashMap<& 'a str, G1>
  ) -> Option<G1> {
    match key {
      PrivateKey::Leaf(d_u, name) => {
        // terminate recursion - we have reached a leaf node containing a secret share. Encryption can only be successful if
        // the matching remaining part of the secret is embedded within the ciphertext (that is the case iff the ciphertext
        // was encrypted under the attribute that our current Leaf node represents)
        match att_cs.get(name) {
          None => return None,
          Some(c_i) => return Some(c_i.clone() * *d_u),
        }
      },
      PrivateKey::Node(thresh, children) => {
        // continue recursion - call for all children and then, if enough children decrypt successfully, reconstruct the secret share for 
        // this intermediate node.
        let children_result: Vec<(Fr, G1)> = children.into_iter().enumerate()
          .map(|(i, child)| (Fr::from((i + 1) as u64), Self::decrypt_node(child, att_cs))) // node indexes start at one, enumerate() starts at zero! 
          .filter_map(|(i, x)| match x { None => None, Some(y) => Some((i, y))}) // filter out all children that couldn't decrypt because of missing ciphertext secret shares
          .collect();
        // we can only reconstruct our secret share if at least `thresh` children decrypted successfully (interpolation of `thresh-1`-degree polynomial)
        if children_result.len() < *thresh as usize { return None }
        // an arbitrary subset omega with |omega| = thresh is enough to reconstruct the secret. To make it easy, we just take the first `thresh` in our list.
        let relevant_children: Vec<(Fr, G1)> = children_result.into_iter().take((*thresh).try_into().unwrap()).collect();
        let relevant_indexes: Vec<Fr> = relevant_children.iter()
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
  fn decrypt(
    &self,
    ciphertext: &'a YaoABECiphertext<'a>,
    key: &PrivateKey,
  ) -> Option<Vec<u8>> {
    let res = Self::decrypt_node(&key, &ciphertext.c_i);
    let c_prime = match res {
      None => return None,
      Some(p) => p,
    };
    let (x, y) = c_prime.coordinates();
    let mut iv: Vec<u8> = ciphertext.c.iter().take(16).map(|x| x.clone()).collect();
    let mut aes_ctr = aes::ctr(aes::KeySize::KeySize256, &(<[u8; 4 * 8]>::from(x)), &mut iv);
    let mut plaintext: Vec<u8> = Vec::new();
    plaintext.resize(ciphertext.c.len() - 16, 0);
    aes_ctr.process(&ciphertext.c[16..], &mut plaintext);

    let mut sha256_hasher = sha2::Sha256::new();
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
  use crate::*;
  use rand;
  #[test]
  fn leaf_only_access_tree() {
    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
    let (es, public) = crate::YaoABEPrivate::setup(&atts);
    //println!("{:#?}", es);
    //println!("\n public params:\n{:?}", public);

    let access_structure = crate::AccessStructure::Leaf("student");

    // //println!("access structure:\n{:#?}", access_structure);

    let priv_key = es.keygen(&access_structure);
    //println!("private key:\n{:?}", priv_key);

    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..500).map(|_| rng.gen()).collect();

    let attributes = vec!["student", "tum", "has_bachelor", "over21"];

    let ciphertext =  public.encrypt(&attributes, &data);

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

    let attributes = vec!["tum", "over21"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }

  #[test]
  fn flat_access_tree() {
    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
    let (es, public) = crate::YaoABEPrivate::setup(&atts);
    //println!("{:#?}", es);
    //println!("\n public params:\n{:#?}", public);
  
    let access_structure = AccessStructure::Node(
      2,
      vec![
        AccessStructure::Leaf("tum"),
        AccessStructure::Leaf("student"),
        AccessStructure::Leaf("has_bachelor"),
        AccessStructure::Leaf("over21"),
      ]);
  
  
    let priv_key = es.keygen(&access_structure);
    //println!("private key:\n{:?}", priv_key);
  
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..500).map(|_| rng.gen()).collect();

    let attributes = vec!["student", "tum", "has_bachelor", "over21"];
  
    let ciphertext = public.encrypt(&attributes, &data);
  
    // println!("ciphertext:\n{:?}", ciphertext);
    
    let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    
    assert_eq!(decrypted, data);
    
    // failing decryption
    let attributes = vec!["tum"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }


  #[test]
  fn malleability() {
    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
    let (es, public) = crate::YaoABEPrivate::setup(&atts);
    //println!("{:#?}", es);
    //println!("\n public params:\n{:#?}", public);
  
    let access_structure = AccessStructure::Node(
      2,
      vec![
        AccessStructure::Leaf("tum"),
        AccessStructure::Leaf("student"),
        AccessStructure::Leaf("has_bachelor"),
        AccessStructure::Leaf("over21"),
      ]);
  
  
    let priv_key = es.keygen(&access_structure);
    //println!("private key:\n{:?}", priv_key);
  
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..500).map(|_| rng.gen()).collect();
    // let mut data: Vec<u8> = (0..500).map(|_| 0).collect();

    let attributes = vec!["student", "tum", "has_bachelor", "over21"];
  
    let mut ciphertext = public.encrypt(&attributes, &data);

    assert_eq!(data, public.decrypt(&ciphertext, &priv_key).unwrap());

    ciphertext.c[16] ^= 0xaf; // skip IV
    let mut data2 = data.clone();
    data2[0] ^= 0xaf;

  
    // println!("ciphertext:\n{:?}", ciphertext);
    
    let decrypted = public.decrypt(&ciphertext, &priv_key);
    
    // decryption should fail because MAC is wrong
    assert_eq!(decrypted, None);
  }

  #[test]
  fn deep_access_tree() {

    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor", "cs"];
    let (es, public) = crate::YaoABEPrivate::setup(&atts);

    //println!("{:#?}", es);
    //println!("\n public params:\n{:?}", public);
  
    // this represents the following logical access structure
    // (tum AND student) OR (cs AND has_bachelor AND (over21 OR over25))
    let access_structure = AccessStructure::Node(
      1,
      vec![
        AccessStructure::Node(2,
          vec![
            AccessStructure::Leaf("student"),
            AccessStructure::Leaf("tum"),
          ]),
        AccessStructure::Node(3,
          vec![
            AccessStructure::Leaf("cs"),
            AccessStructure::Node(1,
              vec![
                AccessStructure::Leaf("over21"),
                AccessStructure::Leaf("over25"),
              ]),
            AccessStructure::Leaf("has_bachelor"),
          ]),
      ]); 
  
    let priv_key = es.keygen(&access_structure);
    //println!("private key:\n{:?}", priv_key);
  
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..500).map(|_| rng.gen()).collect();

    // example 1 - shall decrypt
    let attributes = vec!["student", "tum"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    assert_eq!(decrypted, data);

    // example 2 - shall decrypt
    let attributes = vec!["student", "has_bachelor", "cs", "over21"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    assert_eq!(decrypted, data);

    // example 2 - shall not decrypt
    let attributes = vec!["student", "cs", "over21"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }

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