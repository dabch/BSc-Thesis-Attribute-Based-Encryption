use p256::elliptic_curve::{Group, Field};
use p256::{Scalar, ProjectivePoint, AffinePoint};
use rand_core::OsRng;
use std::collections::HashMap;
use std::convert::TryInto;


fn main() {
  
  
  let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
  let (es, public) = YaoABEPrivate::setup(&atts);
  println!("{:#?}", es);
  println!("\n public params:\n{:#?}", public);

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
  println!("private key:\n{:?}", priv_key);

  let data = vec![1, 2, 3];
  let attributes = vec!["student", "tum", "has_bachelor", "over21"];

  let ciphertext = public.encrypt(&attributes, &data);

  
  let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
  
  assert_eq!(decrypted, ciphertext.secret_c);

  if let PrivateKey::Leaf(d, name) = priv_key {
    let c_i = ciphertext.c_i.get(name).unwrap();
    let (s_i, _) = es.atts.get(name).unwrap();
    let c_i2 = ProjectivePoint::generator() * ciphertext.secret_k * s_i;
    let d2 = es.master_secret * s_i.invert().unwrap();
    assert_eq!(*c_i, c_i2);
    assert_eq!(d, d2);
    assert_eq!(public.pk, ProjectivePoint::generator() * es.master_secret);
    // let manual_decryption = (C_i2 * d2).to_affine();
    let manual_decryption = (es.pk * ciphertext.secret_k).to_affine();
    println!("------------ manual leaf dec ------------\n{:?}", manual_decryption);
    assert_eq!(ciphertext.secret_c, manual_decryption);
  }

}

/// Represents the full parameters of an ABE scheme, known in full only to the KGC
#[derive(Debug)]
struct YaoABEPrivate<'a> {
  atts: HashMap<&'a str, (Scalar, ProjectivePoint)>,
  pk: ProjectivePoint,
  master_secret: Scalar,
}

/// represents the public ABE parameters, known to all participants and used for encryption, decryption and the like
#[derive(Debug)]
struct YaoABEPublic<'a> {
  atts: HashMap<&'a str, ProjectivePoint>,
  pk: ProjectivePoint,
}

/// represents an access structure that defines the powers of a key.
/// This is passed to keygen() by the KGC, and then embedded in the private key issued to the user.
#[derive(Debug)]
enum AccessStructure<'a> {
  Node(u64, Vec<AccessStructure<'a>>), // threshold, children
  Leaf(&'a str),
}

/// Represents a ciphertext as obtained by encrypt() and consumed by decrypt()
/// Contains both the actual (symetrically) encrypted data and all data required to reconstruct the 
/// symmetric keys given a private key created under a matching access structure.
#[derive(Debug)]
struct YaoABECiphertext<'a> {
  c: Vec<u8>, // actual ciphertext (output of AES)
  mac: Vec<u8>, // mac over the cleartext (TODO better encrypt-then-mac?)
  c_i: HashMap<&'a str, ProjectivePoint>, // attributes and their respective curve elements
  secret_c: AffinePoint,
  secret_k: Scalar,
}

/// Represents a private key obtained by keygen() and used to decrypt ABE-encrypted data
/// This data structure mirrors the recursive nature of access structures to ease implementation
/// of decryption. The secret shared (D_u in the original paper) allowing decryption are embedded
/// in the leaves of the tree.
#[derive(Debug)]
enum PrivateKey<'a> {
  Node(u64, Vec<PrivateKey<'a>>),
  Leaf(Scalar, &'a str),
}

/// Polynomial p(x) = a0 + a1 * x + a2 * x^2 + ... defined by a vector of coefficients [a0, a1, a2, ...]
#[derive(Debug)]
struct Polynomial(Vec<Scalar>);

impl Polynomial {
  /// Evaluates the polynomial p(x) at a given x
  fn eval(&self, x: Scalar) -> Scalar {
    self.0.iter().rev().fold(Scalar::zero(), |acc, c| c + &(x * acc))
  }

  /// Generates a random polynomial p(x) of degree `coeffs` coefficients, where p(0) = `a0`
  fn randgen(a0: Scalar, coeffs: u64) -> Polynomial {
    let mut coefficients = vec![a0];

    coefficients.extend((1..coeffs).map(|_| Scalar::random(&mut OsRng)));
    assert_eq!(coefficients.len() as u64, coeffs);
    Polynomial(coefficients)
  }

  /// Calculates the langrage base polynomials l_i(x) for given set of indices omega and the index i.
  /// As we only ever need to interpolate p(0), no value for x may be passed.
  fn lagrange_of_zero(i: &Scalar, omega: &Vec<Scalar>) -> Scalar {
    println!("LAGRANGE: {:?}\n{:?}", i, omega);
    let r = omega.iter()
      .filter(|x| *x != i)
      .map(|x| { println!("{:?}", x); x} )
      .map(|j| -*j * (i-j).invert().unwrap())
      .fold(Scalar::one(), |acc, x| acc * x);
    println!("\n");
    r
  }
}

impl<'a> YaoABEPrivate<'a> {

  /// Corresponds to the `(A) Setup` phase in the original paper. Sets up an encryption scheme with a fixed set of attributes and 
  /// generates both public and private parameter structs. This is typically run exactly once by the KGC.
  fn setup(att_names: &Vec<&'static str>) -> (Self, YaoABEPublic<'a>) {
    let master_secret = Scalar::random(&mut OsRng); // corresponds to "s" in the original paper
    let g = ProjectivePoint::generator();
    
    // save all attributes with their corresponding public and private parameters (private is needed by kgc for key generation)
    let mut att_map: HashMap<&str, (Scalar, ProjectivePoint)> = HashMap::new();

    // for each attribute, choose a private field element s_i and make G * s_i public
    for attr in att_names {
      let si = Scalar::random(&mut OsRng);
      let gi = g * si;
      att_map.insert(attr, (si, gi));
    }
    
    let pk = g * master_secret; // master public key, corresponds to `PK`

    // create equivalend HashMap for public parameters, but of course remove the private parameters for each attribute
    let atts_public: HashMap<&str, ProjectivePoint> = att_map.iter().map(|(k, (_, p))| (k.clone(), p.clone())).collect();

    (
      YaoABEPrivate {
        atts: att_map,
        pk,
        master_secret,
      },
      YaoABEPublic {
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
      Scalar::from(0), // this is the only node ever to have index 0, all others have index 1..n
    )
  }

  /// internal recursive helper to ease key generation
  fn keygen_node (&self,
    tree: &'a AccessStructure,
    parent_poly: &Polynomial,
    index: Scalar
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
        let s_inverse = s.invert().unwrap();
        return PrivateKey::Leaf(q_of_zero * s_inverse, attr_name.clone());
      },
      AccessStructure::Node(thresh, children) => {
        // continue recursion, call recursively for all children and return a key node that contains children's key subtrees
        let own_poly = Polynomial::randgen(q_of_zero, thresh.clone()); // `thres`-degree polynomial determined by q_of_zero and `thresh` random coefficients
        let children_res: Vec<PrivateKey> = children.iter().enumerate().
          map(|(i, child)| self.keygen_node(child, &own_poly, Scalar::from((i+1) as u64)))
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
    _plaintext: &'a Vec<u8>,
    ) -> YaoABECiphertext<'a>
  {
    // choose a C', which is then used to encrypt the actual plaintext with a symmetric cipher
    let (k, c_prime) = loop {
      let k = Scalar::random(&mut OsRng);
      let cprime = self.pk * k;
      if cprime.is_identity().unwrap_u8() == 0 { break (k, cprime) };
    };

    // Store the information needed to reconstruct C' under a matching key. For each attribute, only a single point
    // multiplication is calculated.
    let mut att_cs: HashMap<&str, ProjectivePoint> = HashMap::new();
    for att in atts {
      let att_pubkey: &ProjectivePoint = self.atts.get(att).unwrap();
      let c_i = att_pubkey * &k;
      att_cs.insert(att, c_i);
    }
    println!("---------- ENCRYPT: encrypting with point ------------\n{:?}", c_prime.to_affine());

    YaoABECiphertext {
      c: Vec::new(),
      mac: Vec::new(),
      c_i: att_cs,
      // the following two are only for debugging and testing, and will be removed as soon as actual encryption is implemented.
      secret_c: c_prime.to_affine(),
      secret_k: k,
    }
  }

  /// Recursive helper function for decryption
  fn decrypt_node(
    key: &PrivateKey,
    att_cs: &HashMap<& 'a str, ProjectivePoint>
  ) -> Option<ProjectivePoint> {
    match key {
      PrivateKey::Leaf(d_u, name) => {
        // terminate recursion - we have reached a leaf node containing a secret share. Encryption can only be successful if
        // the matching remaining part of the secret is embedded within the ciphertext (that is the case iff the ciphertext
        // was encrypted under the attribute that our current Leaf node represents)
        match att_cs.get(name) {
          None => return None,
          Some(c_i) => return Some(c_i.clone() * d_u),
        }
      },
      PrivateKey::Node(thresh, children) => {
        // continue recursion - call for all children and then, if enough children decrypt successfully, reconstruct the secret share for 
        // this intermediate node.
        let children_result: Vec<(Scalar, ProjectivePoint)> = children.into_iter().enumerate()
          .map(|(i, child)| (Scalar::from((i + 1) as u64), Self::decrypt_node(child, att_cs))) // node indexes start at one, enumerate() starts at zero! 
          .filter_map(|(i, x)| match x { None => None, Some(y) => Some((i, y))}) // filter out all children that couldn't decrypt because of missing ciphertext secret shares
          .collect();
        // we can only reconstruct our secret share if at least `thresh` children decrypted successfully (interpolation of `thresh-1`-degree polynomial)
        if children_result.len() < *thresh as usize { return None }
        // an arbitrary subset omega with |omega| = thresh is enough to reconstruct the secret. To make it easy, we just take the first `thresh` in our list.
        let relevant_children: Vec<(Scalar, ProjectivePoint)> = children_result.into_iter().take((*thresh).try_into().unwrap()).collect();
        let relevant_indexes: Vec<Scalar> = relevant_children.iter()
          .map(|(i, _)| i.clone()).collect(); // our langrange helper function wants this vector of field elements
        let result: ProjectivePoint = relevant_children.into_iter()
          .map(|(i, dec_res)| { dec_res * Polynomial::lagrange_of_zero(&i, &relevant_indexes) } )
          .fold(ProjectivePoint::identity(), |acc, g| g + acc);
        // println!("node got result: {:?}\n at node {:?}\n", result, key);
        return Some(result);
      }
    }
  }

  /// Decrypt a ciphertext using a given private key. At this point, doesn't actually do any decryption, it just reconstructs the point used as encryption/mac key.
  fn decrypt(
    &self,
    ciphertext: &'a YaoABECiphertext<'a>,
    key: &PrivateKey,
  ) -> Option<AffinePoint> {
    let res = Self::decrypt_node(&key, &ciphertext.c_i);
    match res {
      Some(p) => { println!("--------- DECRYPT decrypted root to ----------\n{:?}", p.to_affine()); return Some(p.to_affine()) },
      None => { println!("--------- DECRYPT failed ----------"); return None }
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::*;
  #[test]
  fn leaf_only_access_tree() {
    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
    let (es, public) = crate::YaoABEPrivate::setup(&atts);
    println!("{:#?}", es);
    println!("\n public params:\n{:?}", public);

    let access_structure = crate::AccessStructure::Leaf("student");

    // println!("access structure:\n{:#?}", access_structure);

    let priv_key = es.keygen(&access_structure);
    println!("private key:\n{:?}", priv_key);

    let data = vec![1, 2, 3];
    let attributes = vec!["student", "tum", "has_bachelor", "over21"];

    let ciphertext =  public.encrypt(&attributes, &data);

    // println!("ciphertext:\n{:?}", ciphertext);
    
    let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();  

    assert_eq!(decrypted, ciphertext.secret_c);

    match priv_key { 
      crate::PrivateKey::Leaf(d, name) =>  {
        let c_i = ciphertext.c_i.get(name).unwrap();
        let (s_i, _) = es.atts.get(name).unwrap();
        let c_i2 = crate::ProjectivePoint::generator() * ciphertext.secret_k * s_i;
        let d2 = es.master_secret * s_i.invert().unwrap();
        assert_eq!(*c_i, c_i2);
        assert_eq!(d, d2);
        assert_eq!(public.pk, crate::ProjectivePoint::generator() * es.master_secret);
        // let manual_decryption = (C_i2 * d2).to_affine();
        let manual_decryption = (es.pk * ciphertext.secret_k).to_affine();
        println!("------------ manual leaf dec ------------\n{:?}", manual_decryption);
        assert_eq!(ciphertext.secret_c, manual_decryption);
      },
      _ => assert!(false),
    }

    let attributes = vec!["tum", "over21"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }

  #[test]
  fn flat_access_tree() {
    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
    let (es, public) = crate::YaoABEPrivate::setup(&atts);
    println!("{:#?}", es);
    println!("\n public params:\n{:#?}", public);
  
    let access_structure = AccessStructure::Node(
      2,
      vec![
        AccessStructure::Leaf("tum"),
        AccessStructure::Leaf("student"),
        AccessStructure::Leaf("has_bachelor"),
        AccessStructure::Leaf("over21"),
      ]);
  
  
    let priv_key = es.keygen(&access_structure);
    println!("private key:\n{:?}", priv_key);
  
    let data = vec![1, 2, 3];
    let attributes = vec!["student", "tum", "has_bachelor", "over21"];
  
    let ciphertext = public.encrypt(&attributes, &data);
  
    // println!("ciphertext:\n{:?}", ciphertext);
    
    let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    
    assert_eq!(decrypted, ciphertext.secret_c);
    
    // failing decryption
    let attributes = vec!["tum"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }

  #[test]
  fn deep_access_tree() {

    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor", "cs"];
    let (es, public) = crate::YaoABEPrivate::setup(&atts);

    println!("{:#?}", es);
    println!("\n public params:\n{:?}", public);
  
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
    println!("private key:\n{:?}", priv_key);
  
    let data = vec![1, 2, 3];

    // example 1 - shall decrypt
    let attributes = vec!["student", "tum"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    assert_eq!(decrypted, ciphertext.secret_c);

    // example 2 - shall decrypt
    let attributes = vec!["student", "has_bachelor", "cs", "over21"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    assert_eq!(decrypted, ciphertext.secret_c);

    // example 2 - shall not decrypt
    let attributes = vec!["student", "cs", "over21"];
    let ciphertext = public.encrypt(&attributes, &data);
    let decrypted = public.decrypt(&ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }
  
  #[test]
  fn poly_eval() {

    let poly = crate::Polynomial(vec![1, 2, 3, 4].iter().map(|x| crate::Scalar::from(x.clone())).collect());

    let closure = |x: u64| { 1 + 2 * x + 3 * x * x + 4 * x * x * x };
    
    assert_eq!(Scalar::from(closure(1)), poly.eval(Scalar::from(1)));

    assert_eq!(Scalar::from(closure(4)), poly.eval(Scalar::from(4)));
    assert_eq!(Scalar::from(closure(8100)), poly.eval(Scalar::from(8100)));
  }

  #[test]
  fn curve_operations_dry_run() {

    let s = Scalar::random(&mut OsRng);
    let s_inv = s.invert().unwrap();

    let g = ProjectivePoint::random(&mut OsRng);

    let c = g * s;

    let c_dec = c * s_inv;
    assert_eq!(g.to_affine(), c_dec.to_affine());

  }
}