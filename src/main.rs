//use elliptic_curve;
use p256::elliptic_curve::{Group, Field};
use p256::{Scalar, ProjectivePoint, AffinePoint};
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;


fn main() {
  
  
  let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
  let es = YaoABEPrivate::setup(&atts);
  println!("{:#?}", es);
  let public = es.to_public();
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
  // let access_structure = AccessStructure::Node(
  //   2,
  //   vec![
  //     AccessStructure::Leaf("tum"),
  //     AccessStructure::Leaf("student"),
  //     AccessStructure::Leaf("has_bachelor"),
  //     AccessStructure::Leaf("over21"),
  //   ]);
  // let access_structure = AccessStructure::Leaf("student");

  // println!("access structure:\n{:#?}", access_structure);

  // let poly = Polynomial(vec![1, 2, 3, 4].iter().map(|x| Scalar::from(x.clone())).collect());
  
  // println!("f(1) = {:?}", poly.eval(Scalar::from(1)));

  // println!("f(4) = {:?}", poly.eval(Scalar::from(4)));
  // println!("f(8100) = {:?}", poly.eval(Scalar::from(8100)));

  let priv_key = es.keygen(&access_structure);
  println!("private key:\n{:?}", priv_key);

  let data = vec![1, 2, 3];
  let attributes = vec!["student", "tum", "has_bachelor", "over21"];

  let ciphertext = YaoABEPrivate::encrypt(&public, &attributes, &data);

  // println!("ciphertext:\n{:?}", ciphertext);
  
  let decrypted = YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key).unwrap();
  
  assert_eq!(decrypted, ciphertext.secret_c);

  if let KeyAccessStructure::Leaf(d, name) = priv_key {
    let C_i = ciphertext.c_i.get(name).unwrap();
    let (s_i, _) = es.atts.get(name).unwrap();
    let C_i2 = ProjectivePoint::generator() * ciphertext.secret_k * s_i;
    let d2 = es.master_secret * s_i.invert().unwrap();
    assert_eq!(*C_i, C_i2);
    assert_eq!(d, d2);
    assert_eq!(public.pk, ProjectivePoint::generator() * es.master_secret);
    // let manual_decryption = (C_i2 * d2).to_affine();
    let manual_decryption = (es.pk * ciphertext.secret_k).to_affine();
    println!("------------ manual leaf dec ------------\n{:?}", manual_decryption);
    assert_eq!(ciphertext.secret_c, manual_decryption);
  }

  // let s = Scalar::random(&mut OsRng);
  // let s_inv = s.invert().unwrap();

  // let g = ProjectivePoint::random(&mut OsRng);

  // let c = g * s;

  // let c_dec = c * s_inv;

  // println!("s:\n{:?},\ns^-1:\n{:?},\ns * s^-1:\n{:?}", s, s_inv, s * s_inv);

  // assert_eq!(g.to_affine(), c_dec.to_affine());

}

#[derive(Debug)]
struct YaoABEPrivate<'a> {
  atts: HashMap<&'a str, (Scalar, ProjectivePoint)>,
  pk: ProjectivePoint,
  master_secret: Scalar,
}

#[derive(Debug)]
struct YaoABEPublic<'a> {
  atts: HashMap<&'a str, &'a ProjectivePoint>,
  pk: ProjectivePoint,
}

#[derive(Debug)]
enum AccessStructure<'a> {
  Node(u64, Vec<AccessStructure<'a>>), // threshold, children
  Leaf(&'a str),
}

#[derive(Debug)]
struct YaoABECiphertext<'a> {
  //omega: &Vec<&str>, // set of attributes (implied by c_i)
  c: Vec<u8>, // actual ciphertext (output of AES)
  mac: Vec<u8>, // mac over the cleartext (TODO better encrypt-then-mac?)
  c_i: HashMap<&'a str, ProjectivePoint>, // attributes and their respective curve elements
  secret_c: AffinePoint,
  secret_k: Scalar,
}

#[derive(Debug)]
struct YaoABEKey<'a>(HashMap<&'a str, Scalar>, &'a AccessStructure<'a>);

#[derive(Debug)]
enum KeyAccessStructure<'a> {
  Node(u64, Vec<KeyAccessStructure<'a>>),
  Leaf(Scalar, &'a str),
}

#[derive(Debug)]
struct Polynomial(Vec<Scalar>);

impl Polynomial {
  fn eval(&self, x: Scalar) -> Scalar {
    self.0.iter().rev().fold(Scalar::zero(), |acc, c| c + &(x * acc))
  }

  fn randgen(a0: Scalar, coeffs: u64) -> Polynomial {
    let mut coefficients = vec![a0];

    coefficients.extend((1..coeffs).map(|x| Scalar::random(&mut OsRng)));
    assert_eq!(coefficients.len() as u64, coeffs);
    Polynomial(coefficients)
  }
}

impl<'a> YaoABEPrivate<'a> {
  fn setup(att_names: &Vec<&'static str>) -> Self {
    let s = Scalar::random(&mut OsRng);
    let g = ProjectivePoint::generator();
    
    let mut att_map: HashMap<&str, (Scalar, ProjectivePoint)> = HashMap::new();
    for attr in att_names {
      let si = Scalar::random(&mut OsRng);
      let gi = g * si;
      att_map.insert(attr, (si, gi));
    }
    
    YaoABEPrivate {
      atts: att_map,
      pk: g * s,
      master_secret: s,
    }
  }

  fn to_public(&self) -> YaoABEPublic {
    YaoABEPublic {
      atts: self.atts.iter().map(|(k, (s, p))| (k.clone(), p)).collect(),
      pk: self.pk,
    }
  }

  fn keygen(
    &self,
    access_structure: &'a AccessStructure
  ) ->
    KeyAccessStructure
  { 
    // if let AccessStructure::Node(thresh, children) = access_structure {
    //   let final_ds = self.keygen_internal(access_structure, parent_poly: &Polynomial, index: Scalar)
    // }
    self.keygen_internal(
      &access_structure,
      &Polynomial::randgen(self.master_secret, 1),
      Scalar::from(0), // this is the only node ever to have index 0, all others have index 1..n
    )
    // if let AccessStructure::Leaf(att_name) = access_structure {
    //   let (s, _) = self.atts.get(att_name).unwrap();
    //   assert_eq!(self.master_secret, self.master_secret * s * &s.invert().unwrap());
    //   return KeyAccessStructure::Leaf(self.master_secret * s.invert().unwrap(), att_name.clone());
    // }
    // KeyAccessStructure::Leaf(Scalar::one(), "")
  }

  fn keygen_internal (&self,
    tree: &'a AccessStructure,
    parent_poly: &Polynomial,
    index: Scalar
  ) ->
    KeyAccessStructure
  {
    // println!("keygen_internal with index {:?}\nparent_poly(0) = {:?}\nfor node {:?}\n", index, parent_poly.eval(Scalar::zero()), tree);
    match tree {
      AccessStructure::Leaf(attr_name) => {
        let q_of_zero = parent_poly.eval(index);
        let (s, _) = self.atts.get(attr_name).unwrap();
        let s_inverse = s.invert().unwrap();
        return KeyAccessStructure::Leaf(q_of_zero * s_inverse, attr_name.clone());
      },
      AccessStructure::Node(thresh, children) => {
        let own_poly = Polynomial::randgen(parent_poly.eval(index), thresh.clone());
        let children_res: Vec<KeyAccessStructure> = children.iter().enumerate().
          map(|(i, child)| self.keygen_internal(child, &own_poly, Scalar::from((i+1) as u64)))
          .collect();
        return KeyAccessStructure::Node(*thresh, children_res);
      }
    }
  }

  fn encrypt(
    params: &YaoABEPublic,
    atts: &'a Vec<&'a str>,
    plaintext: &'a Vec<u8>,
    ) -> YaoABECiphertext<'a>
  {
    let (k, Cprime) = loop {
      let k = Scalar::random(&mut OsRng);
      let cprime = params.pk * k;
      if cprime.is_identity().unwrap_u8() == 0 { break (k, cprime) };
    };

    let mut att_cs: HashMap<&str, ProjectivePoint> = HashMap::new();
    for att in atts {
      let att_pubkey: &ProjectivePoint = params.atts.get(att).unwrap();
      let c_i = att_pubkey * &k;
      att_cs.insert(att, c_i);
    }
    println!("---------- ENCRYPT: encrypting with point ------------\n{:?}", Cprime.to_affine());

    YaoABECiphertext {
      c: Vec::new(),
      mac: Vec::new(),
      c_i: att_cs,
      secret_c: Cprime.to_affine(),
      secret_k: k,
    }
  }

  fn decrypt_node(
    key: &KeyAccessStructure,
    att_cs: &HashMap<& 'a str, ProjectivePoint>
  ) -> Option<ProjectivePoint> {
    match key {
      KeyAccessStructure::Leaf(d_u, name) => {
        match att_cs.get(name) {
          None => return None,
          Some(c_i) => return Some(c_i.clone() * d_u),
        }
      },
      KeyAccessStructure::Node(thresh, children) => {
        let children_result: Vec<(Scalar, ProjectivePoint)> = children.into_iter().enumerate()
          .map(|(i, child)| (Scalar::from((i + 1) as u64), Self::decrypt_node(child, att_cs)))
          .filter_map(|(i, x)| match x { None => None, Some(y) => Some((i, y))})
          .collect();
        if children_result.len() < *thresh as usize { return None }
        let relevant_children: Vec<(Scalar, ProjectivePoint)> = children_result.into_iter().take((*thresh).try_into().unwrap()).collect();
        let relevant_indexes: Vec<Scalar> = relevant_children.iter()
          .map(|(i, _)| i.clone()).collect();
        let result: ProjectivePoint = relevant_children.into_iter()
          .map(|(i, dec_res)| { dec_res * Self::lagrange_of_zero(&i, &relevant_indexes) } )
          .fold(ProjectivePoint::identity(), |acc, g| g + acc);
        // println!("node got result: {:?}\n at node {:?}\n", result, key);
        return Some(result);
      }
    }
  }

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

  fn decrypt(
    params: &'a YaoABEPublic,
    ciphertext: &'a YaoABECiphertext<'a>,
    key: &KeyAccessStructure,
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
    let es = crate::YaoABEPrivate::setup(&atts);
    println!("{:#?}", es);
    let public = es.to_public();
    println!("\n public params:\n{:?}", public);

    let access_structure = crate::AccessStructure::Leaf("student");

    // println!("access structure:\n{:#?}", access_structure);

    let priv_key = es.keygen(&access_structure);
    println!("private key:\n{:?}", priv_key);

    let data = vec![1, 2, 3];
    let attributes = vec!["student", "tum", "has_bachelor", "over21"];

    let ciphertext =  crate::YaoABEPrivate::encrypt(&public, &attributes, &data);

    // println!("ciphertext:\n{:?}", ciphertext);
    
    let decrypted = crate::YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key).unwrap();
    
    assert_eq!(decrypted, ciphertext.secret_c);

    match priv_key { 
      crate::KeyAccessStructure::Leaf(d, name) =>  {
        let C_i = ciphertext.c_i.get(name).unwrap();
        let (s_i, _) = es.atts.get(name).unwrap();
        let C_i2 = crate::ProjectivePoint::generator() * ciphertext.secret_k * s_i;
        let d2 = es.master_secret * s_i.invert().unwrap();
        assert_eq!(*C_i, C_i2);
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
    let ciphertext = YaoABEPrivate::encrypt(&public, &attributes, &data);
    let decrypted = YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }

  #[test]
  fn flat_access_tree() {
    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
    let es = YaoABEPrivate::setup(&atts);
    println!("{:#?}", es);
    let public = es.to_public();
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
  
    let ciphertext = YaoABEPrivate::encrypt(&public, &attributes, &data);
  
    // println!("ciphertext:\n{:?}", ciphertext);
    
    let decrypted = YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key).unwrap();
    
    assert_eq!(decrypted, ciphertext.secret_c);
    
    // failing decryption
    let attributes = vec!["tum"];
    let ciphertext = YaoABEPrivate::encrypt(&public, &attributes, &data);
    let decrypted = YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key);
    assert_eq!(None, decrypted);
  }

  #[test]
  fn deep_access_tree() {

    let atts = vec!["student", "tum", "over21", "over25", "has_bachelor", "cs"];
    let es = YaoABEPrivate::setup(&atts);
    println!("{:#?}", es);
    let public = es.to_public();
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
    let ciphertext = YaoABEPrivate::encrypt(&public, &attributes, &data);
    let decrypted = YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key).unwrap();
    assert_eq!(decrypted, ciphertext.secret_c);

    // example 2 - shall decrypt
    let attributes = vec!["student", "has_bachelor", "cs", "over21"];
    let ciphertext = YaoABEPrivate::encrypt(&public, &attributes, &data);
    let decrypted = YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key).unwrap();
    assert_eq!(decrypted, ciphertext.secret_c);

    // example 2 - shall not decrypt
    let attributes = vec!["student", "cs", "over21"];
    let ciphertext = YaoABEPrivate::encrypt(&public, &attributes, &data);
    let decrypted = YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key);
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