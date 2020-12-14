//use elliptic_curve;
use p256::elliptic_curve::{Group, Field};
use p256::{Scalar, ProjectivePoint, AffinePoint};
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;


fn main() {
  
  
  let atts = vec!["student", "tum", "over21"];
  let es = YaoABEPrivate::setup(&atts);
  println!("{:#?}", es);
  let public = es.to_public();
  println!("\n public params:\n{:#?}", public);

  // let access_structure = AccessStructure::Node(
  //   2,
  //   vec![AccessStructure::Leaf("over21"), AccessStructure::Leaf("tum")]
  // );
  let access_structure = AccessStructure::Leaf("student");

  println!("{:#?}", access_structure);

  // let poly = Polynomial(vec![1, 2, 3, 4].iter().map(|x| Scalar::from(x.clone())).collect());
  
  // println!("f(1) = {:?}", poly.eval(Scalar::from(1)));

  // println!("f(4) = {:?}", poly.eval(Scalar::from(4)));
  // println!("f(8100) = {:?}", poly.eval(Scalar::from(8100)));

  let priv_key = es.keygen(&access_structure);
  println!("{:?}", priv_key);

  let data = vec![1, 2, 3];
  let attributes = vec!["student", "tum"];

  let ciphertext = YaoABEPrivate::encrypt(&public, &attributes, &data);
  
  //let decrypted = YaoABEPrivate::decrypt(&public, &ciphertext, &priv_key);

  if let KeyAccessStructure::Leaf(d, name) = priv_key {
    println!("------------ manual leaf dec ------------\n{:?}", (ciphertext.c_i.get(name).unwrap() * &d).to_affine());
  }
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
    let g = ProjectivePoint::random(&mut OsRng);
    
    let mut att_map: HashMap<&str, (Scalar, ProjectivePoint)> = HashMap::new();
    for attr in att_names {
      let si = Scalar::random(&mut OsRng);
      let gi = g * si;
      att_map.insert(attr, (si, gi));
    }
    
    YaoABEPrivate {
      atts: att_map,
      pk: g,
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
  }

  fn keygen_internal (&self,
    tree: &'a AccessStructure,
    parent_poly: &Polynomial,
    index: Scalar
  ) ->
    KeyAccessStructure
  {
    match tree {
      AccessStructure::Leaf(attr_name) => {
        let q_of_zero = parent_poly.eval(Scalar::zero());
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
          .map(|(i, dec_res)| dec_res * Self::lagrange_of_zero(&i, &relevant_indexes))
          .fold(ProjectivePoint::identity(), |acc, g| g + acc);
        return Some(result);
      }
    }
  }

  fn lagrange_of_zero(i: &Scalar, omega: &Vec<Scalar>) -> Scalar {
    omega.iter()
      .filter(|x| *x != i)
      .map(|j| -*j * (i-j).invert().unwrap())
      .fold(Scalar::one(), |acc, x| acc * x)
  }

  fn decrypt(
    params: &'a YaoABEPublic,
    ciphertext: &'a YaoABECiphertext<'a>,
    key: &KeyAccessStructure,
  ) -> Vec<u8> {
    let res = Self::decrypt_node(&key, &ciphertext.c_i);
    match res {
      Some(p) => println!("--------- DECRYPT decrypted root to ----------\n{:?}", p.to_affine()),
      None => println!("--------- DECRYPT failed ----------")
    }
    Vec::new()
  }
}
