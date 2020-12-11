//use elliptic_curve;
use p256::elliptic_curve::{Group, Field};
use p256::{Scalar, ProjectivePoint, AffinePoint};
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};


fn main() {
  
  
  let atts = vec!["student", "tum", "over21"];
  let es = YaoABEPrivate::setup(&atts);
  println!("{:#?}", es);
  let public = es.to_public();
  println!("\n public params:\n{:#?}", public);

  let access_structure = AccessStructure::Node(
    2,
    vec![AccessStructure::Leaf("student"), AccessStructure::Leaf("tum")]
  );

  println!("{:#?}", access_structure);

  // let poly = Polynomial(vec![1, 2, 3, 4].iter().map(|x| Scalar::from(x.clone())).collect());
  
  // println!("f(1) = {:?}", poly.eval(Scalar::from(1)));

  // println!("f(4) = {:?}", poly.eval(Scalar::from(4)));
  // println!("f(8100) = {:?}", poly.eval(Scalar::from(8100)));
  // println!("{:?}", Scalar::from(1225));

  // println!("randgen(125, 5) = {:#?}", Polynomial::randgen(Scalar::from(125), 5));

  // let vecvec = vec![vec![1, 2, 3, 4], vec![5, 6, 7], vec![8, 9, 10, 11]];

  // println!("{:?}", vecvec.into_iter().flatten().collect::<Vec<i64>>());

  let priv_key = es.keygen(access_structure);
  println!("{:?}", priv_key);
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
struct YaoABEKey(Vec<Scalar>);

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
    access_structure: AccessStructure
  ) ->
    YaoABEKey
  { 
    // if let AccessStructure::Node(thresh, children) = access_structure {
    //   let final_ds = self.keygen_internal(access_structure, parent_poly: &Polynomial, index: Scalar)
    // }
    let final_ds = self.keygen_internal(
      &access_structure,
      &Polynomial::randgen(self.master_secret, 1),
      Scalar::from(1)
    );
    YaoABEKey(final_ds)
  }

  fn keygen_internal(&self,
    tree: &AccessStructure,
    parent_poly: &Polynomial,
    index: Scalar
  ) ->
    Vec<Scalar>
  {
    match tree {
      AccessStructure::Leaf(attr_name) => {
        let q_of_zero = parent_poly.eval(Scalar::zero());
        let (s, _) = self.atts.get(attr_name).unwrap();
        let s_inverse = s.invert().unwrap();
        return vec![q_of_zero * s_inverse];
      },
      AccessStructure::Node(thresh, children) => {
        let own_poly = Polynomial::randgen(parent_poly.eval(index), thresh.clone());
        let children_res: Vec<Scalar> = children.iter().enumerate().
          map(|(i, child)| self.keygen_internal(child, &own_poly, Scalar::from(i as u64))).
          flatten().
          collect();
        return children_res;
      }
    }
    Vec::new()
  }

  fn encrypt(
    params: YaoABEPublic,
    atts: &'a Vec<&'a str>,
    plaintext: &'a Vec<u8>,
    ) -> YaoABECiphertext<'a>
  {
    let (k, Cprime) = loop {
      let k = Scalar::random(&mut OsRng);
      let Cprime = params.pk * k;
      if Cprime.is_identity().unwrap_u8() == 0 { break (k, Cprime) };
    };

    let mut att_cs: HashMap<&str, ProjectivePoint> = HashMap::new();
    for att in atts {
      let att_pubkey: &ProjectivePoint = params.atts.get(att).unwrap();
      let c_i = att_pubkey * &k;
      att_cs.insert(att, c_i);
    }

    YaoABECiphertext {
      c: Vec::new(),
      mac: Vec::new(),
      c_i: att_cs,
    }
  }
}
