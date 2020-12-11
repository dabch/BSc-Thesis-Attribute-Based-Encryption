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

struct YaoABECiphertext<'a> {
  //omega: &Vec<&str>, // set of attributes (implied by c_i)
  c: Vec<u8>, // actual ciphertext (output of AES)
  mac: Vec<u8>, // mac over the cleartext (TODO better encrypt-then-mac?)
  c_i: HashMap<&'a str, ProjectivePoint>, // attributes and their respective curve elements
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
