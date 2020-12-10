//use elliptic_curve;
use p256::elliptic_curve::{Group, Field};
use p256::{Scalar, ProjectivePoint, AffinePoint};
use rand_core::OsRng;
use std::collections::HashMap;

fn main() {
  
  
  let atts = vec!["student", "tum", "over21"];
  let es = YaoABE::setup(&atts);
  println!("{:#?}", es);
}

#[derive(Debug)]
struct YaoABE<'a> {
  atts: HashMap<&'a str, (Scalar, ProjectivePoint)>,
  pk: ProjectivePoint,
  master_secret: Scalar,
}

impl YaoABE<'_> {
  fn setup(att_names: &Vec<&'static str>) -> Self {
    let s = Scalar::random(&mut OsRng);
    let g = ProjectivePoint::random(&mut OsRng);
    
    let mut att_map: HashMap<&str, (Scalar, ProjectivePoint)> = HashMap::new();
    for attr in att_names {
      let si = Scalar::random(&mut OsRng);
      let gi = g * si;
      att_map.insert(attr, (si, gi));
    }

    YaoABE {
      atts: att_map,
      pk: g,
      master_secret: s,
    }
  }

  //fn encrypt(pk: ProjectivePoint, atts: &Vec<&str>, plaintext: Vec<u8>) -> {
//
  //}
}
