#![no_std]
pub use yao_abe::*;

mod yao_abe;

// fn main() {
  
  
//   let atts = vec!["student", "tum", "over21", "over25", "has_bachelor"];
//   let (es, public) = YaoABEPrivate::setup(&atts);
//   //println!("{:#?}", es);
//   //println!("\n public params:\n{:#?}", public);

//   let access_structure = AccessStructure::Node(
//     2,
//     vec![
//       AccessStructure::Leaf("tum"),
//       AccessStructure::Node(2,
//         vec![
//           AccessStructure::Leaf("student"),
//           AccessStructure::Leaf("has_bachelor"),
//         ]),
//     ]); 

//   let priv_key = es.keygen(&access_structure);
//   //println!("private key:\n{:?}", priv_key);

  
//   let mut rng = rand::thread_rng();
//   let data: Vec<u8> = (0..500).map(|_| rng.gen()).collect();

//   let attributes = vec!["student", "tum", "has_bachelor", "over21"];

  
//   let ciphertext = public.encrypt(&attributes, &data);

  
//   let decrypted = public.decrypt(&ciphertext, &priv_key);
  
//   assert_eq!(data, decrypted.unwrap());
// }

