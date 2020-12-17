use criterion::{black_box, criterion_group, criterion_main, Criterion};
use yao_abe_rust::{YaoABEPublic, YaoABEPrivate, AccessStructure};
use rand::Rng;


fn deep_access_tree() {

  let atts = vec!["student", "tum", "over21", "over25", "has_bachelor", "cs"];
  let (es, public) = YaoABEPrivate::setup(&atts);

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

fn criterion_benchmark(c: &mut Criterion) {
  let atts = vec!["student", "tum", "over21", "over25", "has_bachelor", "cs"];
    let (es, public) = YaoABEPrivate::setup(&atts);

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

    c.bench_function("deep tree encryption / decryption", |b| b.iter(|| public.encrypt(&attributes, &data)));

    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    // assert_eq!(decrypted, data);

    // // example 2 - shall decrypt
    // let attributes = vec!["student", "has_bachelor", "cs", "over21"];
    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    // assert_eq!(decrypted, data);

    // // example 2 - shall not decrypt
    // let attributes = vec!["student", "cs", "over21"];
    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key);
    // assert_eq!(None, decrypted);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);