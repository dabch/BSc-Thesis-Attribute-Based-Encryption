// use rabe_bn::{Fr, G1, G2, Gt};
use rand::{self, Rng, RngCore};
use std::time::Instant;

// use yao_abe_rust::{AccessNode, AccessStructure, YaoABEPrivate, YaoABEPublic, F, G, S};
use gpsw06_abe::{GpswAbeCiphertext, GpswAbePrivate, GpswAbePublic, AccessNode, AccessStructure, G1, G2, F, S};
use heapless::{consts, FnvIndexMap, Vec};

use abe_utils::{policies_deep_ternary, policies_deep_binary};

const SMPL_CNT: u128 = 10;

type PUBLIC<'a, 'b> = GpswAbePublic<'a, 'b>;
type PRIVATE<'a, 'b> = GpswAbePrivate<'a, 'b>;
type ACCESS_NODE<'a> = AccessNode<'a>;

type PUBLIC_MAP = G2;
type PRIVATE_MAP = F;

fn main() {
    let mut rng = rand::thread_rng();

    let system_atts: Vec<&str, S> = Vec::from_slice(&[
        "att01", "att02", "att03", "att04", "att05", "att06", "att07", "att08", "att09", "att10",
        "att11", "att12", "att13", "att14", "att15", "att16", "att17", "att18", "att19", "att20",
        "att21", "att22", "att23", "att24", "att25", "att26", "att27", "att28", "att29", "att30",
    ])
    .unwrap();
    let mut public_map: FnvIndexMap<&str, PUBLIC_MAP, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, PRIVATE_MAP, S> = FnvIndexMap::new();

    // println!("Setup");
    // for i in 1..31 {
    //     let mut us = 0;
    //     for _ in 0..SMPL_CNT {
    //         // rprintln!("starting setup");
            // let mut public_map: FnvIndexMap<&str, PUBLIC_MAP, S> = FnvIndexMap::new();
            // let mut private_map: FnvIndexMap<&str, PRIVATE_MAP, S> = FnvIndexMap::new();
    //         let start = Instant::now();
            // let (private, public) = PRIVATE::setup(&system_atts[..i], &mut public_map, &mut private_map, &mut rng);
    //         us += Instant::now().duration_since(start).as_micros();
    //     }
    //     println!("{};{:?}", i, us / SMPL_CNT);
    // }

    let (private, public) =
        PRIVATE::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);

    println!("Encrypt");
    let mut data: [u8; 256] = [0; 256];
    rng.fill_bytes(&mut data);

    let atts = ["att12", "att29", "att07", "att10", "att22", "att24", "att23", "att18", "att08", "att06", "att14", "att11", "att25", "att02", "att09", "att26", "att03", "att20", "att04", "att30", "att01", "att21", "att15", "att19", "att05", "att13", "att17", "att27", "att16", "att28"];
    // let i = 30;
    // for i in 1..31 {
    //     // rprintln!("starting setup");
    //     let mut us = 0;
    //     for _ in 0..SMPL_CNT {
    //         let start = Instant::now();
            // let ciphertext = public.encrypt(&atts[..i], &mut data, &mut rng).unwrap();
    //         us += Instant::now().duration_since(start).as_micros();
    //     }
    //     println!("{};{:?}", i, us / SMPL_CNT);
    // }

    println!("KeyGen");

    let ciphertext = public.encrypt(&system_atts, &mut data, &mut rng).unwrap();

    // let policies_3: &[&[AccessNode]] = policies_deep_ternary!();
    // let policies_2: &[&[AccessNode]] = policies_deep_binary!();

    // let i = 0;

    // let key = private.keygen(&public, policies_2[i], &mut rng);

    // let plain = PUBLIC::decrypt(ciphertext, &key);

    // rng.fill_bytes(&mut data);
    // println!("keygen;dec");
    // for i in 0..policies.len() {
    //     // rprintln!("starting setup");
    //     let mut keygen_us = 0;
    //     let mut dec_us = 0;
    //     for _ in 0..SMPL_CNT {
    //         let mut data_cpy = data.clone();
    //         let ciphertext = public.encrypt(&atts, &mut data_cpy, &mut rng).unwrap();

    //         let start = Instant::now();
    //         let key = private.keygen(&public, policies[i], &mut rng);
    //         keygen_us += Instant::now().duration_since(start).as_micros();

    //         let start = Instant::now();
    //         let data_recovered = PUBLIC::decrypt(ciphertext, &key).unwrap();
    //         dec_us += Instant::now().duration_since(start).as_micros();
    //         assert_eq!(data_recovered, data);
            
    //     }
    //     println!(
    //         "{};{}",
    //         keygen_us / (SMPL_CNT as u128),
    //         dec_us / (SMPL_CNT as u128)
    //     );
    // }
    // let access_structure: AccessStructure = &[
    //   AccessNode::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
    //   AccessNode::Leaf("tum"),
    //   AccessNode::Leaf("student"),
    //   AccessNode::Leaf("has_bachelor"),
    //   AccessNode::Leaf("over21"),
    // ];
}
