// use rabe_bn::{Fr, G1, G2, Gt};
use rand::{self, Rng, RngCore};
use std::time::Instant;

use yao_abe_rust::{AccessNode, AccessStructure, YaoABEPrivate, YaoABEPublic, F, G, S};
// use gpsw06_abe::{GpswAbeCiphertext, GpswAbePrivate, GpswAbePublic, AccessNode, AccessStructure, G1, G2, F, S};
use heapless::{consts, FnvIndexMap, Vec};

const SMPL_CNT: u128 = 100;

type PUBLIC<'a, 'b> = YaoABEPublic<'a, 'b>;
type PRIVATE<'a, 'b> = YaoABEPrivate<'a, 'b>;
type ACCESS_NODE<'a> = AccessNode<'a>;

type PUBLIC_MAP = G;
type PRIVATE_MAP = (F, G);

fn main() {
    let mut rng = rand::thread_rng();

    let system_atts: Vec<&str, S> = Vec::from_slice(&[
        "att01", "att02", "att03", "att04", "att05", "att06", "att07", "att08", "att09", "att10",
        "att11", "att12", "att13", "att14", "att15", "att16", "att17", "att18", "att19", "att20",
        "att21", "att22", "att23", "att24", "att25", "att26", "att27", "att28", "att29", "att30",
    ])
    .unwrap();
    // let access_structure = &[
    //   ACCESS_NODE::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
    //   ACCESS_NODE::Leaf("tum"),
    //   ACCESS_NODE::Leaf("student"),
    //   ACCESS_NODE::Leaf("has_bachelor"),
    //   ACCESS_NODE::Leaf("over21"),
    // ];

    let mut public_map: FnvIndexMap<&str, PUBLIC_MAP, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, PRIVATE_MAP, S> = FnvIndexMap::new();

    // println!("Setup");
    // for i in 1..31 {
    //     let mut us = 0;
    //     for _ in 0..SMPL_CNT {
    //         // rprintln!("starting setup");
    //         let mut public_map: FnvIndexMap<&str, PUBLIC_MAP, S> = FnvIndexMap::new();
    //         let mut private_map: FnvIndexMap<&str, PRIVATE_MAP, S> = FnvIndexMap::new();
    //         let start = Instant::now();
    //         let (private, public) = PRIVATE::setup(&system_atts[..i], &mut public_map, &mut private_map, &mut rng);
    //         us += Instant::now().duration_since(start).as_micros();
    //     }
    //     println!("{};{:?}", i, us / SMPL_CNT);
    // }

    let (private, public) =
        PRIVATE::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);

    // println!("Encrypt");
    // let mut data: [u8; 256] = [0; 256];
    // rng.fill_bytes(&mut data);

    // let atts = ["att12", "att29", "att07", "att10", "att22", "att24", "att23", "att18", "att08", "att06", "att14", "att11", "att25", "att02", "att09", "att26", "att03", "att20", "att04", "att30", "att01", "att21", "att15", "att19", "att05", "att13", "att17", "att27", "att16", "att28"];
    // for i in 1..31 {
    //     // rprintln!("starting setup");
    //     let mut us = 0;
    //     for _ in 0..SMPL_CNT {
    //         let start = Instant::now();
    //         let ciphertext = public.encrypt(&atts[..i], &mut data, &mut rng).unwrap();
    //         us += Instant::now().duration_since(start).as_micros();
    //     }
    //     println!("{};{:?}", i, us / SMPL_CNT);
    // }

    println!("KeyGen");
    // let SET_A: &[AccessStructure] = &[
       
    // ];
    // let access_structures: &[AccessStructure] = &[
    //     &[AccessNode::Leaf("att12")],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 2]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //     ],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Leaf("att07"),
    //     ],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Node(2, Vec::from_slice(&[5, 6]).unwrap()),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Leaf("att10"),
    //     ],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3, 7]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Node(2, Vec::from_slice(&[5, 6]).unwrap()),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Leaf("att10"),
    //         AccessNode::Leaf("att22"),
    //     ],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3, 7]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Node(2, Vec::from_slice(&[5, 6, 8]).unwrap()),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Leaf("att10"),
    //         AccessNode::Leaf("att22"),
    //         AccessNode::Leaf("att24"),
    //     ],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3, 7]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Node(2, Vec::from_slice(&[5, 6, 8]).unwrap()),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Leaf("att10"),
    //         AccessNode::Leaf("att22"),
    //         AccessNode::Node(2, Vec::from_slice(&[9, 10]).unwrap()),
    //         AccessNode::Leaf("att24"),
    //         AccessNode::Leaf("att23"),
    //     ],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3, 7]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Node(2, Vec::from_slice(&[5, 6, 8]).unwrap()),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Leaf("att10"),
    //         AccessNode::Leaf("att22"),
    //         AccessNode::Node(3, Vec::from_slice(&[9, 10, 11]).unwrap()),
    //         AccessNode::Leaf("att24"),
    //         AccessNode::Leaf("att23"),
    //         AccessNode::Leaf("att18"),
    //     ],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3, 7]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Node(2, Vec::from_slice(&[5, 6, 8]).unwrap()),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Leaf("att10"),
    //         AccessNode::Leaf("att22"),
    //         AccessNode::Node(3, Vec::from_slice(&[9, 10, 11, 12]).unwrap()),
    //         AccessNode::Leaf("att24"),
    //         AccessNode::Leaf("att23"),
    //         AccessNode::Leaf("att18"),
    //         AccessNode::Leaf("att08"),
    //     ],
    //     &[
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3, 7]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Node(2, Vec::from_slice(&[5, 6, 8]).unwrap()),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Leaf("att10"),
    //         AccessNode::Leaf("att22"),
    //         AccessNode::Node(3, Vec::from_slice(&[9, 10, 11, 12]).unwrap()),
    //         AccessNode::Leaf("att24"),
    //         AccessNode::Leaf("att23"),
    //         AccessNode::Leaf("att18"),
    //         AccessNode::Node(1, Vec::from_slice(&[13]).unwrap()),
    //         AccessNode::Leaf("att06"),
    //     ],
    //     &[
    //         AccessNode::Node(1, Vec::from_slice(&[16]).unwrap()),
    //         AccessNode::Leaf("att20"),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att30"),
    //         AccessNode::Node(2, Vec::from_slice(&[2, 3]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[1, 4]).unwrap()),
    //         AccessNode::Leaf("att06"),
    //         AccessNode::Leaf("att04"),
    //         AccessNode::Node(1, Vec::from_slice(&[6, 7]).unwrap()),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Node(1, Vec::from_slice(&[8, 9]).unwrap()),
    //         AccessNode::Leaf("att01"),
    //         AccessNode::Node(1, Vec::from_slice(&[10, 11]).unwrap()),
    //         AccessNode::Leaf("att13"),
    //         AccessNode::Leaf("att27"),
    //         AccessNode::Node(1, Vec::from_slice(&[13, 14]).unwrap()),
    //         AccessNode::Node(3, Vec::from_slice(&[5, 12, 15]).unwrap()),
    //     ],
    //     &[
    //         AccessNode::Node(3, Vec::from_slice(&[3, 10, 11, 12]).unwrap()),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Leaf("att17"),
    //         AccessNode::Node(1, Vec::from_slice(&[1, 2]).unwrap()),
    //         AccessNode::Leaf("att28"),
    //         AccessNode::Leaf("att16"),
    //         AccessNode::Node(1, Vec::from_slice(&[4, 5]).unwrap()),
    //         AccessNode::Leaf("att01"),
    //         AccessNode::Leaf("att05"),
    //         AccessNode::Leaf("att28"),
    //         AccessNode::Node(4, Vec::from_slice(&[6, 7, 8, 9]).unwrap()),
    //         AccessNode::Leaf("att16"),
    //         AccessNode::Leaf("att21"),
    //     ],
    //     &[
    //         AccessNode::Node(1, Vec::from_slice(&[48]).unwrap()),
    //         AccessNode::Leaf("att14"),
    //         AccessNode::Leaf("att06"),
    //         AccessNode::Node(2, Vec::from_slice(&[1, 2]).unwrap()),
    //         AccessNode::Leaf("att12"),
    //         AccessNode::Leaf("att30"),
    //         AccessNode::Node(2, Vec::from_slice(&[4, 5]).unwrap()),
    //         AccessNode::Leaf("att23"),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Node(1, Vec::from_slice(&[7, 8]).unwrap()),
    //         AccessNode::Leaf("att11"),
    //         AccessNode::Leaf("att21"),
    //         AccessNode::Leaf("att23"),
    //         AccessNode::Node(2, Vec::from_slice(&[11, 12]).unwrap()),
    //         AccessNode::Node(1, Vec::from_slice(&[3, 6, 9, 10, 13]).unwrap()),
    //         AccessNode::Leaf("att13"),
    //         AccessNode::Leaf("att16"),
    //         AccessNode::Node(2, Vec::from_slice(&[15, 16]).unwrap()),
    //         AccessNode::Leaf("att11"),
    //         AccessNode::Leaf("att01"),
    //         AccessNode::Node(2, Vec::from_slice(&[18, 19]).unwrap()),
    //         AccessNode::Leaf("att24"),
    //         AccessNode::Leaf("att27"),
    //         AccessNode::Node(2, Vec::from_slice(&[21, 22]).unwrap()),
    //         AccessNode::Leaf("att11"),
    //         AccessNode::Leaf("att27"),
    //         AccessNode::Node(4, Vec::from_slice(&[17, 20, 23, 24, 25]).unwrap()),
    //         AccessNode::Leaf("att02"),
    //         AccessNode::Leaf("att07"),
    //         AccessNode::Node(1, Vec::from_slice(&[27, 28]).unwrap()),
    //         AccessNode::Leaf("att23"),
    //         AccessNode::Node(1, Vec::from_slice(&[29, 30]).unwrap()),
    //         AccessNode::Leaf("att09"),
    //         AccessNode::Leaf("att22"),
    //         AccessNode::Node(1, Vec::from_slice(&[32, 33]).unwrap()),
    //         AccessNode::Leaf("att21"),
    //         AccessNode::Node(3, Vec::from_slice(&[31, 34, 35]).unwrap()),
    //         AccessNode::Leaf("att26"),
    //         AccessNode::Leaf("att18"),
    //         AccessNode::Node(1, Vec::from_slice(&[37, 38]).unwrap()),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Leaf("att18"),
    //         AccessNode::Node(1, Vec::from_slice(&[40, 41]).unwrap()),
    //         AccessNode::Leaf("att16"),
    //         AccessNode::Leaf("att21"),
    //         AccessNode::Node(1, Vec::from_slice(&[43, 44]).unwrap()),
    //         AccessNode::Leaf("att09"),
    //         AccessNode::Leaf("att22"),
    //         AccessNode::Node(
    //             4,
    //             Vec::from_slice(&[14, 26, 36, 39, 42, 45, 46, 47]).unwrap(),
    //         ),
    //     ],
    //     &[
    //         AccessNode::Node(5, Vec::from_slice(&[11, 25, 32, 42, 45, 46]).unwrap()),
    //         AccessNode::Leaf("att21"),
    //         AccessNode::Leaf("att26"),
    //         AccessNode::Leaf("att13"),
    //         AccessNode::Leaf("att16"),
    //         AccessNode::Node(2, Vec::from_slice(&[3, 4]).unwrap()),
    //         AccessNode::Leaf("att19"),
    //         AccessNode::Node(1, Vec::from_slice(&[2, 5, 6]).unwrap()),
    //         AccessNode::Leaf("att16"),
    //         AccessNode::Leaf("att18"),
    //         AccessNode::Node(1, Vec::from_slice(&[8, 9]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[1, 7, 10]).unwrap()),
    //         AccessNode::Leaf("att29"),
    //         AccessNode::Leaf("att03"),
    //         AccessNode::Node(1, Vec::from_slice(&[12, 13]).unwrap()),
    //         AccessNode::Leaf("att08"),
    //         AccessNode::Node(2, Vec::from_slice(&[14, 15]).unwrap()),
    //         AccessNode::Leaf("att08"),
    //         AccessNode::Leaf("att01"),
    //         AccessNode::Node(2, Vec::from_slice(&[17, 18]).unwrap()),
    //         AccessNode::Leaf("att18"),
    //         AccessNode::Leaf("att03"),
    //         AccessNode::Leaf("att04"),
    //         AccessNode::Leaf("att16"),
    //         AccessNode::Node(2, Vec::from_slice(&[22, 23]).unwrap()),
    //         AccessNode::Node(3, Vec::from_slice(&[16, 19, 20, 21, 24]).unwrap()),
    //         AccessNode::Leaf("att17"),
    //         AccessNode::Leaf("att04"),
    //         AccessNode::Node(2, Vec::from_slice(&[26, 27]).unwrap()),
    //         AccessNode::Leaf("att03"),
    //         AccessNode::Leaf("att06"),
    //         AccessNode::Node(1, Vec::from_slice(&[29, 30]).unwrap()),
    //         AccessNode::Node(1, Vec::from_slice(&[28, 31]).unwrap()),
    //         AccessNode::Leaf("att16"),
    //         AccessNode::Leaf("att03"),
    //         AccessNode::Leaf("att03"),
    //         AccessNode::Node(1, Vec::from_slice(&[33, 34, 35]).unwrap()),
    //         AccessNode::Leaf("att24"),
    //         AccessNode::Node(2, Vec::from_slice(&[36, 37]).unwrap()),
    //         AccessNode::Leaf("att26"),
    //         AccessNode::Leaf("att24"),
    //         AccessNode::Node(2, Vec::from_slice(&[39, 40]).unwrap()),
    //         AccessNode::Node(2, Vec::from_slice(&[38, 41]).unwrap()),
    //         AccessNode::Leaf("att28"),
    //         AccessNode::Leaf("att27"),
    //         AccessNode::Node(1, Vec::from_slice(&[43, 44]).unwrap()),
    //         AccessNode::Leaf("att19"),
    //     ],
    // ];
    let atts = [
        "att12", "att29", "att07", "att10", "att22", "att24", "att23", "att18", "att08", "att06",
        "att14", "att11", "att25", "att02", "att09", "att26", "att03", "att20", "att04", "att30",
        "att01", "att21", "att15", "att19", "att05", "att13", "att17", "att27", "att16", "att28",
    ];

    for i in 0..SET_A.len() {
        // rprintln!("starting setup");
        let mut us = 0;
        for _ in 0..SMPL_CNT {
            let start = Instant::now();
            let ciphertext = private.keygen(&SET_A[i], &mut rng);
            us += Instant::now().duration_since(start).as_micros();
        }
        println!("{};{:?}", i + 1, us / SMPL_CNT);
    }
    // let access_structure: AccessStructure = &[
    //   AccessNode::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
    //   AccessNode::Leaf("tum"),
    //   AccessNode::Leaf("student"),
    //   AccessNode::Leaf("has_bachelor"),
    //   AccessNode::Leaf("over21"),
    // ];
}
