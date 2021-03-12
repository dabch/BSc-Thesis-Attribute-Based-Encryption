use rabe_bn::{Fr, G1, G2, Gt};
use rand::{self, Rng};
use std::time::{Instant};

const SMPL_CNT: u128 = 100;

fn main() {
    let mut rng = rand::thread_rng();
   
    // println!("starting random generation using ChaCha");
    let mut us = 0;
    for _ in 0..SMPL_CNT {
        let g: G1 = rng.gen();
        let f: Fr = rng.gen();
        let start = Instant::now();
        let g3 = g * f;
        us += Instant::now().duration_since(start).as_micros();
        print!(".");
    }
    println!();
    println!("G1 took {:?}", us / SMPL_CNT);

    let mut us = 0;
    for _ in 0..SMPL_CNT {
        let g: G2 = rng.gen();
        let f: Fr = rng.gen();
        let start = Instant::now();
        let g3 = g * f;
        us += Instant::now().duration_since(start).as_micros();
        print!(".");
    }
    println!();
    println!("G1 took {:?}", us / SMPL_CNT);

    let mut us = 0;
    for _ in 0..SMPL_CNT {
        let g: Gt = rng.gen();
        let f: Fr = rng.gen();
        let start = Instant::now();
        let g3 = g.pow(f);
        us += Instant::now().duration_since(start).as_micros();
        print!(".");
    }
    println!();
    println!("G2 took {:?}", us / SMPL_CNT);

    // let mut us = 0;
    // for _ in 0..SMPL_CNT {
    //     let g1: Gt = rng.gen();
    //     let g2: Gt = rng.gen();
    //     let start = Instant::now();
    //     let g3 = g1 * g2;
    //     us += Instant::now().duration_since(start).as_micros();
    //     print!(".");
    // }
    // println!();
    // println!("Gt took {:?}", us / SMPL_CNT);
    
}
