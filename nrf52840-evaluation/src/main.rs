#![no_main]
#![no_std]

use cortex_m::asm;
use cortex_m_rt::entry;
use rtt_target::{rtt_init_print, rprintln, rprint};
use core::panic::PanicInfo;
use nrf52840_hal as hal;
use hal::{timer::Instance, };
// use yao_abe_rust::{AccessNode, AccessStructure, YaoAbeCiphertext, YaoABEPrivate, YaoABEPublic, S, F, G};
// use gpsw06_abe::{self, S, F, G1, G2, Gt, GpswAbePrivate, GpswAbePublic, AccessNode, AccessStructure, GpswAbeCiphertext};
use rabe_bn::{Fr, G1, G2, Gt};
use heapless::{Vec, FnvIndexMap};
// use heapless;
use rand::{Rng, RngCore as oldRngCore};
use rand_chacha::{self, rand_core::{SeedableRng, RngCore}};
// use abe_kem;
// use rabe_bn::{G1, Fr};
// use aes;
// use ccm;

#[entry]
fn main() -> ! {
    rtt_init_print!();
    let p = hal::pac::Peripherals::take().unwrap();
    let mut trng = hal::Rng::new(p.RNG);
    let mut seed: [u8; 32] = [0; 32];
    trng.fill_bytes(&mut seed);
    // let mut rng = trng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

    p.TIMER0.timer_start(0 as u32);
    let mut _timer = hal::Timer::new(p.TIMER0);

    // let system_atts: Vec<&str, S> = Vec::from_slice(&["att01", "att02", "att03", "att04", "att05", "att06", "att07", "att08", "att09", "att10", "att11", "att12", "att13", "att14", "att15", "att16", "att17", "att18", "att19", "att20", "att21", "att22", "att23", "att24", "att25", "att26", "att27", "att28", "att29", "att30"]).unwrap();

    // let access_structure: AccessStructure = &[
    //   AccessNode::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
    //   AccessNode::Leaf("tum"),
    //   AccessNode::Leaf("student"),
    //   AccessNode::Leaf("has_bachelor"),
    //   AccessNode::Leaf("over21"),
    // ];

    // let mut public_map: FnvIndexMap<&str, G2, S> = FnvIndexMap::new();
    // let mut private_map: FnvIndexMap<&str, F, S> = FnvIndexMap::new();

    const SMPL_CNT: u32 = 100;
    // rprintln!("starting random generation using ChaCha");
    let mut us = 0;
    for _ in 0..SMPL_CNT {
        let g1: G1 = rng.gen();
        let g2: G2 = rng.gen();
        let start = _timer.read();
        let _g2 = rabe_bn::pairing(g1, g2);
        us += _timer.read() - start;
        rprint!(".");
    }
    rprintln!("pairing took {:?} using ChaCha", us / SMPL_CNT);

    // let mut us = 0;
    // for _ in 0..SMPL_CNT {
    //     let g1: G1 = rng.gen();
    //     let g2: G1 = rng.gen();
    //     let start = _timer.read();
    //     let _g2 = g1 + g2;
    //     us += _timer.read() - start;
    //     rprint!(".");
    // }
    // rprintln!("Smpl from Fr took {:?}ms using ChaCha", us / SMPL_CNT);

    // rprintln!("starting random generation using ChaCha");
    // let mut us = 0;
    // for _ in 0..SMPL_CNT {
    //     let g1: G2 = rng.gen();
    //     let g2: G2 = rng.gen();
    //     let start = _timer.read();
    //     let _g2 = g1 + g2;
    //     us += _timer.read() - start;
    //     rprint!(".");
    // }
    // rprintln!("Smpl from G1 took {:?}ms using ChaCha", us / SMPL_CNT);

    // let mut us = 0;
    // for _ in 0..SMPL_CNT {
    //     let g1: Gt = rng.gen();
    //     let g2: Gt = rng.gen();
    //     let start = _timer.read();
    //     let _g2 = g1 * g2;
    //     us += _timer.read() - start;
    //     rprint!(".");
    // }
    // rprintln!("Smpl from G2 took {:?}ms using ChaCha", us / SMPL_CNT);
    
    // for i in 1..31 {
    //     // rprintln!("starting setup");
    //     let mut public_map: FnvIndexMap<&str, G2, S> = FnvIndexMap::new();
    //     let mut private_map: FnvIndexMap<&str, F, S> = FnvIndexMap::new();
        
    //     let start = _timer.read();
    //     let (private, public) = GpswAbePrivate::setup(&system_atts[..i], &mut public_map, &mut private_map, &mut rng);
    //     let us = _timer.read() - start;
    //     rprintln!("{};{:?}", i, us / 1000);
    // }

    // let (private, public) = GpswAbePrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);

    // let atts = ["att12", "att29", "att07", "att10", "att22", "att24", "att23", "att18", "att08", "att06", "att14", "att11", "att25", "att02", "att09", "att26", "att03", "att20", "att04", "att30", "att01", "att21", "att15", "att19", "att05", "att13", "att17", "att27", "att16", "att28"];
    // for i in 1..31 {
    //     // rprintln!("starting setup");
        
    //     let start = _timer.read();
    //     let ciphertext: GpswAbeCiphertext = public.encrypt(&atts[..i], &mut data, &mut rng).unwrap();
    //     let us = _timer.read() - start;
    //     rprintln!("{};{:?}", i, us / 1000);
    // }

    // rprintln!("starting encrypt");
    // let start = _timer.read();
    // let ciphertext: GpswAbeCiphertext = public.encrypt(&atts, &mut data, &mut rng).unwrap();
    // let us = _timer.read() - start;
    // rprintln!("Encryption took {:?}ms", us / 1000);


    // rprintln!("Starting keygen");
    // let start = _timer.read();
    // let private_key = private.keygen(&public, &access_structure, &mut rng);
    // let us = _timer.read() - start;
    // rprintln!("keygen took {}ms", us / 1000);

    // rprintln!("Starting decrypt");
    // let start = _timer.read();
    // let res = GpswAbePublic::decrypt(ciphertext, &private_key);
    // let us = _timer.read() - start;
    // // assert_eq!(res, data);
    // rprintln!("decrypt took {}ms", us / 1000);

    
    loop {
      asm::bkpt();  
    }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  rprintln!("{}", _panic);
  loop{}
}
