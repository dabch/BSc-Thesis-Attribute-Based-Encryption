#![no_main]
#![no_std]

use cortex_m::asm;
use cortex_m_rt::entry;
use rtt_target::{rtt_init_print, rprintln};
use core::panic::PanicInfo;
use nrf52840_hal as hal;
use hal::{timer::Instance, };
use yao_abe_rust::{AccessNode, AccessStructure, YaoAbeCiphertext, YaoABEPrivate, YaoABEPublic, S, F, G};
// use gpsw06_abe::{self, S, F, G1, G2, Gt, GpswAbePrivate, GpswAbePublic, AccessNode, AccessStructure, GpswAbeCiphertext};
// use rabe_bn::{Gt};
use heapless::{Vec, FnvIndexMap};
// use heapless;
use rand::{Rng, RngCore};
// use abe_kem;
// use rabe_bn::{G1, Fr};
// use aes;
// use ccm;

#[entry]
fn main() -> ! {
    rtt_init_print!();
    let p = hal::pac::Peripherals::take().unwrap();
    let mut rng = hal::Rng::new(p.RNG);

    p.TIMER0.timer_start(0 as u32);
    let mut _timer = hal::Timer::new(p.TIMER0);

    let mut data = [0xde; 100];
    rng.fill_bytes(&mut data);

    rprintln!("data: {:?}", &data);

    let system_atts: Vec<&str, S> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21", "lives_in_munich", "lives_in_garching", "works_at_aisec", "knows_crypto", "wears_glasses", "blabla", "owns_thinkpad", "semester>1", "semester>2", "semester>3", "semester>4", "semester>5"]).unwrap();

    let access_structure: AccessStructure = &[
      AccessNode::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
      AccessNode::Leaf("tum"),
      AccessNode::Leaf("student"),
      AccessNode::Leaf("has_bachelor"),
      AccessNode::Leaf("over21"),
    ];

    let mut public_map: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, (F, G), S> = FnvIndexMap::new();


    rprintln!("starting setup");

    let start = _timer.read();
    let (private, public) = YaoABEPrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    let us = _timer.read() - start;
    rprintln!("Setup took {:?}ms", us / 1000);

    let atts = ["student", "tum", "has_bachelor", "over21", "owns_thinkpad", "lives_in_munich", "lives_in_garching", "works_at_aisec", "knows_crypto", "wears_glasses"];

    rprintln!("starting encrypt");
    let start = _timer.read();
    let ciphertext = public.encrypt(&atts, &mut data, &mut rng).unwrap();
    let us = _timer.read() - start;
    rprintln!("Encryption took {:?}ms", us / 1000);


    rprintln!("Starting keygen");
    let start = _timer.read();
    let private_key = private.keygen(&access_structure, &mut rng).unwrap();
    let us = _timer.read() - start;
    rprintln!("keygen took {}ms", us / 1000);

    rprintln!("Starting decrypt");
    let start = _timer.read();
    let res = YaoABEPublic::decrypt(ciphertext, &private_key);
    let us = _timer.read() - start;
    // assert_eq!(res, data);
    rprintln!("decrypt took {}ms", us / 1000);

    rprintln!("decrypted data: {:?}", res.unwrap());
    loop {
      asm::bkpt();  
    }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  rprintln!("{}", _panic);
  loop{}
}
