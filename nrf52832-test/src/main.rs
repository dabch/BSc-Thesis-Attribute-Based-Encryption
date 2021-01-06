#![no_main]
#![no_std]

use cortex_m::asm;
use cortex_m_rt::entry;
use rtt_target::{rtt_init_print, rprintln};
use core::panic::PanicInfo;
use nrf52832_hal as hal;
use hal::{timer::Instance, };
use yao_abe_rust::{AccessNode, AccessStructure, YaoABECiphertext, YaoABEPrivate, S, F, G};
use heapless::{Vec, FnvIndexMap};
use heapless;
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

    let system_atts: Vec<&str, S> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21", "lives_in_munich", "lives_in_garching", "works_at_aisec", "knows_crypto", "wears_glasses", "blabla", "owns_thinkpad"]).unwrap();
    // let arr: Vec<(&str, G, Fr), S> = Vec::new();

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

    let mut data: [u8; 32] = [0xa; 32];
    let atts = ["student", "tum", "has_bachelor", "over21", "owns_thinkpad"];

    rprintln!("starting encrypt");
    let start = _timer.read();
    let mut ciphertext: YaoABECiphertext = public.encrypt(&atts, &mut data, &mut rng).unwrap();
    let us = _timer.read() - start;
    rprintln!("Encryption took {:?}ms", us / 1000);


    rprintln!("Starting keygen");
    let start = _timer.read();
    let private_key = private.keygen(&access_structure, &mut rng);
    let us = _timer.read() - start;
    rprintln!("keygen took {}ms", us / 1000);

    rprintln!("MAC: {:?}", ciphertext.mac);
    rprintln!("encrypted data: {:?}", ciphertext.c);

    rprintln!("Starting decrypt");
    let start = _timer.read();
    let res = public.decrypt(&mut ciphertext, &private_key);
    let us = _timer.read() - start;
    rprintln!("decrypt took {}ms", us / 1000);

    rprintln!("decrypted data: {:?}", ciphertext.c);
    loop {
      asm::bkpt();  
    }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  rprintln!("{}", _panic);
  loop{}
}
