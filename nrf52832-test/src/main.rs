#![no_main]
#![no_std]

use rand::Rng;
use cortex_m::asm;
use cortex_m_rt::entry;
use rtt_target::{rtt_init_print, rprintln};
use core::panic::PanicInfo;
use nrf52832_hal as hal;
use hal::{timer::Instance, };
use yao_abe_rust::{AccessNode, AccessStructure, YaoABECiphertext, YaoABEPrivate, YaoABEPublic, S};
use heapless::{Vec, consts, IndexMap, FnvIndexMap};
use heapless;
use rabe_bn::{G1, Fr};
// use aes;
// use ccm;

#[entry]
fn main() -> ! {
    rtt_init_print!();
    //println!("Hello, world!");
    rprintln!("Hello World!");

    for _ in (0..10000) {
      asm::nop();
    }
    let p = hal::pac::Peripherals::take().unwrap();
    let mut rng = hal::Rng::new(p.RNG);

    p.TIMER0.timer_start(0 as u32);
    let mut _timer = hal::Timer::new(p.TIMER0);

    rprintln!("Hello World!");
    let system_atts: Vec<&str, S> = Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let arr: Vec<(&str, G1, Fr), S> = Vec::new();

    rprintln!("Hello World!");
    let access_structure: AccessStructure = &[
      AccessNode::Node(2, Vec::from_slice(&[1,2,3,4]).unwrap()),
      AccessNode::Leaf("tum"),
      AccessNode::Leaf("student"),
      AccessNode::Leaf("has_bachelor"),
      AccessNode::Leaf("over21"),
    ];


    rprintln!("Hello World!");
    let mut public_map: FnvIndexMap<&str, G1, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, (Fr, G1), S> = FnvIndexMap::new();

    rprintln!("Hello World!");
    rprintln!("starting setup");
    // panic!("test panick");

    let start = _timer.read();
    let (private, public) = YaoABEPrivate::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    let ms = _timer.read() - start;
    rprintln!("Setup took {:?}ms", ms);

    // let es = YaoABEPrivate::setup(&system_atts, &mut rng);

    let mut data: [u8; 32] = [0xa; 32];
    let atts = ["student", "tum", "has_bachelor", "over21"];

    rprintln!("starting encrypt");
    let start = _timer.read();
    let mut ciphertext = public.encrypt(&atts, &mut data, &mut rng);
    let ms = _timer.read() - start;
    rprintln!("Encryption took {:?}ms", ms);

    loop {
      asm::bkpt();  
    }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  rprintln!("{}", _panic);
  loop{}
}
