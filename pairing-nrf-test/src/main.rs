#![no_main]
#![no_std]

use cortex_m::{asm, iprintln, Peripherals as CortexPeripherals};
use cortex_m_rt::entry;
use rtt_target::{rtt_init_print, rprintln};
use core::panic::PanicInfo;
use nrf52832_hal as hal;
use hal::{timer::Instance};
use heapless::{Vec, FnvIndexMap};
use heapless;
use rand::Rng;

use rabe_bn::{G1, G2, Gt, Fr, pairing, Group};
// use aes;
// use ccm;

#[entry]
fn main() -> ! {
  rtt_init_print!();
  // let mut c = CortexPeripherals::take().unwrap();
  let p = hal::pac::Peripherals::take().unwrap();
  let mut rng = hal::Rng::new(p.RNG);


  // let stim = &mut c.ITM.stim[0];
  // iprintln!(stim, "Hello World!");

  p.TIMER0.timer_start(0 as u32);
  let mut _timer = hal::Timer::new(p.TIMER0);

  rprintln!("getting random elements");
  let g1 = G1::one();
  let g2 = G2::one();
  let alice = rng.gen();
  let bob = rng.gen();
  let charlie = rng.gen();
  rprintln!("computing public keys");
  let a_pub1 = g1 * alice;
  let a_pub2 = g2 * alice;
  let b_pub1 = g1 * bob;
  let b_pub2 = g2 * bob;
  let c_pub1 = g1 * charlie;
  let c_pub2 = g2 * charlie;
  
  rprintln!("computing pairing...");
  let mut acc = 0;
  const COUNT: u32 = 100;
  for _ in 0..COUNT {
    let a = rng.gen();
    let b = rng.gen();
    let start = _timer.read();
    rabe_bn::pairing(a, b);
    acc += _timer.read() - start;
  }
  // let a = rabe_bn::pairing(b_pub1, c_pub2);
  // let b = rabe_bn::pairing(a_pub1, c_pub2);
  // let c = rabe_bn::pairing(a_pub1, b_pub2);
  rprintln!("done pairing, took {}ms", (acc) / (COUNT * 1000));
  // let start = _timer.read();
  // let alice = a.pow(alice);
  // let bob = b.pow(bob);
  // let charlie = c.pow(charlie);
  // rprintln!("done exponentiating, took {}ms", (_timer.read() - start) / 3000);
  // assert_eq!(alice, bob);
  // assert_eq!(bob, charlie);
  // assert_eq!(alice, charlie);
  rprintln!("alice got {:?}", alice);
  rprintln!("done printing gt");

  rprintln!("going into breakpoint loop {}", 1);
  loop {
    asm::bkpt();  
  }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  rprintln!("{}", _panic);
  loop{}
}
