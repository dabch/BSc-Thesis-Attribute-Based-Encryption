#![no_main]
#![no_std]

use cortex_m::asm;
use cortex_m_rt::entry;
use rtt_target::{rtt_init_print, rprintln};
use core::panic::PanicInfo;
use nrf52832_hal as hal;
use hal::{timer::Instance, };
use heapless::{Vec, FnvIndexMap};
use heapless;

use rabe_bn::{G1, G2, Gt, pairing, Group};
// use aes;
// use ccm;

#[entry]
fn main() -> ! {
    rtt_init_print!();
    let p = hal::pac::Peripherals::take().unwrap();
    let mut rng = hal::Rng::new(p.RNG);

    p.TIMER0.timer_start(0 as u32);
    let mut _timer = hal::Timer::new(p.TIMER0);

    rprintln!("getting random elements");
    let g1 = G1::random(&mut rng);
    let g2 = G2::random(&mut rng);
    
    rprintln!("computing pairing...");
    let gt = rabe_bn::pairing(g1, g2);
    rprintln!("done pairing");
    loop {
      asm::bkpt();  
    }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  rprintln!("{}", _panic);
  loop{}
}
