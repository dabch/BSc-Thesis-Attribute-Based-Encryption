#![no_main]
#![no_std]

use core::panic::PanicInfo;
use cortex_m::asm;
use cortex_m_rt::{entry, pre_init};
use hal::timer::Instance;
use nrf52840_hal as hal;

use rtt_target::{rprint, rprintln, rtt_init_print};
// use rabe_bn::{Fr, G1, G2, Gt};

use rand::{Rng, RngCore as oldRngCore};
use rand_chacha::{
  self,
  rand_core::{RngCore, SeedableRng},
};
// use abe_kem;
// use rabe_bn::{G1, Fr};
// use aes;
// use ccm;

use abe_utils::policies;

// use yao_abe_rust::{AccessNode, AccessStructure, YaoABEPrivate, YaoABEPublic, F, G, S};
use gpsw06_abe::{GpswAbeCiphertext, GpswAbePrivate, GpswAbePublic, AccessNode, AccessStructure, G1, G2, F, S};
use heapless::{consts, FnvIndexMap, Vec};



type PUBLIC<'a, 'b> = GpswAbePublic<'a, 'b>;
type PRIVATE<'a, 'b> = GpswAbePrivate<'a, 'b>;
type ACCESS_NODE<'a> = AccessNode<'a>;

type PUBLIC_MAP = G2;
type PRIVATE_MAP = F;

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

  let SMPL_CNT: u64 = 5;

  let system_atts: Vec<&str, S> = Vec::from_slice(&[
    "att01", "att02", "att03", "att04", "att05", "att06", "att07", "att08", "att09", "att10",
    "att11", "att12", "att13", "att14", "att15", "att16", "att17", "att18", "att19", "att20",
    "att21", "att22", "att23", "att24", "att25", "att26", "att27", "att28", "att29", "att30",
  ])
  .unwrap();

  let mut public_map: FnvIndexMap<&str, PUBLIC_MAP, S> = FnvIndexMap::new();
  let mut private_map: FnvIndexMap<&str, PRIVATE_MAP, S> = FnvIndexMap::new();

  // rprintln!("Setup");
  // for i in 1..31 {
    // let i = 10;
    // let mut us: u64 = 0;
    // // for _ in 0..SMPL_CNT {
    //   // rprintln!("starting setup");
    //   let mut public_map: FnvIndexMap<&str, PUBLIC_MAP, S> = FnvIndexMap::new();
    //   let mut private_map: FnvIndexMap<&str, PRIVATE_MAP, S> = FnvIndexMap::new();
    //   let start = _timer.read();
    //   let (private, public) = PRIVATE::setup(
    //     &system_atts[..i],
    //     &mut public_map,
    //     &mut private_map,
    //     &mut rng,
    //   );
    //   us += (_timer.read() - start) as u64;
    // // }
    // rprintln!("{};{:?}", i, us / SMPL_CNT);
  // }


  let (private, public) =
  PRIVATE::setup(&system_atts, &mut public_map, &mut private_map, &mut rng);

  // // rprintln!("Encrypt");
  let mut data: [u8; 256] = [0; 256];
  rng.fill_bytes(&mut data);

  let atts = ["att12", "att29", "att07", "att10", "att22", "att24", "att23", "att18", "att08", "att06", "att14", "att11", "att25", "att02", "att09", "att26", "att03", "att20", "att04", "att30", "att01", "att21", "att15", "att19", "att05", "att13", "att17", "att27", "att16", "att28"];


  // // for i in 1..31 {
  // //     // rprintln!("starting setup");
  // //     let mut us: u64 = 0;
  // //     for _ in 0..SMPL_CNT {
  // //         let start = _timer.read();
  // //         let ciphertext = public.encrypt(&atts[..i], &mut data, &mut rng).unwrap();
  // //         us += (_timer.read() - start) as u64;
  // //     }
  // //    rprintln!("{};{}", i, us / SMPL_CNT);
  // // }


  let policies: &[&[AccessNode]] = policies!();
  let SMPL_CNT: u64 = 1;

  rng.fill_bytes(&mut data);
  rprintln!("keygen;dec");
  for i in 0..policies.len() {
    // let i = 0;
      // rprintln!("starting setup");
      let mut keygen_us: u64 = 0;
      let mut dec_us: u64 = 0;
        let mut data_cpy = data.clone();
        let ciphertext = public.encrypt(&atts, &mut data_cpy, &mut rng).unwrap();

        let start = _timer.read();
        let key = private.keygen(&public, policies[i], &mut rng);
        keygen_us += (_timer.read() - start) as u64;
        // rprint!("keygendone,");
        let start = _timer.read();
        let data_recovered = PUBLIC::decrypt(ciphertext, &key).unwrap();
        dec_us += (_timer.read() - start) as u64;
        // rprint!("decdone,");
        assert_eq!(data_recovered, data);
      rprintln!(
          "{};{}",
          keygen_us / SMPL_CNT as u64,
          dec_us / SMPL_CNT as u64 ,
      );
  }

  rprintln!("done.");
  loop {
    asm::bkpt();
  }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  rprintln!("{}", _panic);
  loop {}
}
