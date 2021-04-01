use rabe_bn::Fr as F;
use heapless::{Vec, consts};

use rand::{Rng, RngCore};

use crate::access_tree::S as STree;


/// Polynomial p(x) = a0 + a1 * x + a2 * x^2 + ... defined by a vector of coefficients [a0, a1, a2, ...]
//#[derive(Debug)]
pub struct Polynomial(Vec<F, consts::U32>);

impl Polynomial {
  /// Evaluates the polynomial p(x) at a given x
  pub fn eval(&self, x: F) -> F {
    self.0.iter().rev().fold(F::zero(), |acc, c| *c + (x * acc))
  }

  /// Generates a random polynomial p(x) of degree `coeffs` coefficients, where p(0) = `a0`
  pub fn randgen(a0: F, coeffs: u64, rng: &mut dyn RngCore) -> Polynomial {
    let mut coefficients: Vec<F, consts::U32> = Vec::from_slice(&[a0]).unwrap();
    coefficients.extend((1..coeffs).map(|_| -> F { rng.gen() }));
    assert_eq!(coefficients.len() as u64, coeffs);
    Polynomial(coefficients)
  }

  /// Calculates the langrage base polynomials l_i(x) for given set of indices omega and the index i.
  /// As we only ever need to interpolate p(0), no value for x may be passed.
  pub fn lagrange_of_zero(i: &F, omega: &Vec<F, STree>) -> F {
    //println!("LAGRANGE: {:?}\n{:?}", i, omega);
    let r = omega.iter()
      .filter(|x| *x != i)
      // .map(|x| { println!("{:?}", x); x} )
      .map(|j| -*j * (*i-*j).inverse().unwrap())
      .fold(F::one(), |acc, x| acc * x);
    //println!("\n");
    r
  }
}