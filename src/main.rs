//use elliptic_curve;
use p256;
//use rand::OsRng;

fn main() {
  
  let g = p256::ProjectivePoint::generator();
  
  let s1 = p256::Scalar::one() + p256::Scalar::one();
  let s2 = p256::Scalar::one() + p256::Scalar::one() + p256::Scalar::one() + p256::Scalar::one() +
  p256::Scalar::one() + p256::Scalar::one() + p256::Scalar::one() + p256::Scalar::one() +
  p256::Scalar::one() + p256::Scalar::one() + p256::Scalar::one() + p256::Scalar::one() +
  p256::Scalar::one() + p256::Scalar::one() + p256::Scalar::one() + p256::Scalar::one() +
  p256::Scalar::one() + p256::Scalar::one();

  let p1 = g * s1;
  let p2 = g * s2;

  assert_eq!(p2 * s1, p1 * s2);
  assert_ne!(p2 * s2, p1 * s1);
  println!("Alice got: {:?}", p2 * s1);
  println!("Bob got:   {:?}", p1 * s2);

  println!();
  println!("DH secret: {}", (p2 * s1).to_affine().x);
}
