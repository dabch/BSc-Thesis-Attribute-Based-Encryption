use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar, Bls12};
use group::{Curve, Group};
use ff::{Field};
use pairing::{Engine};
use rand;

fn main() {
    println!("Hello, world!");
    let mut rng = rand::thread_rng();
    let g1 = G1Projective::random(&mut rng).to_affine();
    let g2 = G2Projective::random(&mut rng).to_affine();

    let gt = Bls12::pairing(&g1, &g2);

    // println!("{:?}", gt);
}
