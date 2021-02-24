use rabe_bn;
use abe_utils::msp::MSP;

use heapless::{FnvIndexMap, Vec, consts};
use rand::{Rng, RngCore};
use rabe_bn::{Group};

use abe_utils::hash_to_group::{hash_jlt, hash_xlt};

type F = rabe_bn::Fr;
type G = rabe_bn::G1;
type H = rabe_bn::G2;
type Gt = rabe_bn::Gt;

type S = consts::U64;

pub struct AcAbePublic {
    h: H,
    h1: H,
    h2: H,
    t1: Gt,
    t2: Gt,
}

pub struct AcAbePrivate {
    g: G,
    h: H,
    a_t: [F; 2],
    b1: F,
    b2: F,
    gd: [G; 3],
}

pub struct AcAbePrivateKey<'a> {
    sk_0: (H, H, H),
    sk_pr: (G, G, G, G),
    sk_y: FnvIndexMap<&'a str, (G, G, G), S>
}

pub fn setup(rng: &mut dyn RngCore) -> (AcAbePublic, AcAbePrivate) {
    let (g, h): (G, H)  = rng.gen();
    let (a1, a2): (F, F) = rng.gen();
    let (d1, d2, d3): (F, F, F) = rng.gen();
    let (b1, b2): (F, F) = rng.gen();

    let h1 = h * a1;
    let h2 = h * a2;
    let t0 = rabe_bn::pairing(g, h); // compute this only once
    let t1 = t0.pow(d1 * a1 + d3);
    let t2 = t0.pow(d2 * a2 + d3);
    let gd1 = g * d1;
    let gd2 = g * d2;
    let gd3 = g * d3;
    (
        AcAbePublic {
            h, h1, h2, t1, t2
        },
        AcAbePrivate {
            g, h, a_t: [a1, a2], b1, b2, gd: [gd1, gd2, gd3]
        }
    )
}

pub fn keygen<'a>(sk: &AcAbePrivate, pk: &AcAbePublic, msp: MSP, rng: &mut dyn RngCore) {//} -> AcAbePrivateKey<'a> {
    let (r1, r2): (F, F) = rng.gen();
    let sk_0 = (pk.h * (sk.b1 * r1), pk.h * (sk.b2 * r2), pk.h * (r1 + r2));

    let mut sigma_prime: Vec<F, S> = Vec::new();
    for i in 0..msp.0[0].1.len() {
        sigma_prime[i] = rng.gen();
    }

    for (i, (lbl, row)) in msp.into_iter().enumerate() {
        let mut sk_i_t = [G::zero(); 3];
        let sigma_i: F = rng.gen();
        for t in 1..3 {
            let a_t_inv = sk.a_t[t as usize].inverse().unwrap();
            sk_i_t[t as usize] = 
                    hash_xlt(lbl.get_str().as_bytes(), 1, t, sk.g) * (sk.b1 * r1 * a_t_inv)
                +   hash_xlt(lbl.get_str().as_bytes(), 2, t, sk.g) * (sk.b2 * r2 * a_t_inv)
                +   hash_xlt(lbl.get_str().as_bytes(), 3, t, sk.g) * ((r1 + r2) * a_t_inv)
                +   sk.g * (sigma_i * a_t_inv)
                +   sk.gd[t as usize] * (F::from(row[0]));

            for (j, m_i_j) in row[1..].iter().enumerate() {
                let j_as_f = F::from(j as u64);
                let m_i_j = F::from(*m_i_j);
                sk_i_t[t as usize] = sk_i_t[t as usize]   +   (
                        hash_jlt(j_as_f, 1, t, sk.g) * (sk.b1 * r1 * a_t_inv)
                        + hash_jlt(j_as_f, 2, t, sk.g) * (sk.b2 * r2 * a_t_inv)
                        + hash_jlt(j_as_f, 3, t, sk.g) * ((r1 + r2) * a_t_inv)
                        + sk.g * (sigma_prime[j] * a_t_inv)
                    ) * m_i_j;
            }
        }
        // sk_i_t[2] = (sk.g * sigma_i).inverse().unwrap() + sk.gd[2] * F::from(row[0]);
    }
    
}


#[cfg(test)]
mod test {
    use super::*;

    use rand::{Rng, RngCore, self};

    #[test]
    fn group_stuff() {
        let mut rng = rand::thread_rng();
        let g:G = rng.gen();

        let f: F = rng.gen();

        assert_eq!(g * f.inverse().unwrap() + g * f, G::one());
    }
}

