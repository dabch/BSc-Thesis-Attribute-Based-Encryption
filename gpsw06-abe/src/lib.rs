//! Implementation of the KP-ABE scheme by Goyal, Pandey Saha and Waters, [available here](https://dl.acm.org/doi/abs/10.1145/1180405.1180418).
//! 
//! Differences to the original paper by Goyal, Pandey, Sahai and Waters:
//! - use of asymmetric pairing (G1 x G2 -> Gt instead of G1 x G1 -> G2)
//!   - when decrypting, the leaf node secret shares are combined with that of the attribute
//!   - for less computational cost when encrypting, swap the pairing arguments in decryptNode
//!   - i.e. the ciphertext's attributes are elements of G1, and the secret shares are elements of G2
//!   - G1 has 96 Bytes, G2 has 192 Bytes and Gt 384 Bytes -> makes a big difference for runtimes and ciphertext size.
//! - hybrid encryption of the actual plaintext using AES-CCM + key encapsulation with ABE
//!
//! with G1 and G2 swapped (S = 16):
//! ```text
//! sizeof(GpswAbeCiphertext) = 2376
//! sizeof(GpswAbePrivate) = 40
//! sizeof(GpswAbePublic) = 680
//! sizeof(PrivateKey) = 3288
//! ```
//! 
//! without swapping (S = 16):
//! ```text
//! sizeof(GpswAbeCiphertext) = 3912
//! sizeof(GpswAbePrivate) = 40
//! sizeof(GpswAbePublic) = 680
//! sizeof(PrivateKey) = 1752
//! ```


#![no_std]

mod gpsw06_abe;
pub use crate::gpsw06_abe::*;