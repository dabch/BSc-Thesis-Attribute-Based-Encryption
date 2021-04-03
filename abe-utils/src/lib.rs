//! Implementation of common functionality in the two ABE implementations of GPSW and YCT schemes
//! 
//! Implemented in this crate:
//! - access trees
//! - hybrid encryption: KDF and symmetric encryption with AES-CCM
//! - polynomials over `Fr`
//! - test policies used to evaluate the libraries
//! 
//! Implemented but not used in the two constructions:
//! - MSPs / LSSS access structures
//! - hashing to the elliptic curve groups



#![no_std]

/// implementation of Access Tree construction from GPSW and YCT
pub mod access_tree;

/// Key encapsulation implementation (KDF and AES encryption)
pub mod kem;

/// Polynomials over `Fr` (random generation, evaluation and interpolation)
pub mod polynomial;

/// Test policies for measurements of the library
pub mod test_policies;

/// Hashing into the elliptic curve groups
pub mod hash_to_group;

/// Implementation of MSP/LSSS access structures
pub mod msp;

pub use kem::{encrypt, decrypt, Ciphertext};

// extern crate std;