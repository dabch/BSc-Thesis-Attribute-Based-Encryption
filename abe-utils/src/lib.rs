#![no_std]
pub mod kem;
pub mod hash_to_group;
pub mod msp;

pub use kem::{encrypt, decrypt, Ciphertext};

extern crate std;

// pub use kem::kdf;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
