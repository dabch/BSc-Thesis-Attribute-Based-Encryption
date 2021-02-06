#![no_std]
mod kem;
mod hash_to_curve;

pub use kem::{encrypt, decrypt};

pub use hash_to_curve;

// pub use kem::kdf;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
