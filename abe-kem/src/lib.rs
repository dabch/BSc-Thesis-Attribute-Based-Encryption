#![no_std]
mod kem;

pub use kem::{encrypt, decrypt, Ciphertext};

// pub use kem::kdf;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
