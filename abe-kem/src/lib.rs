#![no_std]
mod traits;

pub use traits::{encrypt, decrypt};

pub use traits::kdf;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
