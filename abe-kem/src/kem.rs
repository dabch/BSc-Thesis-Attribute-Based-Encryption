use generic_array::GenericArray;
use core::fmt::Display;

use sha3::{Sha3_256, Digest};
use aes::Aes256;
use ccm::{self, aead::{NewAead, AeadInPlace, Error as AeadError}};

use core::fmt::{Write, self};
use rand::{RngCore, Rng};


type Ccm = ccm::Ccm<Aes256, ccm::consts::U10, ccm::consts::U13>;

trait SymmetricKey<KeySize: generic_array::ArrayLength<u8>> {
    type GroupElement;

    fn get_bytes() -> GenericArray<u8, KeySize>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ciphertext<'data> {
    data: &'data mut [u8],
    nonce: [u8; 13],
    mac: ccm::aead::Tag<ccm::consts::U10>,
}

/// This wrapper is needed to manually implement `core::fmt::Write` on the hasher. 
/// It already implements `std::io::Write` which has literally the same effect, but
/// unfortunately is unavailable in a no_std environment.
struct Wrapper<W: Digest>(pub W);

impl<W: Digest> core::fmt::Write for Wrapper<W> {
    fn write_str(&mut self, arg: &str) -> fmt::Result {
        self.0.update(arg);
        Ok(())
    }
}

pub fn encrypt<'a, G: Display>(key: &G, plaintext: &'a mut [u8], rng: &mut dyn RngCore) -> Result<Ciphertext<'a>, AeadError> {
    let aes_key = kdf(&key);
    let nonce: [u8; 13] = rng.gen();

    let ccm = Ccm::new(&aes_key);
    let mac = ccm.encrypt_in_place_detached(&GenericArray::from(nonce), &[], plaintext)?;
    Ok(
        Ciphertext {
            data: plaintext,
            nonce,
            mac,
        }
    )
}

pub fn decrypt<'a, G: Display>(key: &G, mut ciphertext: Ciphertext<'a>) -> Result<&'a mut [u8], Ciphertext<'a>> {
    let aes_key = kdf(&key);
    let ccm = Ccm::new(&aes_key);
    match ccm.decrypt_in_place_detached(&GenericArray::from(ciphertext.nonce), &[], &mut ciphertext.data, &ciphertext.mac) {
        Ok(_) => Ok(ciphertext.data),
        Err(_) => Err(ciphertext),
    }
}

pub fn kdf<G: Display>(inp: &G) -> GenericArray<u8, ccm::consts::U32> {
    let mut hasher = Wrapper(Sha3_256::new());
    write!(&mut hasher, "{}", inp).unwrap(); // this LITERALLY can't fail, see the impl of core::fmt::Write for our Wrapper above ;D
    hasher.0.finalize()
}


#[cfg(test)]
mod tests {
    use rabe_bn::Gt;
    use rand::Rng;
    use super::*;
    #[test]
    fn successful_decryption() {
        let mut rng = rand::thread_rng();
        let g1: Gt = rng.gen();
        let mut data = [0; 128];
        let mut ciphertext = encrypt(g1, &mut data, &mut rng).unwrap();
        // println!("{:?}", ciphertext);
        let data = decrypt(g1, ciphertext).unwrap();
        assert_eq!(data, [0; 128]);
    }
    
    #[test]
    fn failed_decryption() {
        let mut rng = rand::thread_rng();
        let g1: Gt = rng.gen();
        let g2: Gt = rng.gen();
        // println!("{}", g1);
        // println!("{}", g2);
        assert_ne!(kdf(&g1), kdf(&g2));
        let mut data: [u8; 4096] = [0; 4096];
        let mut ciphertext = encrypt(g1, &mut data, &mut rng).unwrap();
        // println!("{:?}", ciphertext.data);
        // ciphertext.data[1] ^= 0x15;
        // println!("{:?}", ciphertext.data);
        let ciphertext = decrypt(g2, ciphertext).unwrap_err();
        assert_ne!([0;128], ciphertext.data);
    }


}
