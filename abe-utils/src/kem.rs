use generic_array::{GenericArray, typenum::consts};
use core::fmt::Display;

use sha3::{Sha3_256, Digest};
use aes::Aes256;
use ccm::{self, aead::{NewAead, AeadInPlace, Error as AeadError}};

use core::fmt::{Write, self};
use rand::{RngCore, Rng};


type Ccm = ccm::Ccm<Aes256, ccm::consts::U10, ccm::consts::U13>;

/// Symmetric ciphertext (data encrypted under AES-CCM)
/// 
/// Ciphertext structure holding information on data encrypted with AES-CCM.
/// The plaintext is encrypted in-place because no additional memory can be allocated.
/// This struct just keeps a pointer to the data and saves the nonce and auth tag.
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

/// Encrypt with a byte slice as key
/// 
/// The slice can have any length and is hashed before it is used as key.
pub fn encrypt_bytes<'a>(key: &[u8], plaintext: &'a mut [u8], rng: &mut dyn RngCore) -> Result<Ciphertext<'a>, AeadError> {
    let aes_key = kdf_bytes(key);
    encrypt_with_aes_key(&aes_key, plaintext, rng)
}

/// Encrypt with any struct implementing `core::fmt::Display` as key
pub fn encrypt<'a, G: Display>(key: &G, plaintext: &'a mut [u8], rng: &mut dyn RngCore) -> Result<Ciphertext<'a>, AeadError> {
    let aes_key = kdf(key);
    encrypt_with_aes_key(&aes_key, plaintext, rng)
}

fn encrypt_with_aes_key<'a>(aes_key: &GenericArray<u8, consts::U32>, plaintext: &'a mut [u8], rng: &mut dyn RngCore) -> Result<Ciphertext<'a>, AeadError> {
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

/// Decrypt with any struct implementing `core::fmt::Display` as key
pub fn decrypt<'a, G: Display>(key: &G, ciphertext: Ciphertext<'a>) -> Result<&'a mut [u8], Ciphertext<'a>> {
    let aes_key = kdf(key);
    decrypt_with_aes_key(&aes_key, ciphertext)
}

/// Decrypt with a byte slice as key
/// 
/// The slice can have any length and is hashed before it is used as key.
pub fn decrypt_bytes<'a>(key: &[u8], ciphertext: Ciphertext<'a>) -> Result<&'a mut [u8], Ciphertext<'a>> {
    let aes_key = kdf_bytes(key);
    decrypt_with_aes_key(&aes_key, ciphertext)
}

fn decrypt_with_aes_key<'a>(aes_key: &GenericArray<u8, consts::U32>, mut ciphertext: Ciphertext<'a>) -> Result<&'a mut [u8], Ciphertext<'a>> {
    let ccm = Ccm::new(&aes_key);
    match ccm.decrypt_in_place_detached(&GenericArray::from(ciphertext.nonce), &[], &mut ciphertext.data, &ciphertext.mac) {
        Ok(_) => Ok(ciphertext.data),
        Err(_) => Err(ciphertext),
    }
}

fn kdf<G: Display>(inp: &G) -> GenericArray<u8, ccm::consts::U32> {
    let mut hasher = Wrapper(Sha3_256::new());
    write!(&mut hasher, "{}", inp).unwrap(); // this LITERALLY can't fail, see the impl of core::fmt::Write for our Wrapper above ;D
    hasher.0.finalize()
}

fn kdf_bytes(inp: &[u8]) -> GenericArray<u8, ccm::consts::U32> {
    let mut hasher = Sha3_256::new();
    hasher.update(inp); // this LITERALLY can't fail, see the impl of core::fmt::Write for our Wrapper above ;D
    hasher.finalize()
}


#[cfg(test)]
mod tests {
    extern crate std;
    extern crate alloc;
    use rabe_bn::{Gt, G1};
    use rand::{Rng, SeedableRng};
    use super::*;
    use alloc::string::ToString;

    use rand_chacha::ChaCha20Rng;
    #[test]
    fn successful_decryption() {
        let mut rng = rand::thread_rng();
        let g1: Gt = rng.gen();
        let mut data = [0; 128];
        let ciphertext = encrypt(&g1, &mut data, &mut rng).unwrap();
        // println!("{:?}", ciphertext);
        let data = decrypt(&g1, ciphertext).unwrap();
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
        let ciphertext = encrypt(&g1, &mut data, &mut rng).unwrap();
        // println!("{:?}", ciphertext.data);
        // ciphertext.data[1] ^= 0x15;
        // println!("{:?}", ciphertext.data);
        let ciphertext = decrypt(&g2, ciphertext).unwrap_err();
        assert_ne!([0;128], ciphertext.data);
    }

    #[test]
    fn non_malleability() {
        let mut rng = rand::thread_rng();
        let g1: Gt = rng.gen();
        let mut data = [0; 4096];
        rng.fill_bytes(&mut data);
        let ciphertext = encrypt(&g1, &mut data, &mut rng).unwrap();
        // println!("{:?}", ciphertext.data);
        ciphertext.data[1] ^= 0x15;
        // println!("{:?}", ciphertext.data);
        let ciphertext = decrypt(&g1, ciphertext).unwrap_err();
        assert_ne!([0;128], ciphertext.data);
    }

    #[test]
    fn check_hashing() {
        let mut rng = rand::thread_rng();
        let g1: Gt = rng.gen();
        let h1 = kdf(&g1);
        let h2 = Sha3_256::digest(&g1.to_string().into_bytes());
        assert_eq!(h1, h2);
    }

    #[test]
    fn check_kdf() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xdeadbeef15dead);
        let g1: G1 = rng.gen();
        let g2: Gt = rng.gen();

        assert_ne!(kdf(&g1), kdf(&g2));

        std::println!("g1: {:?}", g1.to_string());
        std::println!("g2: {:?}", g2.to_string());
    }
}
