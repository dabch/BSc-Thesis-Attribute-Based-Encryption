// use rabe_bn::{Group, Fr, G};
// use elliptic_curve::{Group, Field, sec1::ToEncodedPoint};
// use k256::{Scalar, ProjectivePoint, AffinePoint};

// extern crate std;
use core::convert::TryInto;
use heapless::{consts, FnvIndexMap, Vec};
use rabe_bn::{Fr, Group, G1};
use rand::{Rng, RngCore};

use hmac::{Hmac, Mac, NewMac};
use sha3::Sha3_512;

pub use abe_utils::access_tree::{AccessNode, AccessStructure, S as STree};
use abe_utils::{kem, polynomial::Polynomial};

pub use ccm::aead::Error;

/// The size of attribute lists, maps etc.
/// 
/// This has to be set at compilation time at the moment.
/// TODO once const generics land: Make the schemes generic over the sizes. This will increase usability a great lot!
pub type S = consts::U32;

pub type G = G1;
type GIntermediate = G;
pub type F = Fr;

/// Private parameters of the ABE scheme, known in only to the KGC
pub struct YctAbePrivate<'attr, 'own> {
  // gen: G,
  atts: &'own FnvIndexMap<&'attr str, F, S>,
  // pk: G,
  master_secret: F,
}

/// Public ABE parameters, known to all participants and required for encryption
pub struct YctAbePublic<'attr, 'own> {
  // gen: G,
  atts: &'own FnvIndexMap<&'attr str, G, S>,
  pk: G,
}

/// Represents a ciphertext as obtained by encrypt() and consumed by decrypt()
/// 
/// Contains both the actual (symetrically) encrypted data and all data required to reconstruct the
/// symmetric keys given a private key created under a matching access structure.
#[derive(Debug, PartialEq, Eq)]
struct YctAbeGroupCiphertext<'attr>(FnvIndexMap<&'attr str, G, S>); // attributes and their respective curve elements

/// Ciphertext obtained by encrypting with GPSW
/// 
/// This is a hybrid ciphertext consisting of the key encapsulation (ABE-encrypted symmetric key) and the
/// symmetrically encrypted data. 
#[derive(Debug, PartialEq, Eq)]
pub struct YctAbeCiphertext<'attr, 'data>(YctAbeGroupCiphertext<'attr>, kem::Ciphertext<'data>);

/// Represents a private key obtained by keygen() and used to decrypt ABE-encrypted data
/// 
/// This data structure mirrors the recursive nature of access structures to ease implementation
/// of decryption. The secret shared (D_u in the original paper) allowing decryption are embedded
/// in the leaves of the tree.
pub struct PrivateKey<'attr, 'own>(
  AccessStructure<'attr, 'own>,
  FnvIndexMap<u8, F, consts::U64>,
  [[u8; 8]; 32],
);


/// Setup of the ABE instance.
/// 
/// Sets up an encryption scheme with a fixed set of attributes and
/// generates both public and private parameter structs. This is typically run exactly once by the KGC.
pub fn setup<'attr, 'es>(
  att_names: &[&'attr str],
  public_map: &'es mut FnvIndexMap<&'attr str, G, S>,
  private_map: &'es mut FnvIndexMap<&'attr str, F, S>,
  rng: &mut dyn RngCore,
) -> (YctAbePrivate<'attr, 'es>, YctAbePublic<'attr, 'es>)
where
  'attr: 'es,
{
  let master_secret: F = rng.gen(); // corresponds to "s" in the original paper
  let g: GIntermediate = rng.gen();

  // for each attribute, choose a private field element s_i and make G * s_i public
  for attr in att_names {
    let si: F = rng.gen();
    let mut gi = g * si;
    gi.normalize();
    private_map.insert(attr, si).unwrap();
    public_map.insert(attr, gi).unwrap();
  }

  let mut pk = g * master_secret;
  pk.normalize(); // master public key, corresponds to `PK`

  (
    YctAbePrivate {
      // gen: g,
      atts: private_map,
      // pk,
      master_secret,
    },
    YctAbePublic {
      // gen: g,
      atts: public_map,
      pk,
    },
  )
}

/// Generates a decryption key.
/// 
/// Generate a private key for a given access structure, which allows a user holding the key to decrypt a ciphertext iff its
/// attributes satisfy the given access structure.
pub fn keygen<'attr, 'es, 'key>(
  master_key: &YctAbePrivate,
  access_structure: AccessStructure<'attr, 'key>,
  rng: &mut dyn RngCore,
) -> Result<PrivateKey<'attr, 'key>, ()>
where
  'attr: 'es,
  'es: 'key,
{
  let mut r_per_level = [[0; 8]; 32];
  for i in 0..r_per_level.len() {
    rng.fill_bytes(&mut r_per_level[i]);
  }
  let tuple_arr: Vec<(u8, F), S> = keygen_node(
    master_key,
    &access_structure,
    0,
    &Polynomial::randgen(master_key.master_secret, 1, rng),
    F::zero(), // this is the only node ever to have index 0, all others have index 1..n,
    0,
    &r_per_level,
    rng,
  )?;
  return Ok(PrivateKey(
    access_structure,
    tuple_arr.into_iter().collect(),
    r_per_level,
  ));
}

/// internal recursive helper to ease key generation
fn keygen_node<'attr, 'es, 'key>(
  master_key: &YctAbePrivate<'attr, 'es>,
  tree_arr: AccessStructure<'key, 'key>,
  tree_ptr: u8,
  parent_poly: &Polynomial,
  index: F,
  level: u8,
  r_per_level: &[[u8; 8]; 32],
  rng: &mut dyn RngCore,
) -> Result<Vec<(u8, F), S>, ()>
where
  'attr: 'es,
  'es: 'key,
{
  // own polynomial at x = 0. Exactly q_parent(index).
  let q_of_zero = parent_poly.eval(index);
  let own_node = &tree_arr[tree_ptr as usize];
  match own_node {
    AccessNode::Leaf(attr_name) => {
      // terminate recursion, embed secret share in the leaf
      let q_of_zero = parent_poly.eval(index);
      let s = master_key.atts.get(*attr_name).unwrap();
      let s_inverse = s.inverse().unwrap();
      return Ok(Vec::from_slice(&[(tree_ptr, q_of_zero * s_inverse)]).unwrap());
    }
    AccessNode::Node(thresh, children) => {
      // continue recursion, call recursively for all children and return a key node that contains children's key subtrees
      let own_poly = Polynomial::randgen(q_of_zero, thresh.clone(), rng); // `thres`-degree polynomial determined by q_of_zero and `thresh` random coefficients
      let mut children_res: Vec<(u8, F), S> = Vec::new();
      for (i, c) in children.iter().enumerate() {
        let res = keygen_node(
          master_key,
          tree_arr,
          *c,
          &own_poly,
          index_prf(r_per_level[level as usize], F::from((i + 1) as u64)),
          level + 1,
          r_per_level,
          rng,
        )?;
        children_res.extend_from_slice(&res)?;
      }
      return Ok(children_res);
    }
  }
}

fn index_prf(r: [u8; 8], i: F) -> F {
  let mut maccer: Hmac<Sha3_512> = Hmac::new_varkey(&r).unwrap();
  maccer.update(&i.uninterpret());
  let mac_res = maccer.finalize().into_bytes();
  // std::println!("{:?}", mac_res);
  F::interpret(mac_res.as_slice().try_into().unwrap())
}

/// Encrypt a plaintext under a set of attributes so that it can be decrypted only with a matching key.
/// 
/// Encrypts data using a hybrid approach, i.e. a random curve point is chosen and encrypted under the ABE scheme.
/// This curve point is then run through a KDF to obtain an AES key, which is used to encrypt the actual payload with
/// AES-256 in CCM mode.
pub fn encrypt<'attr, 'es, 'data>(
  params: &YctAbePublic<'attr, 'es>,
  atts: &[&'attr str],
  data: &'data mut [u8],
  rng: &mut dyn RngCore,
) -> Result<YctAbeCiphertext<'attr, 'data>, ()>
where
  'attr: 'es,
  'es: 'data,
{
  // choose a C', which is then used to encrypt the actual plaintext with a symmetric cipher
  let (k, c_prime) = loop {
    let k: F = rng.gen();
    let mut cprime = GIntermediate::from(params.pk) * k;
    cprime.normalize();
    if !bool::from(cprime.is_zero()) {
      break (k, cprime);
    };
  };

  // Store the information needed to reconstruct C' under a matching key. For each attribute, only a single point
  // multiplication is calculated.
  let mut att_cs: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
  for att in atts {
    let att_pubkey = GIntermediate::from(*params.atts.get(att).unwrap());
    let mut c_i = att_pubkey * k;
    c_i.normalize();
    att_cs.insert(att, c_i).unwrap();
  }

  // let key = c_prime.to_affine().to_encoded_point(false).to_untagged_bytes().unwrap();

  //println!("---------- ENCRYPT: encrypting with point ------------\n{:?}", c_prime.to_affine());
  let kem_ciphertext = match kem::encrypt(&c_prime, data, rng) {
    Ok(c) => c,
    Err(_) => return Err(()),
  };
  Ok(YctAbeCiphertext(
    YctAbeGroupCiphertext(att_cs),
    kem_ciphertext,
  ))
}

/// Recursive helper function for decryption
fn decrypt_node<'attr, 'key>(
  tree_arr: AccessStructure<'attr, 'key>,
  tree_ptr: u8,
  secret_shares: &FnvIndexMap<u8, F, consts::U64>,
  att_cs: &FnvIndexMap<&'attr str, G, S>,
  level: u8,
  r_per_level: &[[u8; 8]; 32],
) -> Option<GIntermediate>
where
  'attr: 'key,
{
  let own_node = &tree_arr[tree_ptr as usize];
  match own_node {
    AccessNode::Leaf(name) => {
      // terminate recursion - we have reached a leaf node containing a secret share. Encryption can only be successful if
      // the matching remaining part of the secret is embedded within the ciphertext (that is the case iff the ciphertext
      // was encrypted under the attribute that our current Leaf node represents)
      let d_u = match secret_shares.get(&tree_ptr) {
        None => return None,
        Some(d_u) => d_u,
      };
      match att_cs.get(name) {
        None => return None,
        Some(c_i) => return Some(GIntermediate::from(*c_i) * *d_u),
      }
    }
    AccessNode::Node(thresh, children) => {
      // continue recursion - call for all children and then, if enough children decrypt successfully, reconstruct the secret share for
      // this intermediate node.
      let pruned = match abe_utils::access_tree::prune_dec(tree_arr, tree_ptr, att_cs) {
        Some((_, children)) => children,
        None => return None,
      };

      let children_result: Vec<(F, GIntermediate), STree> = pruned
        .iter()
        .map(|i| {
          (
            index_prf(r_per_level[level as usize], F::from(*i as u64)),
            decrypt_node(
              tree_arr,
              children[(i - 1) as usize],
              secret_shares,
              att_cs,
              level + 1,
              r_per_level,
            ),
          )
        }) // node indexes start at one, enumerate() starts at zero!
        .filter_map(|(i, x)| match x {
          None => None,
          Some(y) => Some((i, y)),
        }) // filter out all children that couldn't decrypt because of missing ciphertext secret shares
        .collect();
      // we can only reconstruct our secret share if at least `thresh` children decrypted successfully (interpolation of `thresh-1`-degree polynomial)
      if children_result.len() < *thresh as usize {
        return None;
      }
      // an arbitrary subset omega with |omega| = thresh is enough to reconstruct the secret. To make it easy, we just take the first `thresh` in our list.
      let relevant_children: Vec<(F, GIntermediate), STree> =
        children_result.into_iter().take(*thresh as usize).collect();
      let relevant_indexes: Vec<F, STree> =
        relevant_children.iter().map(|(i, _)| i.clone()).collect(); // our langrange helper function wants this vector of field elements
      let result: GIntermediate = relevant_children
        .into_iter()
        .map(|(i, dec_res)| dec_res * Polynomial::lagrange_of_zero(&i, &relevant_indexes))
        .fold(GIntermediate::zero(), |acc, g| g + acc);
      // //println!("node got result: {:?}\n at node {:?}\n", result, key);
      return Some(result);
    }
  }
}

/// Decrypt an ABE-encrypted ciphertext.
/// 
/// Decrypts a ciphertext encrypted under the ABE scheme and returns the plaintext if decryption was successful.
/// If it failed, the ciphertext is returned such that it may be decrypted again with a different key.
pub fn decrypt<'attr, 'key, 'data>(
  ciphertext: YctAbeCiphertext<'attr, 'data>,
  key: &PrivateKey<'attr, 'key>,
) -> Result<&'data [u8], YctAbeCiphertext<'attr, 'data>>
where
  'attr: 'key,
  'key: 'data,
{
  let YctAbeCiphertext(kem_cipher, data_cipher) = ciphertext;
  let PrivateKey(access_structure, secret_shares, r_per_level) = key;

  let res = decrypt_node(
    &access_structure,
    0,
    &secret_shares,
    &kem_cipher.0,
    0,
    r_per_level,
  );
  let mut c_prime = match res {
    None => return Err(YctAbeCiphertext(kem_cipher, data_cipher)),
    Some(p) => p,
  };

  c_prime.normalize();
  // let key = c_prime.to_affine().to_encoded_point(false).to_untagged_bytes().unwrap();
  match kem::decrypt(&c_prime, data_cipher) {
    Ok(data) => Ok(data),
    Err(ct) => Err(YctAbeCiphertext(kem_cipher, ct)),
  }
}

#[cfg(test)]
mod tests {
  extern crate std;
  use super::*;

  use rand::Rng;

  #[test]
  fn leaf_only_access_tree() {
    let mut access_structure_vec: Vec<AccessNode, consts::U64> = Vec::new();
    access_structure_vec
      .push(AccessNode::Leaf("student"))
      .unwrap();
    let access_structure = &access_structure_vec[..];

    let mut public_map: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, F, S> = FnvIndexMap::new();

    let mut rng = rand::thread_rng();
    let data_orig: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();
    let mut data = data_orig.clone();

    let attributes_1: Vec<&str, consts::U64> =
      Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let attributes_2: Vec<&str, consts::U64> = Vec::from_slice(&["tum", "over21"]).unwrap();

    let system_atts: Vec<&str, consts::U256> =
      Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();
    let (private, public) = setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    let priv_key = keygen(&private, &access_structure, &mut rng).unwrap();

    let ciphertext = encrypt(&public, &attributes_1, &mut data, &mut rng).unwrap();

    let res = decrypt(ciphertext, &priv_key);

    assert_eq!(Ok(&data_orig[..]), res);

    let mut data = data_orig.clone();

    let ciphertext = encrypt(&public, &attributes_2, &mut data, &mut rng).unwrap();
    let _res = decrypt(ciphertext, &priv_key).unwrap_err();
    // assert_eq!(Err(()), res);
  }

  #[test]
  fn flat_access_tree() {
    let access_structure: AccessStructure = &[
      AccessNode::Node(2, Vec::from_slice(&[1, 2, 3, 4]).unwrap()),
      AccessNode::Leaf("tum"),
      AccessNode::Leaf("student"),
      AccessNode::Leaf("has_bachelor"),
      AccessNode::Leaf("over21"),
    ];

    let attributes_1 = &["student", "tum", "has_bachelor", "over21"][..];
    let attributes_2 = &["tum"][..];

    let mut public_map: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, F, S> = FnvIndexMap::new();

    let mut rng = rand::thread_rng();
    let data_orig: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();
    let mut data = data_orig.clone();

    let system_atts: Vec<&str, consts::U256> =
      Vec::from_slice(&["student", "tum", "has_bachelor", "over21"]).unwrap();

    let (es, public) = setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    //println!("{:#?}", es);
    //println!("\n public params:\n{:#?}", public);
    let priv_key = keygen(&es, &access_structure, &mut rng).unwrap();
    //println!("private key:\n{:?}", priv_key)

    let ciphertext = encrypt(&public, &attributes_1, &mut data, &mut rng).unwrap();
    // println!("ciphertext:\n{:?}", ciphertext);
    let res = decrypt(ciphertext, &priv_key);
    assert_eq!(Ok(&data_orig[..]), res);
    // failing decryption
    let mut data = data_orig.clone();
    let ciphertext = encrypt(&public, &attributes_2, &mut data, &mut rng).unwrap();
    let _res = decrypt(ciphertext, &priv_key).unwrap_err();
    // assert_eq!(Err(Error), res);
  }

  #[test]
  fn deep_access_tree() {
    let mut public_map: FnvIndexMap<&str, G, S> = FnvIndexMap::new();
    let mut private_map: FnvIndexMap<&str, F, S> = FnvIndexMap::new();
    let mut rng = rand::thread_rng();
    let data_orig: Vec<u8, consts::U2048> = (0..500).map(|_| rng.gen()).collect();

    let system_atts = ["student", "tum", "over21", "over25", "has_bachelor", "cs"];
    let (es, public) = setup(&system_atts, &mut public_map, &mut private_map, &mut rng);
    let attributes = &["student", "tum"][..];
    let mut data = data_orig.clone();
    let ciphertext = encrypt(&public, &attributes, &mut data, &mut rng).unwrap();

    // this represents the following logical access structure:
    // (tum AND student) OR (cs AND has_bachelor AND (over21 OR over25))
    let access_structure: AccessStructure = &[
      AccessNode::Node(1, Vec::from_slice(&[1, 2]).unwrap()), // 0
      AccessNode::Node(2, Vec::from_slice(&[3, 4]).unwrap()), // 1
      AccessNode::Node(3, Vec::from_slice(&[5, 6, 7]).unwrap()), // 2
      AccessNode::Leaf("student"),                            // 3
      AccessNode::Leaf("tum"),                                // 4
      AccessNode::Leaf("cs"),                                 // 5
      AccessNode::Leaf("has_bachelor"),                       // 6
      AccessNode::Node(1, Vec::from_slice(&[8, 9]).unwrap()), // 7
      AccessNode::Leaf("over21"),                             // 8
      AccessNode::Leaf("over25"),                             // 9
    ];

    let priv_key = keygen(&es, &access_structure, &mut rng).unwrap();
    //println!("private key:\n{:?}", priv_key);

    // example 1 - shall decrypt (defined above)
    let res = decrypt(ciphertext, &priv_key);
    assert_eq!(Ok(&data_orig[..]), res);

    // example 2 - shall decrypt
    let attributes = &["student", "has_bachelor", "cs", "over21"][..];
    let mut data = data_orig.clone();
    let ciphertext = encrypt(&public, &attributes, &mut data, &mut rng).unwrap();
    let res = decrypt(ciphertext, &priv_key);
    assert_eq!(Ok(&data_orig[..]), res);
    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key).unwrap();
    // assert_eq!(decrypted, data);

    // example 2 - shall not decrypt
    let attributes = &["student", "cs", "over21"][..];
    let mut data = data_orig.clone();
    let ciphertext = encrypt(&public, &attributes, &mut data, &mut rng).unwrap();
    let _res = decrypt(ciphertext, &priv_key).unwrap_err();
    // assert_eq!(Err(Error), res);
    // let ciphertext = public.encrypt(&attributes, &data);
    // let decrypted = public.decrypt(&ciphertext, &priv_key);
    // assert_eq!(None, decrypted);
  }

  #[test]
  fn curve_operations_dry_run() {
    let mut rng = rand::thread_rng();

    let s: F = rng.gen();
    let s_inv: F = s.inverse().unwrap();

    let g: GIntermediate = rng.gen();

    let c = g * s;

    let c_dec = c * s_inv;
    assert_eq!(g, c_dec);
  }
}
