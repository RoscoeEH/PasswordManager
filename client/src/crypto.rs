/*
 * ----------------------------------------------------------------------------
 * Project:     Personal Password Manager
 * File:        crypto.rs
 * Description: Library of crypto functions pulled from RustCrypto and given
 *              wrappers to work with relevant types.
 * 
 * Author:      RoscoeEH
 * ---------------------------------------------------------------------------
 */



// Since this is just used as a library for the client the functions will never be called
#[allow(dead_code)]

use pbkdf2::pbkdf2_hmac_array;
use sha2::{Sha256, Digest};
use std::convert::TryFrom;

use rand::distributions::{Alphanumeric, DistString};

use aes_gcm::{aead::{Aead, AeadCore, KeyInit}, Aes256Gcm, Nonce, Key};

// Values taken from Docs
const PBKDF_ITERATIONS: u32 = 600_000;
const SALT: &[u8] = b"%&@/";



// Takes in user password and generates 256-bit key with PBKDF
pub fn key_derivation(password: String) -> [u8;32]{
    // Runs PBKDF
    let key: [u8; 32] = pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), SALT, PBKDF_ITERATIONS);

    key
}



// Uses AES256gcm authenticated encryption to encrypt a string
pub fn encrypt(message: String, key: [u8; 32]) -> Vec<u8>{

    
    let use_key = Key::<Aes256Gcm>::try_from(key).expect("Invalid key length");

    let cipher = Aes256Gcm::new(&use_key);
    let nonce = Aes256Gcm::generate_nonce().unwrap(); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(&nonce, message.as_bytes().as_ref());

    ciphertext.expect("Encryption Error")
}


// Decryptes AES256gcm encryption and returns a Vec<u8>
pub fn decrypt(ciphertext: Vec<u8>, aes_key: [u8;32]) -> Vec<u8> {
    
    // Extract nonce and ciphertext
    let (nonce, data) = ciphertext.split_at(12);
    let key = Key::<Aes256Gcm>::try_from(aes_key).expect("Invalid key length");
    let cipher = Aes256Gcm::new(&key);
   
    let nonce = Nonce::try_from(nonce).expect("Invalid nonce length");
    let plaintext = cipher.decrypt(&nonce, data);

    plaintext.expect("Decryption Error")
}


// Enum to adapt hash to work for both a string and a [u8;32]
pub enum HashInputType {
    Text(String),
    Bytes([u8; 32]),
}


// SHA2-256 hash function returns [u8;32]
pub fn hash(input: HashInputType) -> [u8;32] {
    match input {
  HashInputType::Text(s) => Sha256::digest(s.as_bytes()).into(),
        HashInputType::Bytes(arr) => Sha256::digest(&arr).into() 
    }
}


// Randomly generates string of a given size
pub fn generate_password(length: usize) -> String {

    let password = Alphanumeric.sample_string(&mut rand::thread_rng(), length);

    password
}


