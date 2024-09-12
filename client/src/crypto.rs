#![allow(unused_imports)]
#![allow(dead_code)]
#[allow(non_snake_case)]


use hex_literal::hex;
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use sha2::{Sha256, Digest};
use std::io;
use std::error::Error;


use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce, Key};

// Values taken from Docs
const PBKDF_ITERATIONS: u32 = 600_000;
const SALT: &[u8] = b"%&@/";


// Takes in user password and generates key with PBKDF
pub fn key_derivation(password: String) -> [u8;32]{
    // Runs PBKDF
    let key: [u8; 32] = pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), SALT, PBKDF_ITERATIONS);

    key
}




pub fn encrypt(message: String, key: [u8; 32]) -> Vec<u8>{

    
    let useKey = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(&useKey);
    let nonce = Aes256Gcm::generate_nonce().unwrap(); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(&nonce, message.as_bytes().as_ref());

    ciphertext.expect("Encryption Error")
}


pub fn decrypt(ciphertext: Vec<u8>, aesKey: [u8;32]) -> Vec<u8> {
    
    // Extract nonce and ciphertext
    let (nonce, data) = ciphertext.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(&aesKey);
    let cipher = Aes256Gcm::new(&key);
 
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), data);

    plaintext.expect("Decryption Error")
}

pub enum HashInputType {
    Text(String),
    Bytes([u8; 32]),
}

pub fn hash(input: HashInputType) -> [u8;32] {
    match input {
	HashInputType::Text(s) => Sha256::digest(s.as_bytes()).into(),
	HashInputType::Bytes(arr) => Sha256::digest(&arr).into() 
    }
}


// Generates new passwords
// pub fn generate_password(length: u8, excludeChars: Vec<char>, useWords: bool, charMapping: bool) {
    
// }
 
