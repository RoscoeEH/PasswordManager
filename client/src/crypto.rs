use hex_literal::hex;
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use sha2::{Sha256, Digest};
use std::io;
use std::error::Error;
use std::convert::TryFrom;

use rand::Rng;
use rand::distributions::Uniform;

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

    
    let use_key = Key::<Aes256Gcm>::try_from(key).expect("Invalid key length");

    let cipher = Aes256Gcm::new(&use_key);
    let nonce = Aes256Gcm::generate_nonce().unwrap(); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(&nonce, message.as_bytes().as_ref());

    ciphertext.expect("Encryption Error")
}


pub fn decrypt(ciphertext: Vec<u8>, aes_key: [u8;32]) -> Vec<u8> {
    
    // Extract nonce and ciphertext
    let (nonce, data) = ciphertext.split_at(12);
    let key = Key::<Aes256Gcm>::try_from(aes_key).expect("Invalid key length");
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
pub fn generate_password(length: usize) -> String {
    let mut password = String::new();
    for _i in 0..length {
	// Generate a random number to convert to an ascii character
	let num = rand::thread_rng().gen_range(33..127);

	// Adds the corresponding ascii char to the string
	if let Some(c) = char::from_u32(num as u32) {
            password.push(c);
        }
    }

    password
}


