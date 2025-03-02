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
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

use rand::distributions::{Alphanumeric, DistString};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};

// Values taken from Docs
const PBKDF_ITERATIONS: u32 = 600_000;
const SALT: &[u8] = b"%&@/";

// Takes in user password and generates 256-bit key with PBKDF
pub fn key_derivation(password: String) -> [u8; 32] {
    // Runs PBKDF
    let key: [u8; 32] =
        pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), SALT, PBKDF_ITERATIONS);

    key
}

// #[test]
pub fn pbkdf2_kat() {
    let password = "test_password".to_string();

    let expected_key: [u8; 32] = [
        0x57, 0x49, 0x0a, 0xf8, 0x65, 0x9b, 0x91, 0x45, 0xca, 0x91, 0x2d, 0x1e, 0x4b, 0xa2, 0xb3,
        0x34, 0x38, 0xae, 0xbe, 0x0b, 0xc8, 0x9e, 0xdf, 0xf8, 0xe0, 0xa6, 0x49, 0xe4, 0x5e, 0xbb,
        0x22, 0xff,
    ];
    let derived_key = key_derivation(password);
    assert_eq!(derived_key, expected_key, "PBKDF2 KAT Failed");
}

// Uses AES256gcm authenticated encryption to encrypt a string
pub fn encrypt(message: String, key: [u8; 32]) -> Vec<u8> {
    let use_key = Key::<Aes256Gcm>::try_from(key).expect("Invalid key length");
    let cipher = Aes256Gcm::new(&use_key);
    let nonce = Aes256Gcm::generate_nonce().expect("Failed to generate nonce");

    let ciphertext = cipher
        .encrypt(&nonce, message.as_bytes().as_ref())
        .expect("Encryption Error");

    // Combine nonce and ciphertext into a single Vec
    let mut encrypted = nonce.to_vec();
    encrypted.extend_from_slice(&ciphertext);
    encrypted
}

// Decryptes AES256gcm encryption and returns a Vec<u8>
pub fn decrypt(ciphertext: Vec<u8>, aes_key: [u8; 32]) -> Vec<u8> {
    if ciphertext.len() < 12 {
        // Check if we have enough bytes for the nonce
        panic!("Ciphertext too short");
    }

    // Split the input into nonce and ciphertext
    let (nonce_slice, encrypted_data) = ciphertext.split_at(12);

    let key = Key::<Aes256Gcm>::try_from(aes_key).expect("Invalid key length");
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(nonce_slice);
    cipher
        .decrypt(nonce, encrypted_data)
        .expect("Decryption Error")
}

// #[test]
pub fn aes256_kat() {
    let key: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];
    let plaintext = "This is a test message".to_string();

    // Encrypt the plaintext
    let encrypted = encrypt(plaintext.clone(), key);

    // Ensure that encryption produced output longer than just the nonce
    assert!(encrypted.len() > 12, "AES-256 KAT Failed - No ciphertext");

    // Decrypt back and compare with the original plaintext
    let decrypted = decrypt(encrypted, key);
    assert_eq!(
        decrypted,
        plaintext.as_bytes(),
        "AES-256 KAT Failed - Plaintext does not match ciphertext"
    );
}

// Enum to adapt hash to work for both a string and a [u8;32]
pub enum HashInputType {
    Text(String),
    Bytes([u8; 32]),
}

// SHA2-256 hash function returns [u8;32]
pub fn hash(input: HashInputType) -> [u8; 32] {
    match input {
        HashInputType::Text(s) => Sha256::digest(s.as_bytes()).into(),
        HashInputType::Bytes(arr) => Sha256::digest(&arr).into(),
    }
}

// #[test]
pub fn sha256_kat() {
    let text_input = "hello world".to_string();
    let expected_hash: [u8; 32] = [
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab,
        0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef,
        0xcd, 0xe9,
    ];
    let computed_hash = hash(HashInputType::Text(text_input));
    assert_eq!(computed_hash, expected_hash, "SHA2-256 KAT Failed");
}

// Randomly generates string of a given size
pub fn generate_password(length: usize) -> String {
    let password = Alphanumeric.sample_string(&mut rand::thread_rng(), length);

    password
}
