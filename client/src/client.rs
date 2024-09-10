use hex_literal::hex;
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use sha2::Sha256;
use std::io;
use std::sync::OnceLock;
use std::error::Error;

use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce, Key};

// Values taken from Docs
const PBKDF_ITERATIONS: u32 = 600_000;
const SALT: &[u8] = b"%&@/";
static AES_KEY: OnceLock<[u8; 32]> = OnceLock::new();


// PBKDF wrapper
fn key_derivation(password: String) -> [u8; 32]{

    // Raise error is OnceLock is full
    
    println!("Master Key:\n");
    let mut password = String::new();

    io::stdin().read_line(&mut password).expect("failed to readline");

    // Runs PBKDF
    let newKey: [u8; 32] = pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), SALT, PBKDF_ITERATIONS);

    // Sets new key into the once lock and panics if it can't add it
    if AES_KEY.set(newKey) == Ok(()){
		panic!("Failed to set AES key.")
    }
}


fn encrypt(message: String, key: [u8, 32]) -> Result<Vec<u8>, Error>{

    // Make it take the session key stored in OnceLock instead of an argument
    // Raise error if no key is stored
    
    let useKey = Key::<Aes256Gcm>::from_slice(key);

    let cipher = Aes256Gcm::new(&useKey);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, message.as_bytes().as_ref())?;

    return cipertext
}


fn decrypt(ciphertext: Vec<u8>, aesKey: [u8, 32]) -> Result<Vec<u8>, Error>{

    // Make it take the session key stored in OnceLock instead of an argument
    // Raise error if no key is stored
    
    // Extract nonce and ciphertext
    let (nonce, ciphertext) = encrypted_data.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(&aesKey);
    let cipher = Aes256Gcm::new(&use_key);

    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?;

    
    return Ok(String::from_utf8(plaintext)?)

}

fn hash(text: String){
   
}


// Generates new passwords
fn generate_password(length: u8, excludeChars: Vec<char>, useWords: bool, charMapping: bool) -> String {

}



pub fn run() {
    get_key();
}
