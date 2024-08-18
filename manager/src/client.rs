use hex_literal::hex;
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use sha2::Sha256;
use std::io;
use std::sync::OnceLock;
use std::error::Error;

use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce, Key};

const PBKDF_ITERATIONS: u32 = 600_000;
const SALT: &[u8] = b"%&@/";
static AES_KEY: OnceLock<[u8; 32]> = OnceLock::new();


// Takes in user password and generates key with PBKDF
fn get_key(){
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
    let useKey = Key::<Aes256Gcm>::from_slice(key);

    let cipher = Aes256Gcm::new(&useKey);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, message.as_bytes().as_ref())?;

    return cipertext
}


pub fn run() {
    get_key();
}
