use tokio::net::TcpStream;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use std::error::Error;
use std::sync::OnceLock;
use std::io as stdIO;

use serde::{Serialize, Deserialize};


mod crypto;


// Global `OnceLock` for the key
static KEY: OnceLock<[u8; 32]> = OnceLock::new();

// Password Structure
#[derive(Serialize, Deserialize)]
struct PasswordInfo {
    title_hash: [u8;32],
    title: Vec<u8>,
    user_id: Vec<u8>,
    password: Vec<u8>,
    url: Vec<u8>,
}

// Takes the info for a new password converts it to ciphertext and serializes it to JSON
fn wrap_password(pw_title: String, pw_user_id: String, user_password: String, web_url: String) -> Result<String, Box<dyn Error>> {
    let data = PasswordInfo {
        title_hash: crypto::hash(crypto::HashInputType::Text(pw_title.clone())),
        title: crypto::encrypt(pw_title, *KEY.get().unwrap()),
        user_id: crypto::encrypt(pw_user_id, *KEY.get().unwrap()),
        password: crypto::encrypt(user_password, *KEY.get().unwrap()),
        url: crypto::encrypt(web_url, *KEY.get().unwrap()),
    };

    Ok(serde_json::to_string(&data)?)
}

// Main client function that takes input and communicates with the server
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get key and load it into oncelock
    let mut input = String::new(); // Impliment rpassword for security in the future
    println!("Enter Password: ");
    stdIO::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    KEY.set(crypto::key_derivation(input)).expect("Key has already been initialized");

    
    // connect to server
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;
    println!("Connected to the server!");


    // TODO - Take in and handle user requests

    

    Ok(())
}
