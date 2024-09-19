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
#[derive(Serialize)]
struct PasswordInfo {
    Title_Hash: [u8;32],
    Title: Vec<u8>,
    User_ID: Vec<u8>,
    Password: Vec<u8>,
    URL: Vec<u8>,
}

// Takes the info for a new password converts it to ciphertext and serializes it to JSON
fn wrap_password(title: String, userID: String, password: String, url: String) -> Result<String, Box<dyn Error>> {
    let data = PasswordInfo {
        Title_Hash: crypto::hash(crypto::HashInputType::Text(title.clone())),
        Title: crypto::encrypt(title, *KEY.get().unwrap()),
        User_ID: crypto::encrypt(userID, *KEY.get().unwrap()),
        Password: crypto::encrypt(password, *KEY.get().unwrap()),
        URL: crypto::encrypt(url, *KEY.get().unwrap()),
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
