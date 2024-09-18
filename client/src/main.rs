use tokio::net::TcpStream;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use std::error::Error;
use std::sync::OnceLock;

use serde_json::{json, Error};


mod crypto;


// Global `OnceLock` for the key
static KEY: OnceLock<[u8; 32]> = OnceLock::new();

// Takes the info for a new password converts it to ciphertext and serializes it to JSON
fn wrap_password(title: String, userID: String, password: String, url: String) -> Result<String, Error> {
    let serialized = json!({
	"Title-Hash": crypto::hash(crypto::HashInputType::Text(title)),
	// TODO alter encrypt and decrypt to work with strings for serialization
	"Title": crypto::encrypt(title, *KEY.get().unwrap()),
	"User-ID": crypto::encrypt(userID, *KEY.get().unwrap()),
	"Password": crypto::encrypt(password, *KEY.get().unwrap()),
	"URL": crypto::encrypt(url, *KEY.get().unwrap())
    });
    
    Ok(serialized)
}

// Main client function that takes input and communicates with the server
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get key and load it into oncelock
    let mut input = String::new(); // Impliment rpassword for security in the future
    println!("Enter Password");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    KEY.set(crypto::key_derivation(input)).expect("Key has already been initialized");

    
    // connect to server
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;
    println!("Connected to the server!");


    // TODO - Take in and handle user requests

    

    Ok(())
}
