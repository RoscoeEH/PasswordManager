use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use std::error::Error;
use std::str;
use hex;

use rocksdb::{DB};

use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

static STORAGE_PATH: &str = "password_map";
static FULL_LIST: &str = "accounts_list";


#[derive(Serialize, Deserialize)]
struct PasswordInfo {
    title_hash: [u8; 32],
    title: Vec<u8>,
    user_id: Vec<u8>,
    password: Vec<u8>,
    url: Vec<u8>,
}

fn store_password(pw_json: &[u8]) -> Result<(), Box<dyn Error>> {
    // Open the RocksDB database
    let db = DB::open_default(STORAGE_PATH)?;

    // Deserialize the JSON into the PasswordInfo struct
    let pw_info: PasswordInfo = serde_json::from_slice(pw_json)?;

    // Convert the title_hash to a string for storage as the key
    let title_hash_str = hex::encode(pw_info.title_hash);

    // Store the full JSON under the title_hash key
    db.put(&title_hash_str, pw_json)?;

    // Prepare the reduced JSON with only title and url
    let reduced_json = json!({
	"title": str::from_utf8(&pw_info.title)?,
	"url": str::from_utf8(&pw_info.url)?
    });

    // Fetch the current list of titles and URLs from the FULL_LIST key
    let mut full_list: Vec<Value> = match db.get(FULL_LIST)? {
	Some(list_data) => serde_json::from_slice(&list_data)?,
	None => Vec::new(),
    };

    // Add the new reduced JSON to the list
    full_list.push(reduced_json);

    // Serialize the updated list and store it back in the database
    let updated_list = serde_json::to_vec(&full_list)?;
    db.put(FULL_LIST, updated_list)?;

    Ok(())
}



fn get_password(pw_id: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Open the RocksDB database
    let db = DB::open_default(STORAGE_PATH)?;

    // Convert the key (pw_id) from bytes to a hex string
    let pw_id_str = hex::encode(pw_id);

    // Retrieve the full JSON stored under the title_hash key
    match db.get(&pw_id_str)? {
        Some(value) => Ok(value),  // Return the full JSON as Vec<u8>
        None => Err(Box::from("Password not found")),  // Handle case where the key doesn't exist
    }
}

fn get_list() -> Result<Vec<u8>, Box<dyn Error>> {
    // Open the RocksDB database
    let db = DB::open_default(STORAGE_PATH)?;

    // Retrieve the list stored under the FULL_LIST key
    match db.get(FULL_LIST)? {
        Some(value) => Ok(value),  // Return the full list as Vec<u8>
        None => Err(Box::from("No accounts list found")),  // Handle case where the list doesn't exist
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Assign address to localhost
    let address = String::from("127.0.0.1:8080");

    // Bind address to listener
    let tcp_listener = TcpListener::bind(&address).await?;
    println!("Server running on {}", address);
    
    loop {
	// Wait for inbound socket
	let (mut socket, addr) = tcp_listener.accept().await?;
	println!("Accepted connection from {}", addr);

	// Spawn async task
	tokio::spawn(async move {
	    let mut buffer = vec![0; 1024];

	    loop {
		let n = match socket.read(&mut buffer).await {
		    Ok(0) => {
			println!("Connection closed by client: {}", addr);
			break;
		    }
		    Ok(n) => n,
		    Err(e) => {
			println!("Failed to read from socket: {}. Error: {}", addr, e);
			break;
		    }
		};

		if n < 2 {
		    println!("Insufficient data received from client {}", addr);
		    continue;
		}

		// First byte as the request
		let request = buffer[0];

		// Remaining bytes as data
		let data = &buffer[1..n];

		// Prepare the response as Vec<u8>
		let response: Vec<u8> = match request {
		    1 => {
			// Request 1: Store a password
			match store_password(data) {
			    Ok(_) => vec![1u8], 
			    Err(e) => {
				println!("Failed to store password: {}", e);
				vec![0u8] // 0 indicates an error
			    }
			}
		    }
		    2 => {
			// Request 2: Access password
			match get_password(data) {
			    Ok(password) => {
				let mut response = vec![2u8];
				response.extend(password);
				response
			    }
			    Err(e) => {
				println!("Failed to get password: {}", e);
				vec![0u8] // 0 indicates an error
			    }
			}
		    }
		    3 => {
			// Request 3: Access item list
			match get_list() {
                            Ok(item_list) => {
                                let mut response = vec![3u8];
                                response.extend(item_list); 
                                response
                            }
                            Err(e) => {
                                println!("Failed to get item list: {}", e);
                                vec![0u8] // 0 indicates an error
                            }
                        }
                    }
                    4 => {
                        // Request 4: Close session
                        let mut response = vec![4u8]; 
                        response.extend_from_slice(b"Session closed");
                        response
                    }
		    _ => {
                        // Unknown request
                        let mut response = vec![0u8]; 
                        response.extend_from_slice(b"Unknown request"); 
                        response
                    }
                };

                // Send the response
                if let Err(e) = socket.write_all(&response).await {
		    println!("Failed to write to socket: {}. Error: {}", addr, e);
		    break;
                }
	    }
        });
    }
}
