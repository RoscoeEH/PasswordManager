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

fn store_password(pw_json: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
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



fn get_password(pw_id: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
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

fn get_list() -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Open the RocksDB database
    let db = DB::open_default(STORAGE_PATH)?;

    // Retrieve the list stored under the FULL_LIST key
    match db.get(FULL_LIST)? {
        Some(value) => Ok(value),  // Return the full list as Vec<u8>
        None => Err(Box::from("No accounts list found")),  // Handle case where the list doesn't exist
    }
}

// Send data to the client
async fn send(socket: &mut tokio::net::TcpStream, request_type: u8, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut response = vec![request_type];
    response.extend_from_slice(data);
    
    socket.write_all(&response).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
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
	    if let Err(e) = handle_connection(&mut socket, addr).await {
		println!("Error handling connection from {}: {}", addr, e);
	    }
	});
    }
}

async fn handle_connection(socket: &mut tokio::net::TcpStream, addr: std::net::SocketAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
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

	let request = buffer[0];
	let data = &buffer[1..n];

	match request {
	    1 => {
		match store_password(data) {
		    Ok(_) => send(socket, 1, b"").await?,
		    Err(e) => {
			println!("Failed to store password: {}", e);
			send(socket, 0, b"Store failed").await?
		    }
		}
	    }
	    2 => {
		match get_password(data) {
		    Ok(password) => send(socket, 2, &password).await?,
		    Err(e) => {
			println!("Failed to get password: {}", e);
			send(socket, 0, b"Password not found").await?
		    }
		}
	    }
	    3 => {
		match get_list() {
		    Ok(item_list) => send(socket, 3, &item_list).await?,
		    Err(e) => {
			println!("Failed to get item list: {}", e);
			send(socket, 0, b"List not found").await?
		    }
		}
	    }
	    4 => {
		send(socket, 4, b"Session closed").await?;
		break;
	    }
	    _ => {
		send(socket, 0, b"Unknown request").await?;
	    }
	}
    }
    Ok(())
}
