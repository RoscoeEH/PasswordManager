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
    let db = DB::open_default(STORAGE_PATH)?;
    let pw_info: PasswordInfo = serde_json::from_slice(pw_json)?;
    let title_hash_str = hex::encode(pw_info.title_hash);
    
    println!("Storing password with hash: {}", title_hash_str);
    println!("Raw hash bytes: {:?}", pw_info.title_hash);
    
    db.put(&title_hash_str, pw_json)?;

    // Prepare the reduced JSON with only title and url
    let reduced_json = json!({
	"title": str::from_utf8(&pw_info.title)?,
	"url": str::from_utf8(&pw_info.url)?
    });

    // Update the full list
    let mut full_list: Vec<Value> = match db.get(FULL_LIST)? {
	Some(list_data) => serde_json::from_slice(&list_data)?,
	None => Vec::new(),
    };

    full_list.push(reduced_json);
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
        None => Err(Box::from("Password not found")), 
    }
}

fn get_list() -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Open the RocksDB database
    let db = DB::open_default(STORAGE_PATH)?;

    // Retrieve the list stored under the FULL_LIST key
    match db.get(FULL_LIST)? {
        Some(value) => Ok(value),  // Return the full list as Vec<u8>
        None => Err(Box::from("No accounts list found")),
    }
}

fn delete_password(title_hash: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let db = DB::open_default(STORAGE_PATH)?;
    let title_hash_str = hex::encode(title_hash);
    
    println!("Attempting to delete password with hash: {}", title_hash_str);
    println!("Raw delete hash bytes: {:?}", title_hash);
    
    // First get the password info to find the title
    let title_to_remove = if let Some(pw_data) = db.get(&title_hash_str)? {
        println!("Found password data in database");
        if let Ok(pw_info) = serde_json::from_slice::<PasswordInfo>(&pw_data) {
            let title = str::from_utf8(&pw_info.title)?.to_string();
            println!("Found title to remove: {}", title);
            title
        } else {
            return Err(Box::from("Failed to parse password info"));
        }
    } else {
        println!("No password found with hash: {}", title_hash_str);
        return Err(Box::from("Password not found"));
    };

    // Update the full list by removing the entry
    let mut full_list: Vec<Value> = match db.get(FULL_LIST)? {
        Some(list_data) => serde_json::from_slice(&list_data)?,
        None => Vec::new(),
    };

    println!("Current list size: {}", full_list.len());
    
    // Remove the entry from the list
    full_list.retain(|item| {
        item.get("title")
            .and_then(|t| t.as_str())
            .map_or(true, |t| t != &title_to_remove)
    });
    
    println!("New list size: {}", full_list.len());
    
    // Update the full list
    let updated_list = serde_json::to_vec(&full_list)?;
    db.put(FULL_LIST, updated_list)?;

    // Finally delete the password entry
    db.delete(&title_hash_str)?;

    Ok(())
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
            Ok(n) => {
                println!("Received {} bytes from client {}", n, addr);
                n
            }
            Err(e) => {
                println!("Failed to read from socket: {}. Error: {}", addr, e);
                break;
            }
        };

        if n < 1 {
            println!("No data received from client {}", addr);
            continue;
        }

        let request = buffer[0];
        let data = if request == 5 {
            // For delete requests, take exactly 32 bytes
            &buffer[1..33]
        } else {
            &buffer[1..n]
        };
        
        match request {
            1 => {
                println!("Processing store password request from {}", addr);
                // Find the end of the JSON data (looking for '}')
                let json_end = data.iter()
                    .position(|&x| x == b'}')
                    .map(|p| p + 1)
                    .unwrap_or(data.len());
                
                let clean_data = &data[..json_end];
                
                match serde_json::from_slice::<PasswordInfo>(clean_data) {
                    Ok(info) => {
                        println!("Successfully parsed JSON");
                        match store_password(clean_data) {
                            Ok(_) => send(socket, 1, b"").await?,
                            Err(e) => {
                                println!("Failed to store password: {}", e);
                                send(socket, 0, b"Store failed").await?
                            }
                        }
                    },
                    Err(e) => {
                        println!("JSON parsing error: {}", e);
                        println!("Raw data (hex): {:?}", clean_data);
                        send(socket, 0, b"Invalid JSON format").await?
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
                println!("Processing list request from {}", addr);
                match get_list() {
                    Ok(item_list) => send(socket, 3, &item_list).await?,
                    Err(e) => {
                        println!("Failed to get item list: {}", e);
                        // Send empty list instead of error
                        let empty_list = serde_json::to_vec(&Vec::<Value>::new())?;
                        send(socket, 3, &empty_list).await?
                    }
                }
            }
            4 => {
                send(socket, 4, b"Session closed").await?;
                break;
            }
            5 => {
                println!("Processing delete request from {}", addr);
                match delete_password(data) {
                    Ok(_) => send(socket, 5, b"Password deleted").await?,
                    Err(e) => {
                        println!("Failed to delete password: {}", e);
                        send(socket, 0, b"Delete failed").await?
                    }
                }
            }
            _ => {
                println!("Unknown request type: {}", request);
                send(socket, 0, b"Unknown request").await?;
            }
        }
    }
    Ok(())
}
