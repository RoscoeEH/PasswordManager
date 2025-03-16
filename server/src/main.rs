/*
 * ------------------------------------------------------------------------------
 * Project:     Personal Password Manager
 * File:        server/main.rs
 * Description: Server that stores serialized and encrytped passwords associated
 *              by hash values. Responds to client input for managing passwords.
 *
 * Author:      RoscoeEH
 * ------------------------------------------------------------------------------
 */

use hex;
use std::error::Error;
use std::str;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rocksdb::DB;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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

#[derive(Serialize, Deserialize)]
struct ListItem {
    title_hash: [u8; 32],
    title: Vec<u8>,
    url: Vec<u8>,
}

fn store_password(pw_json: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let db = DB::open_default(STORAGE_PATH)?;
    let pw_info: PasswordInfo = serde_json::from_slice(pw_json)?;
    let title_hash_str = hex::encode(pw_info.title_hash);

    // Store the full encrypted password info
    db.put(&title_hash_str, pw_json)?;

    // Create a reduced version for the list with just title and URL
    let list_item = ListItem {
        title_hash: pw_info.title_hash,
        title: pw_info.title,
        url: pw_info.url,
    };

    // Update the full list with just titles and URLs
    let mut full_list: Vec<ListItem> = match db.get(FULL_LIST)? {
        Some(list_data) => serde_json::from_slice(&list_data)?,
        None => Vec::new(),
    };

    full_list.push(list_item);
    let updated_list = serde_json::to_vec(&full_list)?;
    db.put(FULL_LIST, updated_list)?;

    Ok(())
}

fn get_password(pw_id: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Open the RocksDB database
    let db = DB::open_default(STORAGE_PATH)?;

    // Convert the pw_id from bytes to a hex string
    let pw_id_str = hex::encode(pw_id);

    // Retrieve the full JSON stored under the title_hash key
    match db.get(&pw_id_str)? {
        Some(value) => Ok(value), // Return the full JSON as Vec<u8>
        None => Err(Box::from("Password not found")),
    }
}

// Gets a list of passwords with a hash, title, and url
fn get_list() -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let db = DB::open_default(STORAGE_PATH)?;

    match db.get(FULL_LIST)? {
        Some(value) => Ok(value),
        None => {
            let empty_list: Vec<ListItem> = Vec::new();
            Ok(serde_json::to_vec(&empty_list)?)
        }
    }
}

fn delete_password(title_hash: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let db = DB::open_default(STORAGE_PATH)?;
    let title_hash_str = hex::encode(title_hash);

    // Update the full list by removing password
    let mut full_list: Vec<ListItem> = match db.get(FULL_LIST)? {
        Some(list_data) => serde_json::from_slice(&list_data)?,
        None => Vec::new(),
    };

    full_list.retain(|item| item.title_hash != *title_hash);

    // Store the updated list
    let updated_list = serde_json::to_vec(&full_list)?;
    db.put(FULL_LIST, updated_list)?;

    // Delete the password entry
    db.delete(&title_hash_str)?;

    Ok(())
}

// Send data to the client
async fn send(
    socket: &mut tokio::net::TcpStream,
    request_type: u8,
    data: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
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

        // Spawn async task
        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut socket, addr).await {
                println!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(
    socket: &mut tokio::net::TcpStream,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut buffer = vec![0; 1024];

    loop {
        let n = match socket.read(&mut buffer).await {
            Ok(0) => {
                break;
            }
            Ok(n) => n,
            Err(e) => {
                println!("Failed to read from socket: {}. Error: {}", addr, e);
                break;
            }
        };

        if n < 1 {
            continue;
        }

        let request = buffer[0];
        let data = if request == 5 {
            // Take exactly 32 bytes
            &buffer[1..33]
        } else {
            &buffer[1..n]
        };

        match request {
            1 => {
                // Find the end of the JSON data
                let json_end = data
                    .iter()
                    .position(|&x| x == b'}')
                    .map(|p| p + 1)
                    .unwrap_or(data.len());

                let clean_data = &data[..json_end];

                match serde_json::from_slice::<PasswordInfo>(clean_data) {
                    Ok(_) => match store_password(clean_data) {
                        Ok(_) => send(socket, 1, b"").await?,
                        Err(_) => send(socket, 0, b"Store failed").await?,
                    },
                    Err(e) => {
                        println!("JSON parsing error: {}", e);
                        send(socket, 0, b"Invalid JSON format").await?
                    }
                }
            }
            2 => match get_password(data) {
                Ok(password) => send(socket, 2, &password).await?,
                Err(e) => {
                    println!("Failed to get password: {}", e);
                    send(socket, 0, b"Password not found").await?
                }
            },
            3 => {
                match get_list() {
                    Ok(item_list) => {
                        // Deserialize to count items
                        if let Ok(_) = serde_json::from_slice::<Vec<ListItem>>(&item_list) {}
                        send(socket, 3, &item_list).await?
                    }
                    Err(e) => {
                        println!("Failed to get item list: {}", e);
                        // Send empty list
                        let empty_list = serde_json::to_vec(&Vec::<Value>::new())?;
                        send(socket, 3, &empty_list).await?
                    }
                }
            }
            4 => {
                send(socket, 4, b"Session closed").await?;
                break;
            }
            5 => match delete_password(data) {
                Ok(_) => send(socket, 5, b"Password deleted").await?,
                Err(e) => {
                    println!("Failed to delete password: {}", e);
                    send(socket, 0, b"Delete failed").await?
                }
            },
            _ => {
                println!("Unknown request type: {}", request);
                send(socket, 0, b"Unknown request").await?;
            }
        }
    }
    Ok(())
}
