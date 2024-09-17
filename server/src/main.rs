use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use std::error::Error;


fn store_password(pw: &[u8]) -> Result<(), Box<dyn Error>> {


    Ok(())
}

fn get_password(pw_id: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {


    Ok(vec![0u8])
}

fn get_list() -> Result<Vec<u8>, Box<dyn Error>> {


    Ok(vec![0u8])
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
