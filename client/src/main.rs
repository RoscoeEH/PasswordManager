#![allow(dead_code)]

use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
    widgets::{Block, Borders, Paragraph},
    layout::{Layout, Constraint, Direction},
};
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};

use std::error::Error;
use std::sync::OnceLock;
use std::io::{self as stdIO, stdout};

use serde::{Serialize, Deserialize};
use serde_json;
use sha2::{Sha256, Digest};
use std::str;
use hex;


mod crypto;


// Global `OnceLock` for the key
static KEY: OnceLock<[u8; 32]> = OnceLock::new();

// Password Structure
#[derive(Serialize, Deserialize)]
struct PasswordInfo {
    title_hash: [u8; 32],
    title: Vec<u8>,
    user_id: Vec<u8>,
    password: Vec<u8>,
    url: Vec<u8>,
}

// Takes the info for a new password converts it to ciphertext and serializes it to JSON
fn wrap_password(title: String, user_id: String, password: String, url: String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let title_hash = crypto::hash(crypto::HashInputType::Text(title.clone()));

    // Create the PasswordInfo struct
    let password_info = PasswordInfo {
        title_hash,
        title: title.as_bytes().to_vec(),
        user_id: user_id.as_bytes().to_vec(),
        password: password.as_bytes().to_vec(),
        url: url.as_bytes().to_vec(),
    };

    // Serialize to JSON
    let json_data = serde_json::to_vec(&password_info)?;
    Ok(json_data)
}

// Send data to the server
async fn send(stream: &mut TcpStream, request_type: u8, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut request = vec![request_type];
    request.extend_from_slice(data);
    
    stream.write_all(&request).await?;
    Ok(())
}

// Input mode enum
#[derive(PartialEq)]
enum InputMode {
    Command,
    Title,
    UserId,
    Password,
    Url,
    Delete,
    Help,
    Get,
}


struct AppState {
    input: String,
    input_mode: InputMode,
    title: String,
    user_id: String,
    password: String,
    url: String,
    password_list: Vec<ListItem>,
    current_password: Option<PasswordInfo>,
}

// Add this struct to store password list items
#[derive(Clone)]
struct ListItem {
    title: String,
    url: String,
}

// Add this function to receive and parse server responses
async fn receive(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
    let mut buffer = vec![0; 1024];
    let n = stream.read(&mut buffer).await?;
    if n == 0 {
        return Err("Connection closed by server".into());
    }
    
    let response_type = buffer[0];
    let data = buffer[1..n].to_vec();
    Ok((response_type, data))
}

// Updates the password list from the server
async fn update_password_list(stream: &mut TcpStream, app_state: &mut AppState) -> Result<(), Box<dyn Error>> {
    if let Ok(_) = send(stream, 3, b"").await {
        if let Ok((response_type, data)) = receive(stream).await {
            if response_type == 3 {
                if let Ok(list) = serde_json::from_slice::<Vec<serde_json::Value>>(&data) {
                    app_state.password_list = list.into_iter()
                        .filter_map(|item| {
                            if let (Some(title), Some(url)) = (
                                item.get("title").and_then(|t| t.as_str()),
                                item.get("url").and_then(|u| u.as_str())
                            ) {
                                Some(ListItem {
                                    title: title.to_string(),
                                    url: url.to_string(),
                                })
                            } else {
                                None
                            }
                        })
                        .collect();
                }
            }
        }
    }
    Ok(())
}

// Main client function that takes input and communicates with the server
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get key and load it into oncelock
    let input = rpassword::prompt_password("Enter Password: ")
        .expect("Failed to read password");

    KEY.set(crypto::key_derivation(input)).expect("Key has already been initialized");

    // connect to server
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Send request for password list
    send(&mut stream, 3, b"").await?;

    // In main(), before the loop:
    let mut app_state = AppState {
        input: String::new(),
        input_mode: InputMode::Command,
        title: String::new(),
        user_id: String::new(),
        password: String::new(),
        url: String::new(),
        password_list: Vec::new(),
        current_password: None,
    };

    // After sending the initial list request, receive and process the response
    let (response_type, data) = receive(&mut stream).await?;
    if response_type == 3 {
        if let Ok(list) = serde_json::from_slice::<Vec<serde_json::Value>>(&data) {
            app_state.password_list = list.into_iter()
                .filter_map(|item| {
                    if let (Some(title), Some(url)) = (
                        item.get("title").and_then(|t| t.as_str()),
                        item.get("url").and_then(|u| u.as_str())
                    ) {
                        Some(ListItem {
                            title: title.to_string(),
                            url: url.to_string(),
                        })
                    } else {
                        None
                    }
                })
                .collect();
        }
    }

    // Main application loop
    loop {
        terminal.draw(|frame| {
            let size = frame.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(3),
                    Constraint::Length(3),
                ].as_slice())
                .split(size);


            let content = {
                let mut display = String::from("Password Manager\n");
                if app_state.input_mode == InputMode::Help {
                    display.push_str("Available commands:\n");
                    display.push_str("- s: Store a new password\n");
                    display.push_str("- d: Delete a password\n");
                    display.push_str("- g: Get password details\n");
                    display.push_str("- f: Fetch password list\n");
                    display.push_str("- q: Quit the program\n");
                    display.push_str("- h: Show this help\n");
                } else if let Some(pw_info) = &app_state.current_password {
                    display.push_str("\nPassword Details:\n");
                    display.push_str(&format!("\nTitle: {}", String::from_utf8_lossy(&pw_info.title)));
                    display.push_str(&format!("\nUsername: {}", String::from_utf8_lossy(&pw_info.user_id)));
                    display.push_str(&format!("\nPassword: {}", String::from_utf8_lossy(&pw_info.password)));
                    display.push_str(&format!("\nURL: {}", String::from_utf8_lossy(&pw_info.url)));
                    display.push_str("\n\nPress Esc to return to password list");
                } else {
                    display.push_str("\nStored Passwords:\n");
                    for item in &app_state.password_list {
                        display.push_str(&format!("\nTitle: {}\nURL: {}\n", item.title, item.url));
                    }
                }
                display
            };
            let content = Paragraph::new(content)
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(content, chunks[0]);

            // Command input mini-buffer
            let input_prompt = match app_state.input_mode {
                InputMode::Command => "Enter command (h for help):",
                InputMode::Title => "Enter title:",
                InputMode::UserId => "Enter username:",
                InputMode::Password => "Enter password:",
                InputMode::Url => "Enter URL:",
                InputMode::Delete => "Enter title to delete:",
                InputMode::Help => "Press any key to return",
                InputMode::Get => "Enter title to view:",
            };
            let input = Paragraph::new(app_state.input.as_str())
                .block(Block::default().borders(Borders::ALL).title(input_prompt));
            frame.render_widget(input, chunks[1]);
        })?;

        // Handle input
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Esc => {
                        app_state.current_password = None;
                        
                        if app_state.input_mode != InputMode::Command {
                            app_state.input.clear();
                            app_state.title.clear();
                            app_state.user_id.clear();
                            app_state.password.clear();
                            app_state.url.clear();
                            app_state.input_mode = InputMode::Command;
                        }
                    },
                    KeyCode::Enter => {
                        match app_state.input_mode {
                            InputMode::Command => {
                            },
                            InputMode::Delete => {
                                let title = app_state.input.clone();
                                let title_hash = crypto::hash(crypto::HashInputType::Text(title.clone()));
                                
                                if let Ok(_) = send(&mut stream, 5, &title_hash[0..32]).await {
                                    let _ = update_password_list(&mut stream, &mut app_state).await;
                                }
                                app_state.input.clear();
                                app_state.input_mode = InputMode::Command;
                            },
                            InputMode::Title => {
                                app_state.title = app_state.input.clone();
                                app_state.input.clear();
                                app_state.input_mode = InputMode::UserId;
                            },
                            InputMode::UserId => {
                                app_state.user_id = app_state.input.clone();
                                app_state.input.clear();
                                app_state.input_mode = InputMode::Password;
                            },
                            InputMode::Password => {
                                app_state.password = app_state.input.clone();
                                app_state.input.clear();
                                app_state.input_mode = InputMode::Url;
                            },
                            InputMode::Url => {
                                app_state.url = app_state.input.clone();
                                if let Ok(json) = wrap_password(
                                    app_state.title.clone(),
                                    app_state.user_id.clone(),
                                    app_state.password.clone(),
                                    app_state.url.clone()
                                ) {
                                    if let Ok(_) = send(&mut stream, 1, &json).await {
                                        let _ = update_password_list(&mut stream, &mut app_state).await;
                                    }
                                }
                                app_state.input.clear();
                                app_state.title.clear();
                                app_state.user_id.clear();
                                app_state.password.clear();
                                app_state.url.clear();
                                app_state.input_mode = InputMode::Command;
                            },
                            InputMode::Help => {
                                app_state.input_mode = InputMode::Command;
                            },
                            InputMode::Get => {
                                let title = app_state.input.clone();
                                let title_hash = crypto::hash(crypto::HashInputType::Text(title));
                                
                                // Send get request (type 2) with the title hash
                                if let Ok(_) = send(&mut stream, 2, &title_hash).await {
                                    if let Ok((response_type, data)) = receive(&mut stream).await {
                                        if response_type == 2 {
                                            if let Ok(pw_info) = serde_json::from_slice::<PasswordInfo>(&data) {
                                                app_state.current_password = Some(pw_info);
                                            }
                                        }
                                    }
                                }
                                app_state.input.clear();
                                app_state.input_mode = InputMode::Command;
                            },
                        }
                    },
                    KeyCode::Char(c) => {
                        if app_state.input_mode == InputMode::Command {
                            match c {
                                's' => {
                                    app_state.input_mode = InputMode::Title;
                                },
                                'd' => {
                                    app_state.input_mode = InputMode::Delete;
                                },
                                'g' => {
                                    app_state.input_mode = InputMode::Get;
                                },
                                'f' => {
                                    let _ = update_password_list(&mut stream, &mut app_state).await;
                                },
                                'h' => {
                                    app_state.input_mode = InputMode::Help;
                                },
                                'q' => {
                                    break;
                                },
                                _ => {}
                            }
                        } else if app_state.input_mode == InputMode::Help {
                            app_state.input_mode = InputMode::Command;
                        } else {
                            app_state.input.push(c);
                        }
                    },
                    KeyCode::Backspace => {
                        app_state.input.pop();
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;

    Ok(())
}
