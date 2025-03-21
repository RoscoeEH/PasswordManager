/*
 * ----------------------------------------------------------------------------
 * Project:     Personal Password Manager
 * File:        client/main.rs
 * Description: Client for accessing and decrypting stored passwords from the a
 *              server. Also allows for password generation and management.
 *
 * Author:      RoscoeEH
 * ---------------------------------------------------------------------------
 */

#![allow(dead_code)]

use copypasta::{ClipboardContext, ClipboardProvider};
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use std::error::Error;
use std::io::stdout;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json;
use std::str;

mod crypto;

// Global OnceLock for the key
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

// Server list item structure
#[derive(Serialize, Deserialize)]
struct ServerListItem {
    title_hash: [u8; 32],
    title: Vec<u8>,
    url: Vec<u8>,
}

// Takes the info for a new password converts it to ciphertext and serializes it to JSON
fn wrap_password(
    title: String,
    user_id: String,
    password: String,
    url: String,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let title_hash = crypto::hash(crypto::HashInputType::Text(title.clone()));

    // Get the key
    let key = KEY.get().expect("Key not initialized");

    // Encrypt the sensitive fields
    let encrypted_title = crypto::encrypt(title, *key);
    let encrypted_user_id = crypto::encrypt(user_id, *key);
    let encrypted_password = crypto::encrypt(password, *key);
    let encrypted_url = crypto::encrypt(url, *key);

    // Create PasswordInfo struct
    let password_info = PasswordInfo {
        title_hash,
        title: encrypted_title,
        user_id: encrypted_user_id,
        password: encrypted_password,
        url: encrypted_url,
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
    GeneratePasswordPrompt,
    PasswordLengthPrompt,
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
    show_password: bool,
    waiting_for_second_key: Option<char>,
    current_page: usize,
    items_per_page: usize,
}

// Struct to store password list items
#[derive(Clone)]
struct ListItem {
    title: String,
    url: String,
}

// Receive and parse server responses
async fn receive(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
    let mut buffer = vec![0; 8192];
    let n = stream.read(&mut buffer).await?;
    if n == 0 {
        return Err("Connection closed by server".into());
    }

    let response_type = buffer[0];
    let data = buffer[1..n].to_vec();
    Ok((response_type, data))
}

// Update the password list from the server
async fn update_password_list(
    stream: &mut TcpStream,
    app_state: &mut AppState,
) -> Result<(), Box<dyn Error>> {
    if let Ok(_) = send(stream, 3, b"").await {
        if let Ok((response_type, data)) = receive(stream).await {
            if response_type == 3 {
                if let Ok(list) = serde_json::from_slice::<Vec<ServerListItem>>(&data) {
                    let key = KEY.get().expect("Key not initialized");

                    app_state.password_list = list
                        .into_iter()
                        .filter_map(|item| {
                            match (
                                String::from_utf8(crypto::decrypt(item.title, *key)),
                                String::from_utf8(crypto::decrypt(item.url, *key)),
                            ) {
                                (Ok(title), Ok(url)) => Some(ListItem { title, url }),
                                _ => None,
                            }
                        })
                        .collect();

                    // Sort the password list by title
                    app_state
                        .password_list
                        .sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
                }
            }
        }
    }
    Ok(())
}

// Validate password instead of the program exiting on wrong passwords
async fn validate_password(
    password: &str,
    stream: &mut TcpStream,
) -> Result<[u8; 32], Box<dyn Error>> {
    // Derive key from the password
    let derived_key = crypto::key_derivation(password.to_string());

    // Request the password list from the server to test decryption
    if let Ok(_) = send(stream, 3, b"").await {
        if let Ok((response_type, data)) = receive(stream).await {
            if response_type == 3 {
                if let Ok(list) = serde_json::from_slice::<Vec<ServerListItem>>(&data) {
                    // Try to decrypt the first item's title
                    if !list.is_empty() {
                        // Try to decrypt and catch any errors
                        match std::panic::catch_unwind(|| {
                            crypto::decrypt(list[0].title.clone(), derived_key)
                        }) {
                            Ok(title_bytes) => {
                                // Successfully decrypted, check if it's valid UTF-8
                                if String::from_utf8(title_bytes).is_ok() {
                                    return Ok(derived_key);
                                }
                            }
                            Err(_) => {
                                // Decryption failed - wrong password
                                return Err("Invalid password".into());
                            }
                        }
                    } else {
                        // No passwords yet - sets new master password
                        return Ok(derived_key);
                    }
                }
            }
        }
    }

    Err("Invalid password".into())
}

// Main client function
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // connect to server
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;

    // Password validation loop
    let derived_key = loop {
        let input =
            rpassword::prompt_password("Enter Password: ").expect("Failed to read password");

        match validate_password(&input, &mut stream).await {
            Ok(key) => break key,
            Err(_) => {
                println!("Invalid password. Please try again.");
                continue;
            }
        }
    };

    // Now store the validated key
    KEY.set(derived_key)
        .expect("Key has already been initialized");

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Send request for password list
    send(&mut stream, 3, b"").await?;

    // display-able state options
    let mut app_state = AppState {
        input: String::new(),
        input_mode: InputMode::Command,
        title: String::new(),
        user_id: String::new(),
        password: String::new(),
        url: String::new(),
        password_list: Vec::new(),
        current_password: None,
        show_password: false,
        waiting_for_second_key: None,
        current_page: 0,
        items_per_page: 10,
    };

    // After sending the initial list request, receive and process the response
    let (response_type, data) = receive(&mut stream).await?;
    if response_type == 3 {
        if let Ok(list) = serde_json::from_slice::<Vec<ServerListItem>>(&data) {
            let key = KEY.get().expect("Key not initialized");

            app_state.password_list = list
                .into_iter()
                .filter_map(|item| {
                    match (
                        String::from_utf8(crypto::decrypt(item.title, *key)),
                        String::from_utf8(crypto::decrypt(item.url, *key)),
                    ) {
                        (Ok(title), Ok(url)) => Some(ListItem { title, url }),
                        _ => None,
                    }
                })
                .collect();

            // Sort the password list by title
            app_state
                .password_list
                .sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
        }
    }

    // Main application loop
    loop {
        terminal.draw(|frame| {
            let size = frame.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)].as_slice())
                .split(size);

            let content = {
                let mut display = String::from("Password Manager\n");
                if app_state.input_mode == InputMode::Help {
                    display.push_str("Available commands:\n");
                    display.push_str("- s: Store a new password\n");
                    display.push_str("- d: Delete a password\n");
                    display.push_str("- g: Get password details\n");
                    display.push_str("- f: Fetch password list\n");
                    display.push_str("- n: Next page of passwords\n");
                    display.push_str("- p: Previous page of passwords\n");
                    display.push_str("- q: Quit the program\n");
                    display.push_str("- h: Show this help\n");
                } else if let Some(pw_info) = &app_state.current_password {
                    let key = KEY.get().expect("Key not initialized");

                    // Decrypt all fields
                    let title = String::from_utf8(crypto::decrypt(pw_info.title.clone(), *key))
                        .unwrap_or_else(|_| "Invalid UTF-8".to_string());
                    let username =
                        String::from_utf8(crypto::decrypt(pw_info.user_id.clone(), *key))
                            .unwrap_or_else(|_| "Invalid UTF-8".to_string());
                    let password =
                        String::from_utf8(crypto::decrypt(pw_info.password.clone(), *key))
                            .unwrap_or_else(|_| "Invalid UTF-8".to_string());
                    let url = String::from_utf8(crypto::decrypt(pw_info.url.clone(), *key))
                        .unwrap_or_else(|_| "Invalid UTF-8".to_string());

                    display.push_str("\nPassword Details:\n");
                    display.push_str(&format!("\nTitle: {}", title));
                    display.push_str(&format!("\nUsername: {}", username));

                    if app_state.show_password {
                        display.push_str(&format!("\nPassword: {}", password));
                    } else {
                        display.push_str(&format!("\nPassword: {}", "*".repeat(password.len())));
                    }

                    display.push_str(&format!("\nURL: {}", url));
                    display.push_str("\n\nPress 's' to show/hide password");
                    display.push_str("\nPress 'c-p' to copy password");
                    display.push_str("\nPress 'c-u' to copy username");
                    display.push_str("\nPress Esc to return to password list");
                } else {
                    display.push_str("\nStored Passwords:\n");

                    // Calculate total pages
                    let total_pages = if app_state.password_list.is_empty() {
                        1
                    } else {
                        (app_state.password_list.len() - 1) / app_state.items_per_page + 1
                    };

                    // Get start and end indices for current page
                    let start_idx = app_state.current_page * app_state.items_per_page;
                    let end_idx =
                        (start_idx + app_state.items_per_page).min(app_state.password_list.len());

                    // Display page information
                    display.push_str(&format!(
                        "\nPage {} of {} ({} items)\n",
                        app_state.current_page + 1,
                        total_pages,
                        app_state.password_list.len()
                    ));

                    // Display passwords for current page
                    if app_state.password_list.is_empty() {
                        display.push_str("\nNo passwords stored.\n");
                    } else {
                        for item in &app_state.password_list[start_idx..end_idx] {
                            display
                                .push_str(&format!("\nTitle: {}\nURL: {}\n", item.title, item.url));
                        }

                        // Add navigation hints if multiple pages
                        if total_pages > 1 {
                            display.push_str("\nPress 'n' for next page, 'p' for previous page\n");
                        }
                    }
                }
                display
            };
            let content = Paragraph::new(content).block(Block::default().borders(Borders::ALL));
            frame.render_widget(content, chunks[0]);

            // Command input mini-buffer
            let input_prompt = match app_state.input_mode {
                InputMode::Command => "Enter command (h for help):",
                InputMode::Title => "Enter title:",
                InputMode::UserId => "Enter username:",
                InputMode::Password => "Enter password:",
                InputMode::GeneratePasswordPrompt => {
                    "Would you like to generate a password? (y/n):"
                }
                InputMode::PasswordLengthPrompt => "Enter password length (recommended: 16-32):",
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
                        app_state.show_password = false;
                        app_state.waiting_for_second_key = None;

                        if app_state.input_mode != InputMode::Command {
                            app_state.input.clear();
                            app_state.title.clear();
                            app_state.user_id.clear();
                            app_state.password.clear();
                            app_state.url.clear();
                            app_state.input_mode = InputMode::Command;
                        }
                    }
                    KeyCode::Enter => {
                        match app_state.input_mode {
                            InputMode::Command => {}
                            InputMode::Delete => {
                                let title = app_state.input.clone();
                                let title_hash =
                                    crypto::hash(crypto::HashInputType::Text(title.clone()));

                                if let Ok(_) = send(&mut stream, 5, &title_hash[0..32]).await {
                                    let _ = update_password_list(&mut stream, &mut app_state).await;
                                }
                                app_state.input.clear();
                                app_state.input_mode = InputMode::Command;
                            }
                            InputMode::Title => {
                                app_state.title = app_state.input.clone();
                                app_state.input.clear();
                                app_state.input_mode = InputMode::UserId;
                            }
                            InputMode::UserId => {
                                app_state.user_id = app_state.input.clone();
                                app_state.input.clear();
                                // Go to the generate password prompt instead of directly to password input
                                app_state.input_mode = InputMode::GeneratePasswordPrompt;
                            }
                            InputMode::GeneratePasswordPrompt => {
                                if app_state.input.to_lowercase() == "y" {
                                    // User wants to generate a password, ask for length
                                    app_state.input.clear();
                                    app_state.input_mode = InputMode::PasswordLengthPrompt;
                                } else if app_state.input.to_lowercase() == "n" {
                                    // User wants to enter password manually
                                    app_state.input.clear();
                                    app_state.input_mode = InputMode::Password;
                                } else {
                                    // Invalid input, clear and stay in the same mode
                                    app_state.input.clear();
                                }
                            }
                            InputMode::Password => {
                                app_state.password = app_state.input.clone();
                                app_state.input.clear();
                                app_state.input_mode = InputMode::Url;
                            }
                            InputMode::PasswordLengthPrompt => {
                                // Parse the length input
                                if let Ok(length) = app_state.input.parse::<usize>() {
                                    if length > 0 {
                                        // Generate a password with the specified length
                                        let generated_password = crypto::generate_password(length);
                                        app_state.password = generated_password;
                                        app_state.input.clear();
                                        app_state.input_mode = InputMode::Url;
                                    } else {
                                        // Invalid length, clear and stay in the same mode
                                        app_state.input.clear();
                                    }
                                } else {
                                    // Invalid input, clear and stay in the same mode
                                    app_state.input.clear();
                                }
                            }
                            InputMode::Url => {
                                app_state.url = app_state.input.clone();
                                if let Ok(json) = wrap_password(
                                    app_state.title.clone(),
                                    app_state.user_id.clone(),
                                    app_state.password.clone(),
                                    app_state.url.clone(),
                                ) {
                                    if let Ok(_) = send(&mut stream, 1, &json).await {
                                        let _ =
                                            update_password_list(&mut stream, &mut app_state).await;
                                    }
                                }
                                app_state.input.clear();
                                app_state.title.clear();
                                app_state.user_id.clear();
                                app_state.password.clear();
                                app_state.url.clear();
                                app_state.input_mode = InputMode::Command;
                            }
                            InputMode::Help => {
                                app_state.input_mode = InputMode::Command;
                            }
                            InputMode::Get => {
                                let title = app_state.input.clone();
                                let title_hash = crypto::hash(crypto::HashInputType::Text(title));

                                // Send get request (type 2) with the title hash
                                if let Ok(_) = send(&mut stream, 2, &title_hash).await {
                                    if let Ok((response_type, data)) = receive(&mut stream).await {
                                        if response_type == 2 {
                                            if let Ok(pw_info) =
                                                serde_json::from_slice::<PasswordInfo>(&data)
                                            {
                                                app_state.current_password = Some(pw_info);
                                            }
                                        }
                                    }
                                }
                                app_state.input.clear();
                                app_state.input_mode = InputMode::Command;
                            }
                        }
                    }
                    KeyCode::Char(c) => {
                        if app_state.input_mode == InputMode::Command {
                            if let Some(first_key) = app_state.waiting_for_second_key {
                                // Handle second key of combination
                                match (first_key, c) {
                                    ('c', 'p') => {
                                        if let Some(pw_info) = &app_state.current_password {
                                            let key = KEY.get().expect("Key not initialized");
                                            if let Ok(decrypted) = String::from_utf8(
                                                crypto::decrypt(pw_info.password.clone(), *key),
                                            ) {
                                                if let Ok(mut ctx) = ClipboardContext::new() {
                                                    let _ = ctx.set_contents(decrypted);
                                                }
                                            }
                                        }
                                    }
                                    ('c', 'u') => {
                                        if let Some(pw_info) = &app_state.current_password {
                                            let key = KEY.get().expect("Key not initialized");
                                            if let Ok(decrypted) = String::from_utf8(
                                                crypto::decrypt(pw_info.user_id.clone(), *key),
                                            ) {
                                                if let Ok(mut ctx) = ClipboardContext::new() {
                                                    let _ = ctx.set_contents(decrypted);
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                                app_state.waiting_for_second_key = None;
                            } else {
                                // Handle first key press
                                match c {
                                    'c' => {
                                        if app_state.current_password.is_some() {
                                            app_state.waiting_for_second_key = Some('c');
                                        }
                                    }
                                    's' => {
                                        if app_state.current_password.is_some() {
                                            app_state.show_password = !app_state.show_password;
                                        } else {
                                            app_state.input_mode = InputMode::Title;
                                        }
                                    }
                                    'n' => {
                                        if app_state.current_password.is_none() {
                                            let total_pages = if app_state.password_list.is_empty()
                                            {
                                                1
                                            } else {
                                                (app_state.password_list.len() - 1)
                                                    / app_state.items_per_page
                                                    + 1
                                            };
                                            if app_state.current_page + 1 < total_pages {
                                                app_state.current_page += 1;
                                            }
                                        }
                                    }
                                    'p' => {
                                        if app_state.current_password.is_none()
                                            && app_state.current_page > 0
                                        {
                                            app_state.current_page -= 1;
                                        }
                                    }
                                    'd' => {
                                        app_state.input_mode = InputMode::Delete;
                                    }
                                    'g' => {
                                        app_state.input_mode = InputMode::Get;
                                    }
                                    'f' => {
                                        let _ =
                                            update_password_list(&mut stream, &mut app_state).await;
                                    }
                                    'h' => {
                                        app_state.input_mode = InputMode::Help;
                                    }
                                    'q' => {
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        } else if app_state.input_mode == InputMode::Help {
                            app_state.input_mode = InputMode::Command;
                        } else {
                            app_state.input.push(c);
                        }
                    }
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
