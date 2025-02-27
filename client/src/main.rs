#![allow(dead_code)]

use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
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

// Send data to the server
async fn send(stream: &mut TcpStream, request_type: u8, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut request = vec![request_type];
    request.extend_from_slice(data);
    
    stream.write_all(&request).await?;
    Ok(())
}

struct AppState {
    input: String,
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
    };

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

            // Main content
            let content = Paragraph::new("Password Manager")
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(content, chunks[0]);

            // Command input mini-buffer
            let input = Paragraph::new(app_state.input.as_str())
                .block(Block::default().borders(Borders::ALL).title("Enter command:"));
            frame.render_widget(input, chunks[1]);
        })?;

        // Handle input
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Enter => {
                        // Handle command
                        app_state.input.clear();
                    }
                    KeyCode::Char(c) => {
                        app_state.input.push(c);
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
