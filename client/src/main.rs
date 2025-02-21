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

// Main client function that takes input and communicates with the server
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

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


    // Send request for password list
    stream.write_all(&vec![3u8]).await?;

    
    // Main application loop
    loop {
        terminal.draw(|frame| {
            let size = frame.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(
                    [
                        Constraint::Min(3),
                        Constraint::Length(3),
                    ]
                    .as_slice()
                )
                .split(size);

            // Main content
            let content = Paragraph::new("Password Manager")
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(content, chunks[0]);

            // Command input mini-buffer
            let input = Paragraph::new("Type commands here:")
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(input, chunks[1]);
        })?;

        // Handle input
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    // Cleanup
    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;

    Ok(())
}
