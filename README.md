# PasswordManager
A client-server model password manager written in Rust. Uses Tokio for async server functions and RustCrypto for AES-GCM encryption, HMAC PBKDF, and SHA2 hashing. All data communicated between client and server is encrypted, with plaintext keys never stored in either client or server and must be entered into the client at time of use.

## Client
The client prompts for a master password at startup and uses PBKDF2 to derive an encryption key that is stored in a thread-safe OnceLock for the session. It communicates with the server over TCP to store and retrieve encrypted passwords. All sensitive data is encrypted using AES-GCM before transmission to the server.

### Components
The client consists of the following key functions:
- `key_derivation(password: String)` - Takes the user's master password and generates a 256-bit encryption key using PBKDF2.
- `encrypt(message: String, key: [u8; 32])` - Encrypts a string using AES-GCM with the session key, including the nonce in the output.
- `decrypt(ciphertext: Vec<u8>, key: [u8; 32])` - Decrypts AES-GCM encrypted data using the session key.
- `hash(input: HashInputType)` - Generates SHA-256 hash of either text or bytes.
- `generate_password(length: usize)` - Generates a random alphanumeric password of specified length.

The client provides a terminal user interface with the following features:
- Store new passwords (title, username, password, URL)
- Retrieve and display stored passwords
- Copy username/password to clipboard
- Delete stored passwords
- View list of stored passwords

## Server
The server uses RocksDB for persistent storage and handles encrypted password data without having access to the encryption key. It responds to client requests including storing, retrieving, listing, and deleting passwords.

### Components
The server implements the following operations:
- Store password (type 1): Stores full encrypted password information
- Get password (type 2): Retrieves specific password by title hash
- List passwords (type 3): Returns list of stored passwords with titles and URLs
- Delete password (type 5): Removes password entry by title hash

## Password Structure
Passwords are stored using two structures:

### PasswordInfo (Full Password Data)
```rust
struct PasswordInfo {
    title_hash: [u8; 32],    // SHA-256 hash of the title
    title: Vec<u8>,          // Encrypted title
    user_id: Vec<u8>,        // Encrypted username/email
    password: Vec<u8>,       // Encrypted password
    url: Vec<u8>,            // Encrypted URL
}
```

### ListItem (List Display Data)
```rust
struct ListItem {
    title_hash: [u8; 32],    // SHA-256 hash of the title
    title: Vec<u8>,          // Encrypted title
    url: Vec<u8>,            // Encrypted URL
}
```

All sensitive data is encrypted using AES-GCM before being sent to the server, ensuring the server never has access to plaintext credentials.
