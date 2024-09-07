# PasswordManager
A client-server model password manager written in rust. Uses Tokio for aync server functions and RustCrypto for AES-GCM encryption, HMAC PBKDF and SHA2 hashing. All data communicated between client and server is either hashed or encrypted, plaintext keys are not stored in either client or server and must be entered into the client at time of use.


## Client
The client takes in a password and uses the PBKDF to create a key that is stored for the session. It requests passwords form the server over HTTPS and then decrypts them with the key. It also encrypts new passwords and sends the ciphertext to the server for storage. The client impliments Known Answer Tests (KATs) on the crytpogrphic functions used

### Components
The client is made up of the following:
- get_key() - requests a password fromn the user and uses it to generate the encryption key type [u8,32] used for this session. The key is stored in OnceLock.
- encrypt(string) - Takes a string as a message and uses the stored key the generate ciphertext of the message. Raises an error if no key is stored.
- decrypt(vec<u8>) - Takes a vec<u8> as ciphertext and decrypts it and returns the plaintext message. Creates error is there is no key stored.
- hash(String) - Returns the hash of the input string.
- generate_password(length: u8, excludeChars: Vec<char>, useWords: bool, charMapping: bool)  - Generates a random password of the given length. Excludes specific chars if they are not accepted in the service processing the password. The last flag determines if the password should be words or characters. If the password is in words a mapping of chars can be randomly generated to increase complexity in a way that is still readable, for instance "s -> $" or "o -> 0".


## Server
The server has no access to cryptogrphic functions, it is simply a file server that takes HTTPS requests and returns the appropriate file. The file can be identified as the right password according to a hash of either the title name for the password or the hash of an associated website.

### Components




## Password structure
The files key components are:
- Title - an identifier
- Website - website with the account, having this helps avoid the problem of forgetting what title you set. This can be set to N/A
- User ID - the username or email or phone number associated as the user ID
- Password - self explainatory
- Additional Fields - a field name and content

Strings containing this are strucutred as follows:
```
title-hash:<hash(Title)>::website-hash:<hash(Website)>::title:<encrypt(Title)>::website:<encrypt(Website)>::user-id:<encrypt(User ID)>::password:<encrypt(Password)
```

All additional fields are added at the end in the same format.