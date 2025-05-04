# Simple Secure File (SSF) Tool
A command-line utility for encrypting and decrypting files using password-based authenticated encryption.

## Features
- Encrypts individual files using AES-256-GCM.
- Uses Argon2 for secure password-based key derivation with a random salt.
- Includes a random nonce for each encryption.
- Verifies data integrity and authenticity during decryption.
- Prevents accidental overwriting of output files (unless --force is used).
- Uses buffered I/O for better performance on larger files.

## Installation
To build and install the SSF tool, you need to have Rust and Cargo installed.

1. Clone the repository:
```bash
git clone git@github.com:LucasnDomingues/ssf_tool.git
cd ssf_tool
```

2. Build the release version:
```bash
cargo build --release
```
The executable will be located in the `target/release/` directory. You can copy it to a directory in your system's PATH to run it from anywhere.

**Linux/macOS**:
```bash
cp target/release/ssf_tool /usr/local/bin/
```
(You might need sudo)

**Windows**: Copy target\release\ssf_tool.exe to a directory in your PATH.

## Usage
The `ssf_tool` command has two subcommands: encrypt and decrypt.

### Encrypting a File
To encrypt a file, use the `encrypt` subcommand followed by the input and output file paths:

```bash
ssf_tool encrypt <input_file> <output_file>
```
You will be securely prompted to enter and confirm a password.

Example:
```bash
ssf_tool encrypt my_document.txt my_document.txt.enc
```

### Decrypting a File
To decrypt an encrypted file, use the `decrypt` subcommand followed by the encrypted input file path and the desired output file path:

```bash 
ssf_tool decrypt <encrypted_file> <output_file>
```
You will be securely prompted to enter the password used during encryption.

Example:
```bash 
ssf_tool decrypt my_document.txt.enc my_document_decrypted.txt
``` 

### Overwriting Files
By default, the tool will prevent overwriting an existing output file. To force overwriting, use the `--force` (or `-f`) flag:

```bash
ssf_tool encrypt my_document.txt my_document.txt.enc --force
ssf_tool decrypt my_document.txt.enc my_document_decrypted.txt -f
``` 

## Encrypted File Format
The encrypted file has a simple structure:

**Salt**: 16 bytes (used for key derivation)

**Nonce (IV)**: 12 bytes (used for AES-GCM)

**Ciphertext + GCM Tag**: Remaining bytes (encrypted data with authentication tag)

The total header size is 28 bytes.

## Security Considerations

- This tool uses standard, recommended cryptographic algorithms (Argon2, AES-256-GCM).
- **The security relies heavily on the strength of your password**. Choose a strong, unique password.
- The Argon2 parameters used are defaults; for maximum security, these could be tuned based on benchmarks of your target system.
- The tool does not include advanced features like secure deletion (shredding) of the original file after encryption.

## Tests

To run the tests:
```bash
cargo test
```
