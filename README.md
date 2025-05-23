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

### Shell Completion
You can generate shell completion scripts for your preferred shell (Bash, Zsh, Fish, PowerShell, etc.) to enable tab completion for `ssf_tool` commands and arguments.

1. **Generate the script:**
Run the `completion` subcommand followed by the name of your shell. The output is the completion script.

```bash
ssf_tool completion <your-shell-name>
```
Replace `your-shell-name` with your shell (e.g., `bash`, `zsh`, `fish`, `powershell`).

2. **Install the script:**
The installation method depends on your shell. You typically redirect the output of the generation command to a file in a specific directory that your shell loads completion scripts from.

- **For Bash:**
```bash
ssf_tool completion bash > ~/.local/share/bash-completion/completions/ssf_tool
# You might need to create the directory: mkdir -p ~/.local/share/bash-completion/completions/
# Then restart your terminal or source your bash profile (e.g., source ~/.bashrc)
```

- **For Zsh:**
```bash
ssf_tool completion zsh > ~/.zsh/completion/_ssf_tool
# You might need to create the directory: mkdir -p ~/.zsh/completion/
# Add the directory to your $fpath in ~/.zshrc (if not already there):
# fpath=(~/.zsh/completion $fpath)
# autoload -Uz compinit
# compinit
# Then restart your terminal or source ~/.zshrc
```

- **For Fish:**
```bash
ssf_tool completion fish > ~/.config/fish/completions/ssf_tool.fish
# Then restart your terminal
```

- **For PowerShell:**
```bash
ssf_tool completion powershell | Out-String | Invoke-Expression
# To make it permanent, add the above line to your PowerShell profile script.
```

Consult your shell's documentation for more advanced or system-wide installation methods.

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
