use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

// --- Constants ---
pub const KEY_LEN: usize = 32; // AES-256 requires a 32-byte key
pub const SALT_LEN: usize = 16; // Recommended salt length
pub const NONCE_LEN: usize = 12; // AES-GCM standard nonce length (96 bits)

/// Derives a cryptographic key from a password and a salt using Argon2.
///
/// # Arguments
/// * `password` - The user's password as a byte slice.
/// * `salt` - A unique, random salt as a byte slice.
/// * `key_length` - The desired length of the derived key in bytes (e.g., 32 for AES-256).
///
/// # Returns
/// A `Result` containing the derived key as a `Vec<u8>` on success,
/// * `key_length` - The desired length of the derived key in bytes (e.g
pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
    key_length: usize,
) -> Result<Vec<u8>> {
    let argon2 = Argon2::default();

    let mut derived_key = vec![0u8; key_length];

    argon2
        .hash_password_into(password, salt, &mut derived_key)
        .map_err(|e| anyhow::anyhow!("Argon2 derivation failed: {}", e))?;

    Ok(derived_key)
}

/// Generates a cryptographically secure random salt of the specified length.
///
/// # Arguments
/// * `length` - The desired length of the salt in bytes.
///
/// # Returns
/// A `Result` containing the random salt as a Vec<u8> on success,
/// or an error if random number generation fails.
pub fn generate_random_salt(length: usize) -> Result<Vec<u8>> {
    let mut salt_bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut salt_bytes);
    Ok(salt_bytes)
}

/// Encrypts a file using password-based AES-256-GCM.
///
/// Reads the input file, derives a key from the password and a random salt,
/// encrypts the content, and writes the salt, nonce, and ciphertext
/// (including GCM tag) to the output file.
///
/// The output file format is: [Salt (16 bytes)] [Nonce (12 bytes)] [Ciphertext + GCM Tag]
///
/// # Arguments
/// * `input_path` - Path to the file to encrypt.
/// * `output_path` - Path where the encrypted file will be written.
/// * `password` - The user's password as a byte slice.
///
/// # Returns
/// A `Result` indicating success or an error.
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    force: bool,
) -> Result<()> {
    if output_path.exists() && !force {
        return Err(anyhow!(
            "Output file already exists: {}. Use --force to overwrite.",
            output_path.display()
        ));
    }
    let input_file = File::open(input_path)
        .with_context(|| format!("Failed to open input file: {}", input_path.display()))?;
    let mut reader = BufReader::new(input_file);
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let salt = generate_random_salt(SALT_LEN)?;

    let derived_key = derive_key_from_password(password, &salt, KEY_LEN)?;

    // --- 3. Generate Nonce (IV) ---
    // AES-GCM requires a 12-byte nonce
    let nonce_length = NONCE_LEN;
    let mut nonce_bytes = vec![0u8; nonce_length];
    OsRng.fill_bytes(&mut nonce_bytes); // Generate random nonce

    // --- 4. Initialize AES-GCM Cipher ---
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    // --- 5. Encrypt the Plaintext ---cargo test

    // The `encrypt` method appends the GCM tag to the ciphertext
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {:?}", e))?; // Convert crypto error

    // --- 6. Write Salt, Nonce, and Ciphertext to Output File ---
    let output_file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;
    let mut writer = BufWriter::new(output_file);

    // Write Salt (16 bytes)
    writer.write_all(&salt).with_context(|| {
        format!(
            "Failed to write salt to output file: {}",
            output_path.display()
        )
    })?;

    // Write Nonce (12 bytes)
    writer.write_all(&nonce_bytes).with_context(|| {
        format!(
            "Failed to write nonce to output file: {}",
            output_path.display()
        )
    })?;

    // Write Ciphertext (includes GCM tag)
    writer.write_all(&ciphertext).with_context(|| {
        format!(
            "Failed to write ciphertext to output file: {}",
            output_path.display()
        )
    })?;

    // Ensure all buffered data is written to the underlying file and then to disk
    writer
        .flush()
        .with_context(|| format!("Failed to flush output file: {}", output_path.display()))?;

    Ok(()) // Indicate success
}

/// Decrypts a file
///
/// Reads the salt and nonce from the file header, re-derives the key
/// from the password and salt, decrypts the ciphertext, and verifies
/// the GCM authentication tag.
///
/// The input file format is expected to be: [Salt (16 bytes)] [Nonce (12 bytes)] [Ciphertext + GCM Tag]
///
/// # Arguments
/// * `input_path` - Path to the encrypted file to decrypt.
/// * `output_path` - Path where the decrypted file will be written.
/// * `password` - The user's password as a byte slice.
///
/// # Returns
/// A `Result` indicating success or an error. If decryption fails (wrong
/// password or tampered data), an error is returned and no output is written.
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    force: bool,
) -> Result<()> {
    if output_path.exists() && !force {
        return Err(anyhow!(
            "Output file already exists: {}. Use --force to overwrite.",
            output_path.display()
        ));
    }
    // --- 1. Open the encrypted input file ---
    let input_file = File::open(input_path).with_context(|| {
        format!(
            "Failed to open encrypted input file: {}",
            input_path.display()
        )
    })?;
    let mut reader = BufReader::new(input_file);

    // --- 2. Read Salt (16 bytes) ---
    let mut salt_bytes = vec![0u8; SALT_LEN];
    reader.read_exact(&mut salt_bytes)
        .with_context(|| format!("Failed to read salt from encrypted file: {}. File might be too short or corrupted.", input_path.display()))?;

    // --- 3. Read Nonce (12 bytes) from the buffer ---
    let mut nonce_bytes = vec![0u8; NONCE_LEN];
    reader.read_exact(&mut nonce_bytes)
        .with_context(|| format!("Failed to read nonce from encrypted file: {}. File might be too short or corrupted.", input_path.display()))?;

    // --- 4. Read Ciphertext + GCM Tag from the buffer ---
    // NOTE: This still reads the rest of the file into memory for the crypto step.
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext) // Read the rest from the buffer
        .with_context(|| format!("Failed to read ciphertext from encrypted file: {}", input_path.display()))?;


    // --- 5. Re-Derive Key from Password and Stored Salt ---
    let derived_key = derive_key_from_password(password, &salt_bytes, KEY_LEN)?;

    // --- 6. Initialize AES-GCM Cipher ---
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    // --- 7. Decrypt the Ciphertext and Verify Tag ---
    // The `decrypt` method automatically verifies the GCM tag.
    // If verification fails (wrong password or tampered data), it returns an error.
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Incorrect password or corrupted file."))?;

    // --- 8. Write the Plaintext to Output File ---
    let output_file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;

        let mut writer = BufWriter::new(output_file); 

        writer.write_all(&plaintext)
            .with_context(|| format!("Failed to write decrypted content to output file: {}", output_path.display()))?;
    
        writer.flush()
            .with_context(|| format!("Failed to flush output file: {}", output_path.display()))?; 
    Ok(()) // Indicate success
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Seek};

    use super::*;
    use anyhow::Result;
    use tempfile::tempdir; // Use anyhow::Result in tests as well

    #[test]
    fn test_derive_key() -> Result<()> {
        let password = b"mysecretpassword123";
        let salt = generate_random_salt(SALT_LEN)?;

        let derived_key = derive_key_from_password(password, &salt, KEY_LEN)?;

        assert_eq!(derived_key.len(), KEY_LEN);
        assert_eq!(salt.len(), SALT_LEN);

        Ok(())
    }

    #[test]
    fn test_derive_key_deterministic_with_same_salt() -> Result<()> {
        let password = b"anotherpassword";
        let fixed_salt = vec![1u8; SALT_LEN];

        let key_length = 16;

        let derived_key1 = derive_key_from_password(password, &fixed_salt, key_length)?;
        let derived_key2 = derive_key_from_password(password, &fixed_salt, key_length)?;

        assert_eq!(derived_key1, derived_key2);
        assert_eq!(derived_key1.len(), key_length);

        Ok(())
    }

    #[test]
    fn test_generate_random_salt() -> Result<()> {
        let salt1 = generate_random_salt(SALT_LEN)?;
        let salt2 = generate_random_salt(SALT_LEN)?;

        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), SALT_LEN);
        assert_eq!(salt2.len(), SALT_LEN);

        Ok(())
    }

    #[test]
    fn test_encrypt_file_basic() -> Result<()> {
        // Create a temporary directory for test files
        let dir = tempdir()?;
        let input_path = dir.path().join("test_input_encrypt.txt");
        let encrypted_path = dir.path().join("test_input_encrypt.txt.enc");
        let password = b"test_password_for_encrypt";
        let original_content = b"This is a short file to test encryption.";

        // Write original content to input file
        let mut input_file = File::create(&input_path)?;
        input_file.write_all(original_content)?;
        input_file.flush()?;

        // --- Encrypt the file ---
        encrypt_file(&input_path, &encrypted_path, password, false)?;

        // --- Verify the encrypted file exists and has the correct header size ---
        let encrypted_file_metadata = std::fs::metadata(&encrypted_path)
            .with_context(|| format!("Encrypted file not found: {}", encrypted_path.display()))?;

        let expected_min_size = SALT_LEN + NONCE_LEN + original_content.len() + 16; // Salt + Nonce + Plaintext + GCM Tag (16 bytes)
        let actual_size: u64 = encrypted_file_metadata.len();

        println!("Original content size: {}", original_content.len());
        println!(
            "Expected minimum encrypted file size (header + plaintext + tag): {}",
            expected_min_size
        );
        println!("Actual encrypted file size: {}", actual_size);

        // The encrypted size should be at least the size of the header plus the original content plus the tag.
        // It might be slightly larger due to file system overhead, but the header size is fixed.
        assert!(
            actual_size >= expected_min_size as u64,
            "Encrypted file is smaller than expected minimum size"
        );

        // Read the first 28 bytes (salt + nonce) to verify the header structure
        let mut encrypted_file_read = File::open(&encrypted_path)?;
        let mut header_buffer = [0u8; 28]; // 16 bytes salt + 12 bytes nonce
        encrypted_file_read.read_exact(&mut header_buffer)?;

        // We can't assert the header content is specific (it's random),
        // but successfully reading 28 bytes confirms the structure starts correctly.
        println!("Successfully read 28-byte header from encrypted file.");

        // tempdir will automatically clean up the directory and files when it goes out of scope
        Ok(())
    }

    #[test]
    fn test_decrypt_file_cycle() -> Result<()> {
        let dir = tempdir()?;
        let input_path = dir.path().join("test_input_cycle.txt");
        let encrypted_path = dir.path().join("test_input_cycle.txt.enc");
        let decrypted_path = dir.path().join("test_output_cycle.txt");
        let password = b"super_secret_cycle_password";
        let original_content = b"This content will be encrypted and then decrypted.";

        // 1. Write original content to input file
        let mut input_file = File::create(&input_path)?;
        input_file.write_all(original_content)?;
        input_file.flush()?;

        // 2. Encrypt the file
        println!("Test: Encrypting file for decryption test...");
        encrypt_file(&input_path, &encrypted_path, password, false)?;
        println!("Test: Encryption complete.");

        // Ensure the encrypted file exists
        assert!(encrypted_path.exists());

        // 3. Decrypt the encrypted file
        println!("Test: Decrypting file...");
        decrypt_file(&encrypted_path, &decrypted_path, password, false)?;
        println!("Test: Decryption complete.");

        // Ensure the decrypted file exists
        assert!(decrypted_path.exists());

        // 4. Read the decrypted content
        let mut decrypted_file = File::open(&decrypted_path)?;
        let mut decrypted_content = Vec::new();
        decrypted_file.read_to_end(&mut decrypted_content)?;

        // 5. Verify the decrypted content matches the original
        assert_eq!(original_content.to_vec(), decrypted_content);
        println!("Test: Decrypted content matches original content.");

        // tempdir cleans up files automatically
        Ok(())
    }

    #[test]
    fn test_decrypt_file_wrong_password() -> Result<()> {
        let dir = tempdir()?;
        let input_path = dir.path().join("test_input_wrong_pass.txt");
        let encrypted_path = dir.path().join("test_input_wrong_pass.txt.enc");
        let decrypted_path = dir.path().join("test_output_wrong_pass.txt");
        let correct_password = b"correct_password_for_test";
        let wrong_password = b"incorrect_password_for_test";
        let original_content = b"Content for wrong password test.";

        // 1. Write original content to input file
        let mut input_file = File::create(&input_path)?;
        input_file.write_all(original_content)?;
        input_file.flush()?;

        // 2. Encrypt the file with the correct password
        println!("Test: Encrypting file for wrong password test...");
        encrypt_file(&input_path, &encrypted_path, correct_password, false)?;
        println!("Test: Encryption complete.");

        // Ensure the encrypted file exists
        assert!(encrypted_path.exists());

        // 3. Attempt to decrypt with the WRONG password
        println!("Test: Attempting decryption with wrong password...");
        let decrypt_result = decrypt_file(&encrypted_path, &decrypted_path, wrong_password, false);

        // 4. Verify that decryption FAILED
        assert!(decrypt_result.is_err());
        println!("Test: Decryption with wrong password correctly failed.");

        // 5. Verify that the output file was NOT created or is empty
        // Check if the file exists, and if it does, check its size.
        if decrypted_path.exists() {
            let metadata = fs::metadata(&decrypted_path)?;
            assert_eq!(
                metadata.len(),
                0,
                "Output file should be empty on decryption failure"
            );
        }
        // If the file didn't exist, that's also correct.

        Ok(())
    }

    #[test]
    fn test_decrypt_file_tampered() -> Result<()> {
        let dir = tempdir()?;
        let input_path = dir.path().join("test_input_tamper.txt");
        let encrypted_path = dir.path().join("test_input_tamper.txt.enc");
        let decrypted_path = dir.path().join("test_output_tamper.txt");
        let password = b"password_for_tamper_test";
        let original_content = b"Content for tampering test.";

        // 1. Write original content to input file
        let mut input_file = File::create(&input_path)?;
        input_file.write_all(original_content)?;
        input_file.flush()?;

        // 2. Encrypt the file
        println!("Test: Encrypting file for tampering test...");
        encrypt_file(&input_path, &encrypted_path, password, false)?;
        println!("Test: Encryption complete.");

        // Ensure the encrypted file exists
        assert!(encrypted_path.exists());

        // 3. Tamper with the encrypted file (change a few bytes in the ciphertext)
        println!("Test: Tampering with the encrypted file...");
        let mut encrypted_file = fs::OpenOptions::new().write(true).open(&encrypted_path)?;
        // Seek past the header (salt + nonce = 28 bytes)
        encrypted_file.seek(std::io::SeekFrom::Start(28))?;
        // Write some different bytes - this will corrupt the ciphertext and break the GCM tag
        encrypted_file.write_all(b"TAMPERED")?;
        encrypted_file.flush()?;
        println!("Test: File tampered.");

        // 4. Attempt to decrypt the TAMPERED file with the CORRECT password
        println!("Test: Attempting decryption of tampered file...");
        let decrypt_result = decrypt_file(&encrypted_path, &decrypted_path, password, false);

        // 5. Verify that decryption FAILED due to integrity check
        assert!(decrypt_result.is_err());
        println!("Test: Decryption of tampered file correctly failed.");

        // 6. Verify that the output file was NOT created or is empty
        if decrypted_path.exists() {
            let metadata = fs::metadata(&decrypted_path)?;
            assert_eq!(
                metadata.len(),
                0,
                "Output file should be empty on decryption failure"
            );
        }

        Ok(())
    }
}
