use anyhow::{Result, bail};
use rpassword::read_password;
use std::io::{self, Write};

/// Prompts the user for a password securely without echoing input.
///
/// # Arguments
/// * `prompt` - The message to display to the user before prompting.
///
/// # Returns
/// A `Result` containing the entered password as a String on success,
/// or an error if reading fails.
pub fn prompt_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = read_password()?;
    Ok(password)
}

/// Prompts the user for a password twice to confirm, securely.
///
/// # Arguments
/// * `prompt` - The message to display for the first prompt.
/// * `confirm_prompt` - The message to display for the confirmation prompt.
///
/// # Returns
/// A `Result` containing the confirmed password as a String on success,
/// or an error if reading fails or passwords do not match.
pub fn prompt_password_and_confirm(prompt: &str, confirm_prompt: &str) -> Result<String> {
    let password = prompt_password(prompt)?;
    let confirmation = prompt_password(confirm_prompt)?;

    if password == confirmation {
        Ok(password)
    } else {
        bail!("Passwords do not match");
    }
}
