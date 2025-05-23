mod crypto;
mod password;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::{io, path::PathBuf};
use clap_complete::{generate, Shell};

/// Simple Secure File (SSF) Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypts a file
    Encrypt {
        /// Input file path
        #[arg(help = "Path to the file to encrypt")]
        input_path: PathBuf,

        /// Output file path
        #[arg(help = "Path where the encrypted file will be written")]
        output_path: PathBuf,

        /// Overwrite output file if it already exists
        #[arg(short, long, help = "Overwrite output file if it already exists")]
        force: bool, // Add the force flag here
    },
    /// Decrypts a file
    Decrypt {
        /// Input encrypted file path
        #[arg(help = "Path to the encrypted file")]
        input_path: PathBuf,

        /// Output decrypted file path
        #[arg(help = "Path where the decrypted file will be written")]
        output_path: PathBuf,

        /// Overwrite output file if it already exists
        #[arg(short, long, help = "Overwrite output file if it already exists")]
        force: bool, // Add the force flag here
    },
        /// Generate shell completion scripts
        #[command(hide = true)]
        Completion {
            /// The shell to generate completion for
            #[arg(value_enum)]
            shell: Shell,
        },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt {
            input_path,
            output_path,
            force,
        } => {
            let password =
                password::prompt_password_and_confirm("Enter password: ", "Confirm password: ")?;
            let password_bytes = password.as_bytes();

            println!("Starting encryption...");
            crypto::encrypt_file(input_path, output_path, password_bytes, *force)?;
            println!("Encryption successful!");
        }
        Commands::Decrypt {
            input_path,
            output_path,
            force,
        } => {
            let password = password::prompt_password("Enter password: ")?;
            let password_bytes = password.as_bytes();

            println!("Starting decryption...");
            crypto::decrypt_file(input_path, output_path, password_bytes, *force)?;
            println!("Decryption successful!");
        }
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(*shell, &mut cmd, name, &mut io::stdout());
        }
    }

    Ok(())
}
