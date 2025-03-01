use clap::{Parser, Subcommand};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use serde_json::Value;
use colored::*;

/// A simple CLI tool for JWT transactions.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encode a new JWT token.
    Encode {
        /// Object or identifier for the token.
        #[arg(short, long)]
        object: String,

        /// Secret key to sign the token.
        #[arg(short, long)]
        secret: String,
    },
    /// Decode and verify an existing JWT token.
    Decode {
        /// The JWT token string.
        #[arg(short, long)]
        token: String,

        /// Secret key to verify the token.
        #[arg(short, long)]
        secret: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn print_colored_json(json: &Value) {
    if let Some(obj) = json.as_object() {
        println!("{}", "{".cyan());
        for (i, (key, value)) in obj.iter().enumerate() {
            let key_colored = format!("\"{}\"", key).yellow();
            let value_colored = match value {
                Value::String(s) => format!("\"{}\"", s).green(),
                Value::Number(n) => format!("{}", n).blue(),
                Value::Bool(b) => format!("{}", b).magenta(),
                Value::Null => "null".red(),
                _ => format!("{}", value).color("white"), // or any other color you prefer
            };

            let comma = if i < obj.len() - 1 { "," } else { "" };
            println!("  {}: {}{}", key_colored, value_colored, comma);
        }
        println!("{}", "}".cyan());
    }
}


fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encode { object, secret } => {
            // Set token expiration to 10 minutes from now.
            let expiration = Utc::now()
                .checked_add_signed(Duration::minutes(100))
                .expect("Failed to compute timestamp")
                .timestamp() as usize;

            let claims = Claims {
                sub: object.clone(),
                exp: expiration,
            };

            match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())) {
                Ok(token) => println!("Encoded JWT Token:\n{}", token),
                Err(err) => eprintln!("Error encoding token: {}", err),
            }
        },
        Commands::Decode { token, secret } => {
            let validation = Validation::default();
            match decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation) {
                Ok(token_data) => {
                    let json_value = serde_json::to_value(&token_data.claims).unwrap();
                    print_colored_json(&json_value);
                },
                Err(err) => eprintln!("{}", format!("Error decoding token: {}", err).red()),
            }
        },
    }
}
