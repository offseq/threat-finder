// API-key acquisition and storage for the first run.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
struct Config {
    api_key: String,
}

/// Environment variable checked before any saved config — lets the tool run
/// non-interactively in CI/cron without a config file.
const ENV_KEY: &str = "OFFSEQ_API_KEY";

/// Resolve an API key from, in order: the OFFSEQ_API_KEY env var, the saved
/// config (unless `reset`), then interactive setup (only if `interactive`).
/// Returns None when no key can be obtained without prompting.
pub fn resolve_api_key(reset: bool, interactive: bool) -> Option<String> {
    if let Ok(k) = std::env::var(ENV_KEY) {
        let k = k.trim().to_string();
        if !k.is_empty() {
            return Some(k);
        }
    }

    if !reset {
        if let Some(cfg) = load_config() {
            if !cfg.api_key.is_empty() {
                return Some(cfg.api_key);
            }
        }
    }

    if interactive {
        run_initial_setup();
        return load_config().map(|c| c.api_key).filter(|k| !k.is_empty());
    }

    None
}

fn config_path() -> PathBuf {
    let base = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("offseq-rust").join("config.toml")
}

fn load_config() -> Option<Config> {
    let path = config_path();
    if !path.exists() {
        return None;
    }
    let contents = fs::read_to_string(&path).ok()?;
    toml::from_str(&contents).ok()
}

fn save_config(cfg: &Config) -> io::Result<()> {
    let path = config_path();

    // Create the config directory private (0700) so the key file is never
    // briefly exposed in a world-traversable parent.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let toml_str = toml::to_string(cfg).map_err(io::Error::other)?;

    // Create the file with 0600 from the start (no chmod-after-write TOCTOU
    // window), then re-assert 0600 in case it already existed.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    f.write_all(toml_str.as_bytes())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn run_initial_setup() {
    println!("\n┌─────────────────────────────────────────────────┐");
    println!("│           OffSeq Threat Finder - Setup          │");
    println!("└─────────────────────────────────────────────────┘\n");
    println!("No API key found. You need an OffSeq API key to continue.\n");

    loop {
        println!("  [1]  I already have my API key");
        println!("  [2]  I need to get my API key\n");
        print!("Select an option: ");
        let _ = io::stdout().flush();

        let choice = match read_line() {
            Some(c) => c,
            None => {
                // EOF (e.g. piped/closed stdin) — abort instead of looping forever.
                eprintln!("\nNo input received; aborting setup.");
                return;
            }
        };

        match choice.trim() {
            "1" => {
                let key = prompt_for_key();
                match save_config(&Config { api_key: key }) {
                    Ok(_) => {
                        println!("\n✓  API key saved successfully.\n");
                        return;
                    }
                    Err(e) => {
                        eprintln!("\n[!] Failed to save config: {e}\n");
                        // Loop back so the user can retry.
                    }
                }
            }
            "2" => {
                println!("\nYour API key is available at:");
                println!("  https://radar.offseq.com/console\n");
                println!("Once you have your key, select option 1 to continue.\n");
            }
            _ => {
                println!("\nInvalid choice, please enter 1 or 2.\n");
            }
        }
    }
}

fn prompt_for_key() -> String {
    loop {
        // Read the key with echo disabled so it isn't left on screen/scrollback.
        let key = rpassword::prompt_password("\nPaste your API key (input hidden): ")
            .unwrap_or_default();
        let key = key.trim().to_string();

        if key.is_empty() {
            println!("API key cannot be empty, please try again.");
            continue;
        }

        if key.len() < 48 {
            println!("That doesn't look like a valid API key (too short). Please try again.");
            continue;
        }

        return key;
    }
}

/// Message shown on a 429 quota-exhaustion response.
pub fn prompt_upgrade() {
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│            Rate Limit Reached               │");
    println!("└─────────────────────────────────────────────┘\n");
    println!("You have exhausted the API calls available on your current plan.");
    println!("To continue using OffSeq, upgrade your plan at:\n");
    println!("  https://radar.offseq.com/pricing\n");
}

/// Read a line from stdin. Returns None on EOF so callers don't spin forever.
fn read_line() -> Option<String> {
    let mut buf = String::new();
    match io::stdin().read_line(&mut buf) {
        Ok(0) => None,
        Ok(_) => Some(buf),
        Err(_) => None,
    }
}
