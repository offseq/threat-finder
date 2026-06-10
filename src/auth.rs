// API-key acquisition and storage for the first run.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
struct Config {
    #[serde(default)]
    api_key: String,
    /// Continuous-monitoring settings (host identity + prompt preference). Kept
    /// in its own table so an older config without it still loads.
    #[serde(default, skip_serializing_if = "Monitoring::is_default")]
    monitoring: Monitoring,
}

/// `[monitoring]` config table. `host_id` is a stable per-host UUID generated
/// once; `prompt` is the post-scan registration prompt mode.
#[derive(Serialize, Deserialize, Default)]
struct Monitoring {
    /// Stable host identity sent as `hostId`. Empty until first generated.
    #[serde(default)]
    host_id: String,
    /// Prompt mode: `ask` (default) | `never` | `always`. Empty == `ask`.
    #[serde(default)]
    prompt: String,
}

impl Monitoring {
    fn is_default(&self) -> bool {
        self.host_id.is_empty() && self.prompt.is_empty()
    }
}

/// Default prompt mode when none is persisted.
const DEFAULT_PROMPT_MODE: &str = "ask";

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
                // Preserve any existing [monitoring] section when (re)writing the key.
                let mut cfg = load_config().unwrap_or_default();
                cfg.api_key = key;
                match save_config(&cfg) {
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

// ── Monitoring config (host identity + prompt preference) ────────────────────

/// Return the stable per-host UUID, generating and persisting one on first use.
/// On a config save failure the freshly-generated id is still returned (so a
/// single run is consistent) — it just won't be stable across runs.
pub fn get_or_create_host_id() -> String {
    let mut cfg = load_config().unwrap_or_default();
    if !cfg.monitoring.host_id.is_empty() {
        return cfg.monitoring.host_id;
    }
    let id = uuid::Uuid::new_v4().to_string();
    cfg.monitoring.host_id = id.clone();
    let _ = save_config(&cfg);
    id
}

/// The post-scan registration prompt mode: `ask` (default) | `never` | `always`.
pub fn monitoring_prompt_mode() -> String {
    match load_config() {
        Some(cfg) if !cfg.monitoring.prompt.is_empty() => cfg.monitoring.prompt,
        _ => DEFAULT_PROMPT_MODE.to_string(),
    }
}

/// Persist the registration prompt mode (e.g. `"never"` after a user opts out).
/// Returns the IO result so callers can warn if it didn't stick.
pub fn set_monitoring_prompt_mode(mode: &str) -> io::Result<()> {
    let mut cfg = load_config().unwrap_or_default();
    cfg.monitoring.prompt = mode.to_string();
    save_config(&cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // config_path() is process-global; serialize the tests that mutate it and
    // point them at an isolated temp dir via $XDG_CONFIG_HOME / $HOME.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TempConfigHome {
        dir: PathBuf,
        prev_xdg: Option<std::ffi::OsString>,
        prev_home: Option<std::ffi::OsString>,
    }

    impl TempConfigHome {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("tf-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
            let prev_home = std::env::var_os("HOME");
            // dirs::config_dir() uses XDG_CONFIG_HOME on Linux and $HOME on macOS.
            std::env::set_var("XDG_CONFIG_HOME", &dir);
            std::env::set_var("HOME", &dir);
            TempConfigHome { dir, prev_xdg, prev_home }
        }
    }

    impl Drop for TempConfigHome {
        fn drop(&mut self) {
            match &self.prev_xdg {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match &self.prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn host_id_generates_persists_and_reloads() {
        let _g = ENV_LOCK.lock().unwrap();
        let _tmp = TempConfigHome::new();

        let id1 = get_or_create_host_id();
        assert_eq!(id1.len(), 36, "v4 UUID string");
        // A second call returns the SAME persisted id (stable across runs).
        let id2 = get_or_create_host_id();
        assert_eq!(id1, id2, "host id must be stable once generated");

        // And it is readable straight from the on-disk config.
        let cfg = load_config().expect("config persisted");
        assert_eq!(cfg.monitoring.host_id, id1);
    }

    #[test]
    fn prompt_mode_defaults_to_ask_and_round_trips() {
        let _g = ENV_LOCK.lock().unwrap();
        let _tmp = TempConfigHome::new();

        assert_eq!(monitoring_prompt_mode(), "ask", "default when unset");
        set_monitoring_prompt_mode("never").unwrap();
        assert_eq!(monitoring_prompt_mode(), "never");
        // Changing the mode must not clobber an existing host id.
        let id = get_or_create_host_id();
        set_monitoring_prompt_mode("always").unwrap();
        assert_eq!(monitoring_prompt_mode(), "always");
        assert_eq!(get_or_create_host_id(), id, "host id preserved across prompt writes");
    }
}
