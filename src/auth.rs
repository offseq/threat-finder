// API-key acquisition and storage for the first run.

use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Once;

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

/// Overrides the base directory for the config file. Useful for CI/containers
/// (and tests) that need a deterministic, isolated config location independent
/// of the OS's per-user directory resolution.
const CONFIG_DIR_ENV: &str = "OFFSEQ_CONFIG_DIR";

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
        if let Some(k) = saved_api_key() {
            return Some(k);
        }
    }

    if interactive {
        run_initial_setup();
        return saved_api_key();
    }

    None
}

fn saved_api_key() -> Option<String> {
    Some(load_config().api_key.trim().to_string()).filter(|k| !k.is_empty())
}

fn config_path() -> PathBuf {
    // An explicit override wins, so the config location is deterministic
    // regardless of platform directory resolution (env-honoring vs. OS Known
    // Folders API). Falls back to the per-user config dir.
    let base = std::env::var_os(CONFIG_DIR_ENV)
        .map(PathBuf::from)
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("offseq-rust").join("config.toml")
}

/// The saved config; a missing file is the default, an unreadable or unparsable
/// one is an error so callers never overwrite (and erase) it.
fn read_config() -> io::Result<Config> {
    let path = config_path();
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
    };
    toml::from_str(&contents)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))
}

/// Read-only view of the config: an unreadable file is warned about (once) and
/// treated as empty.
fn load_config() -> Config {
    static WARN: Once = Once::new();
    read_config().unwrap_or_else(|e| {
        WARN.call_once(|| eprintln!("[!] Ignoring unreadable config {e}"));
        Config::default()
    })
}

/// Read-modify-write that refuses to touch a config it can't parse.
fn update_config(f: impl FnOnce(&mut Config)) -> io::Result<()> {
    let mut cfg = read_config()?;
    f(&mut cfg);
    save_config(&cfg)
}

/// Atomic, owner-private write: a fresh 0600 temp file is fsynced, then renamed
/// over the target, so a crash never leaves a truncated config.
fn save_config(cfg: &Config) -> io::Result<()> {
    let path = config_path();
    let dir = path.parent().expect("config path has a parent");
    create_private_dir(dir)?;

    let toml_str = toml::to_string(cfg).map_err(io::Error::other)?;
    let tmp = dir.join(format!(".config.toml.{}.tmp", uuid::Uuid::new_v4()));
    let res = (|| {
        let mut f = create_private(&tmp)?;
        f.write_all(toml_str.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, &path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

// %APPDATA% is already ACL'd to the user.
#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    // Tighten a pre-existing directory too.
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
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
                let Some(key) = prompt_for_key() else {
                    eprintln!("\nCouldn't read the API key; aborting setup.");
                    return;
                };
                // Preserve any existing [monitoring] section when (re)writing the key.
                let mut cfg = match read_config() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("\n[!] Not overwriting unreadable config {e}\nFix or remove it, then retry.\n");
                        return;
                    }
                };
                cfg.api_key = key;
                match save_config(&cfg) {
                    Ok(()) => {
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
                println!("\nAPI access is included on every plan, including Free. Your key is at:");
                println!("  https://radar.offseq.com/console\n");
                println!("Once you have your key, select option 1 to continue.\n");
            }
            _ => {
                println!("\nInvalid choice, please enter 1 or 2.\n");
            }
        }
    }
}

/// None when the terminal can't be read (retrying would spin forever).
fn prompt_for_key() -> Option<String> {
    loop {
        // Read the key with echo disabled so it isn't left on screen/scrollback.
        let key = rpassword::prompt_password("\nPaste your API key (input hidden): ").ok()?;
        let key = key.trim().to_string();

        if key.is_empty() {
            println!("API key cannot be empty, please try again.");
            continue;
        }

        if key.len() < 48 {
            println!("That doesn't look like a valid API key (too short). Please try again.");
            continue;
        }

        return Some(key);
    }
}

/// Message shown on a 429 quota-exhaustion response. `detail`, when present, is
/// the server's own message — it distinguishes an hourly burst from a daily or
/// monthly quota and carries the reset time, so we surface it verbatim above the
/// generic upgrade line rather than guessing.
/// Printed to stderr so it can't corrupt JSON written to stdout.
pub fn prompt_upgrade(detail: Option<&str>) {
    eprintln!("\n┌─────────────────────────────────────────────┐");
    eprintln!("│            Rate Limit Reached               │");
    eprintln!("└─────────────────────────────────────────────┘\n");
    eprintln!("{}\n", upgrade_body_line(detail));
    eprintln!("Upgrade your plan for higher limits:");
    eprintln!("  https://radar.offseq.com/console?tab=billing\n");
    eprintln!("Compare plans: https://radar.offseq.com/pricing\n");
}

/// The explanatory line shown by [`prompt_upgrade`]: the server's own message
/// when it provided a non-empty one (it distinguishes hourly/daily/monthly limits
/// and carries the reset time), otherwise a generic fallback.
fn upgrade_body_line(detail: Option<&str>) -> &str {
    match detail.map(str::trim).filter(|d| !d.is_empty()) {
        Some(d) => d,
        None => "You have exhausted the API calls available on your current plan.",
    }
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

/// Return the saved per-host UUID WITHOUT creating or persisting one. `None`
/// means this machine has never registered (no id on disk yet). Use this for
/// read-only paths like `--unregister` that must not mint a fresh id as a side
/// effect; use `get_or_create_host_id()` only when actually registering.
pub fn host_id() -> Option<String> {
    Some(load_config().monitoring.host_id).filter(|id| !id.is_empty())
}

/// Return the stable per-host UUID, generating and persisting one on first use.
/// On a save failure the fresh id is still returned (one run stays consistent),
/// with a warning that it won't be stable across runs.
pub fn get_or_create_host_id() -> String {
    if let Some(id) = host_id() {
        return id;
    }
    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = update_config(|c| c.monitoring.host_id = id.clone()) {
        eprintln!(
            "[!] Couldn't save host id to {}: {e}; registration will create a new Radar host each run",
            config_path().display()
        );
    }
    id
}

/// The post-scan registration prompt mode: `ask` (default) | `never` | `always`.
pub fn monitoring_prompt_mode() -> String {
    Some(load_config().monitoring.prompt)
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| DEFAULT_PROMPT_MODE.to_string())
}

/// Persist the registration prompt mode (e.g. `"never"` after a user opts out).
/// Returns the IO result so callers can warn if it didn't stick.
pub fn set_monitoring_prompt_mode(mode: &str) -> io::Result<()> {
    update_config(|c| c.monitoring.prompt = mode.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn upgrade_body_prefers_server_detail() {
        // The server's message (hourly vs monthly + reset time) passes through.
        assert_eq!(
            upgrade_body_line(Some("Hourly rate limit reached. Resets at 14:00 UTC. Upgrade your plan for higher limits.")),
            "Hourly rate limit reached. Resets at 14:00 UTC. Upgrade your plan for higher limits."
        );
        // Surrounding whitespace is trimmed.
        assert_eq!(upgrade_body_line(Some("  Monthly quota used.  ")), "Monthly quota used.");
        // No detail (or blank) → generic fallback, never an empty line.
        assert_eq!(
            upgrade_body_line(None),
            "You have exhausted the API calls available on your current plan."
        );
        assert_eq!(
            upgrade_body_line(Some("   ")),
            "You have exhausted the API calls available on your current plan."
        );
    }

    // config_path() is process-global; serialize the tests that mutate it and
    // point them at an isolated temp dir via $XDG_CONFIG_HOME / $HOME.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TempConfigHome {
        dir: PathBuf,
        prev: Option<std::ffi::OsString>,
    }

    impl TempConfigHome {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("tf-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            // The explicit override makes config_path() deterministic on every
            // platform (dirs 6 reads the Windows Known Folders API directly, so
            // redirecting %APPDATA% no longer works there).
            let prev = std::env::var_os(CONFIG_DIR_ENV);
            std::env::set_var(CONFIG_DIR_ENV, &dir);
            TempConfigHome { dir, prev }
        }
    }

    impl Drop for TempConfigHome {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(CONFIG_DIR_ENV, v),
                None => std::env::remove_var(CONFIG_DIR_ENV),
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
        assert_eq!(read_config().unwrap().monitoring.host_id, id1);
    }

    #[test]
    fn host_id_read_only_returns_none_without_persisting() {
        let _g = ENV_LOCK.lock().unwrap();
        let _tmp = TempConfigHome::new();

        // Nothing registered yet: the read-only accessor reports None …
        assert_eq!(host_id(), None, "unset host id reads back as None");
        // … and must NOT have written a config (no side-effect persistence).
        assert!(!config_path().exists(), "host_id() must not create a config");

        // Once a real id is minted, the read-only accessor returns it verbatim.
        let id = get_or_create_host_id();
        assert_eq!(host_id().as_deref(), Some(id.as_str()));
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

    #[test]
    fn corrupt_config_is_not_overwritten() {
        let _g = ENV_LOCK.lock().unwrap();
        let _tmp = TempConfigHome::new();

        let path = config_path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let corrupt = "api_key = \"k\"\n[monitoring\n";
        fs::write(&path, corrupt).unwrap();

        assert!(read_config().is_err());
        assert!(set_monitoring_prompt_mode("never").is_err());
        get_or_create_host_id();
        assert_eq!(fs::read_to_string(&path).unwrap(), corrupt, "config left untouched");
    }

    #[test]
    fn saved_api_key_is_trimmed() {
        let _g = ENV_LOCK.lock().unwrap();
        let _tmp = TempConfigHome::new();

        assert_eq!(saved_api_key(), None);
        update_config(|c| c.api_key = "  key\n".into()).unwrap();
        assert_eq!(saved_api_key().as_deref(), Some("key"));
        update_config(|c| c.api_key = "   ".into()).unwrap();
        assert_eq!(saved_api_key(), None);
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_owner_private() {
        let _g = ENV_LOCK.lock().unwrap();
        let _tmp = TempConfigHome::new();

        let path = config_path();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        update_config(|c| c.api_key = "secret".into()).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(dir), 0o700);
        assert_eq!(fs::read_dir(dir).unwrap().count(), 1, "no temp file left behind");
    }
}
