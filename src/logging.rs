//! Runtime logging: writes timestamped diagnostics to a rotating log file so
//! failures can be debugged after the fact, independent of whatever the CLI
//! already prints to stdout/stderr for the user.
//!
//! Log location:
//!   - Linux:   ~/.local/share/threat-finder/logs/threat-finder.log.YYYY-MM-DD
//!   - macOS:   ~/Library/Application Support/threat-finder/logs/threat-finder.log.YYYY-MM-DD
//!   - Windows: %LOCALAPPDATA%\threat-finder\logs\threat-finder.log.YYYY-MM-DD
//!   (resolved via `dirs::data_local_dir()`, the same crate already used
//!   elsewhere in this project for locating config.)
//!
//! Level:
//!   - Defaults to `info`. Override with `RUST_LOG` (e.g. `RUST_LOG=debug`,
//!     or `RUST_LOG=find_threats=debug` to scope it to this crate).
//!   - `--verbose` bumps the default to `debug` when `RUST_LOG` isn't set.

use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Initializes the file logger. Returns a guard that MUST be kept alive for
/// the lifetime of the process — dropping it stops the background thread
/// that flushes log lines to disk, silently truncating the log. Bind the
/// return value to a variable in `main()` (e.g. `let _log_guard = ...;`)
/// rather than discarding it.
///
/// Returns `None` if a log directory couldn't be determined or created; the
/// scanner should still run normally in that case, just without file
/// logging, so this never panics or forces an early return.
pub fn init(verbose: bool) -> Option<WorkerGuard> {
    let log_dir = match log_dir() {
        Some(d) => d,
        None => {
            eprintln!("[!] Could not determine a log directory; file logging disabled.");
            return None;
        }
    };

    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!(
            "[!] Could not create log directory '{}': {e}; file logging disabled.",
            log_dir.display()
        );
        return None;
    }

    let file_appender = tracing_appender::rolling::daily(&log_dir, "threat-finder.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let default_level = if verbose { "debug" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_line_number(true)
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        log_dir = %log_dir.display(),
        "threat-finder starting"
    );

    Some(guard)
}

fn log_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("threat-finder").join("logs"))
}
