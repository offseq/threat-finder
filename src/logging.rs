//! Runtime diagnostics written to a daily-rotated log file, independent of the
//! CLI's own stdout/stderr output.
//!
//! Location: `dirs::data_local_dir()/threat-finder/logs/threat-finder.YYYY-MM-DD.log`
//! (`~/.local/share` on Linux, `~/Library/Application Support` on macOS,
//! `%LOCALAPPDATA%` on Windows). The newest [`KEEP_LOG_FILES`] files are kept.
//!
//! Level defaults to `info` (`debug` with `--verbose`); `RUST_LOG` overrides both.

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;

const KEEP_LOG_FILES: usize = 14;

/// Install the file logger. The returned guard flushes on drop, so keep it alive
/// for the whole run. `None` (logging off, scan unaffected) when no writable log
/// directory exists; that is only reported under `--verbose`.
pub fn init(verbose: bool) -> Option<WorkerGuard> {
    let dir = dirs::data_local_dir()?.join("threat-finder").join("logs");
    // The appender prunes old files at build time and complains about a missing dir.
    let appender = std::fs::create_dir_all(&dir).map_err(|e| e.to_string()).and_then(|()| {
        RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("threat-finder")
            .filename_suffix("log")
            .max_log_files(KEEP_LOG_FILES)
            .build(&dir)
            .map_err(|e| e.to_string())
    });
    let appender = match appender {
        Ok(a) => a,
        Err(e) => {
            if verbose {
                eprintln!("[!] File logging disabled ({}): {e}", dir.display());
            }
            return None;
        }
    };
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if verbose { "debug" } else { "info" }));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .with_line_number(true)
        .try_init()
        .ok()?;

    tracing::info!(version = env!("CARGO_PKG_VERSION"), log_dir = %dir.display(), "threat-finder starting");
    Some(guard)
}
