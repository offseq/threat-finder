//! The base side of a `--base-ref` diff, read with git, as Radar's GitHub App
//! reads a pull request: files at the merge base, `.github/radar.yml` at the base.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const CONFIG_PATH: &str = ".github/radar.yml";

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C").arg(dir)
        .arg("--literal-pathspecs")
        .args(args)
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git {} failed: {}", args.first().unwrap_or(&""), err.trim()));
    }
    String::from_utf8(out.stdout).map_err(|_| format!("git {} printed non-UTF-8 output", args.first().unwrap_or(&"")))
}

pub struct BaseRef {
    root: PathBuf,
    /// The ref's commit: radar.yml is read here, so a change cannot loosen its own gate.
    base: String,
    /// Where files are compared: the merge base with HEAD, or `base` without one.
    merge_base: String,
    /// No merge base was found (a shallow clone), so files are compared with `base`.
    pub no_merge_base: bool,
}

impl BaseRef {
    /// Resolve `reference` in the repository containing `dir`.
    pub fn open(dir: &Path, reference: &str) -> Result<Self, String> {
        if reference.is_empty() || reference.starts_with('-') {
            return Err(format!("'{reference}' is not a git ref"));
        }
        let root = PathBuf::from(git(dir, &["rev-parse", "--show-toplevel"])?.trim());
        let base = git(&root, &["rev-parse", "--verify", "--quiet", &format!("{reference}^{{commit}}")])
            .map_err(|_| format!("'{reference}' is not a commit in this repository (fetch it first)"))?
            .trim()
            .to_string();
        let merge_base = git(&root, &["merge-base", &base, "HEAD"]).map(|s| s.trim().to_string()).ok();
        Ok(BaseRef {
            root,
            no_merge_base: merge_base.is_none(),
            merge_base: merge_base.unwrap_or_else(|| base.clone()),
            base,
        })
    }

    /// `path` relative to the repository root, `/`-separated.
    pub fn repo_path(&self, path: &Path) -> Result<String, String> {
        let canonical = |p: &Path| p.canonicalize().map_err(|e| format!("{}: {e}", p.display()));
        let full = canonical(path)?;
        let rel = full.strip_prefix(canonical(&self.root)?)
            .map_err(|_| format!("{} is outside the git repository", path.display()))?;
        Ok(rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/"))
    }

    /// The file at the merge base, or `None` when it did not exist there.
    pub fn file(&self, rel: &str) -> Result<Option<String>, String> {
        self.show(&self.merge_base, rel)
    }

    /// `.github/radar.yml` at the base, when it exists.
    pub fn config(&self) -> Result<Option<String>, String> {
        self.show(&self.base, CONFIG_PATH)
    }

    fn show(&self, commit: &str, rel: &str) -> Result<Option<String>, String> {
        if git(&self.root, &["ls-tree", "--name-only", commit, "--", rel])?.trim().is_empty() {
            return Ok(None);
        }
        git(&self.root, &["show", &format!("{commit}:{rel}")]).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_files_at_the_merge_base_and_config_at_the_base() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("threat-finder-git-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join(".github")).unwrap();
        std::fs::create_dir_all(dir.join("app")).unwrap();
        let run = |args: &[&str]| git(&dir, &[&["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"], args].concat()).unwrap();
        run(&["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("app/package-lock.json"), "{\"v\":1}").unwrap();
        std::fs::write(dir.join(CONFIG_PATH), "failOn: high\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-qm", "base"]);
        run(&["checkout", "-qb", "change"]);
        std::fs::write(dir.join("app/package-lock.json"), "{\"v\":2}").unwrap();
        std::fs::write(dir.join("Cargo.lock"), "x").unwrap();
        std::fs::write(dir.join(CONFIG_PATH), "failOn: low\n").unwrap();
        run(&["commit", "-qam", "change"]);

        let base = BaseRef::open(&dir.join("app"), "main").unwrap();
        assert!(!base.no_merge_base);
        let rel = base.repo_path(&dir.join("app/package-lock.json")).unwrap();
        assert_eq!(rel, "app/package-lock.json");
        assert_eq!(base.file(&rel).unwrap().as_deref(), Some("{\"v\":1}"));
        assert_eq!(base.file("Cargo.lock").unwrap(), None);
        assert_eq!(base.config().unwrap().as_deref(), Some("failOn: high\n"));
        assert!(BaseRef::open(&dir, "no-such-ref").is_err());
        assert!(BaseRef::open(&dir, "--output=x").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
