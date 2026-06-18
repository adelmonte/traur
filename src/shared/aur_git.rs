//! Read helpers for a *local* AUR package repo (the working directory an AUR
//! helper has already cloned into its build cache). traur no longer clones or
//! caches anything itself — see `aur_fetch` for the standalone HTTP path.

use crate::shared::models::GitCommit;
use std::process::Command;

/// Read PKGBUILD content from a local repo directory.
#[allow(dead_code)]
pub fn read_pkgbuild(repo_path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(repo_path.join("PKGBUILD"))
        .map_err(|e| format!("Failed to read PKGBUILD: {e}"))
}

/// Read .install script if present.
pub fn read_install_script(repo_path: &std::path::Path, pkgbuild_content: &str) -> Option<String> {
    // Try to find install= directive in PKGBUILD
    for line in pkgbuild_content.lines() {
        let trimmed = line.trim();
        if let Some(install_file) = trimmed.strip_prefix("install=") {
            let install_file = install_file.trim_matches(|c| c == '\'' || c == '"');
            return std::fs::read_to_string(repo_path.join(install_file)).ok();
        }
    }

    // Fallback: check common names
    for name in &[
        format!("{}.install", repo_path.file_name()?.to_str()?),
        "install".to_string(),
    ] {
        let path = repo_path.join(name);
        if path.exists() {
            return std::fs::read_to_string(path).ok();
        }
    }

    None
}

/// Parse git log into structured commits.
pub fn read_git_log(repo_path: &std::path::Path, max_commits: usize) -> Vec<GitCommit> {
    let output = Command::new("git")
        .args([
            "log",
            &format!("-{max_commits}"),
            "--format=%H%n%an%n%at%n%s%n---END---",
        ])
        .current_dir(repo_path)
        .output();

    let Ok(output) = output else {
        return Vec::new();
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut commits = Vec::new();

    let mut lines = stdout.lines().peekable();
    while lines.peek().is_some() {
        // hash
        match lines.next() {
            Some(h) if !h.is_empty() => {}
            _ => break,
        };
        let author = lines.next().unwrap_or("").to_string();
        let timestamp: u64 = lines.next().unwrap_or("0").parse().unwrap_or(0);
        // message
        let _ = lines.next();

        // Skip the ---END--- delimiter
        while let Some(line) = lines.peek() {
            if *line == "---END---" {
                lines.next();
                break;
            }
            lines.next();
        }

        commits.push(GitCommit {
            author,
            timestamp,
            diff: None,
        });
    }

    commits
}

/// Read the PKGBUILD content at a specific git revision (e.g., "HEAD~1").
pub fn read_pkgbuild_at_revision(repo_path: &std::path::Path, revision: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["show", &format!("{revision}:PKGBUILD")])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

/// Get the diff of the most recent commit.
pub fn get_latest_diff(repo_path: &std::path::Path) -> Option<String> {
    let output = Command::new("git")
        .args(["diff", "HEAD~1..HEAD"])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

