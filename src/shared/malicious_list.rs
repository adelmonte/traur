//! Known-compromised package check (online only).
//!
//! Fetches Arch's published list of compromised AUR packages and reports a
//! finding if the scanned package name appears on it. This runs only on
//! explicit `traur scan <name>` / all-installed scans — never during a build —
//! and is bounded by a short timeout, cached on disk, and fails open (any
//! network/parse error simply yields no finding).

use crate::shared::scoring::{Signal, SignalCategory};
use std::time::Duration;

/// Best-known source for the compromised-package list. Override with the
/// `TRAUR_MALICIOUS_LIST_URL` environment variable.
const DEFAULT_LIST_URL: &str = "https://md.archlinux.org/SxbqukK6IA/download";
const CACHE_TTL: Duration = Duration::from_secs(6 * 3600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

fn cache_path() -> std::path::PathBuf {
    // Per-user cache file (no libc dependency; USER is enough to avoid clashes).
    let who = std::env::var("USER").unwrap_or_else(|_| "shared".to_string());
    std::env::temp_dir().join(format!("traur-malicious-list-{who}.txt"))
}

fn list_url() -> String {
    std::env::var("TRAUR_MALICIOUS_LIST_URL").unwrap_or_else(|_| DEFAULT_LIST_URL.to_string())
}

/// Load the list text, preferring a fresh on-disk cache. Returns None on any
/// failure (fail-open).
fn load_list() -> Option<String> {
    let path = cache_path();
    if let Ok(meta) = std::fs::metadata(&path) {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().map(|e| e < CACHE_TTL).unwrap_or(false) {
                if let Ok(cached) = std::fs::read_to_string(&path) {
                    return Some(cached);
                }
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .ok()?;
    let body = client.get(list_url()).send().ok()?.text().ok()?;
    let _ = std::fs::write(&path, &body);
    Some(body)
}

/// Return a finding if `package` appears on the known-compromised list.
pub fn check(package: &str) -> Option<Signal> {
    if package.is_empty() {
        return None;
    }
    let list = load_list()?;

    let is_token = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '@');
    let hit = list
        .lines()
        .flat_map(|line| line.split(|c: char| !is_token(c)))
        .any(|tok| tok == package);

    if hit {
        Some(Signal {
            id: "B-KNOWN-MALICIOUS".to_string(),
            category: SignalCategory::Behavioral,
            points: 100,
            description: "Package appears on Arch's known-compromised package list".to_string(),
            is_override_gate: true,
            matched_line: None,
        })
    } else {
        None
    }
}
