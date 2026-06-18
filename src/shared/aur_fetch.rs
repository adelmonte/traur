//! Fetch a package's PKGBUILD and .install scripts directly over HTTP from
//! AUR's cgit web interface. No git clone, no on-disk cache — the files are
//! pulled into memory, scanned, and discarded.

const AUR_CGIT_PLAIN: &str = "https://aur.archlinux.org/cgit/aur.git/plain";

/// GET a single file from a package's AUR repo at HEAD.
fn fetch_file(package_base: &str, file: &str) -> Result<String, String> {
    let url = format!("{AUR_CGIT_PLAIN}/{file}?h={package_base}");
    let resp = reqwest::blocking::get(&url).map_err(|e| format!("HTTP request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("{file} not found ({})", resp.status()));
    }
    resp.text().map_err(|e| format!("Failed to read {file}: {e}"))
}

/// Fetch the PKGBUILD for a package base.
pub fn fetch_pkgbuild(package_base: &str) -> Result<String, String> {
    fetch_file(package_base, "PKGBUILD")
}

/// Fetch the .install script referenced by a PKGBUILD, if any.
///
/// Honours an explicit `install=` directive, then falls back to the common
/// `<pkgbase>.install` / `install` names. Returns None if none exist.
pub fn fetch_install_script(package_base: &str, pkgbuild: &str) -> Option<String> {
    for line in pkgbuild.lines() {
        let trimmed = line.trim();
        if let Some(install_file) = trimmed.strip_prefix("install=") {
            let install_file = install_file.trim_matches(|c| c == '\'' || c == '"');
            if install_file.is_empty() {
                continue;
            }
            return fetch_file(package_base, install_file).ok();
        }
    }

    for name in [format!("{package_base}.install"), "install".to_string()] {
        if let Ok(content) = fetch_file(package_base, &name) {
            return Some(content);
        }
    }

    None
}
