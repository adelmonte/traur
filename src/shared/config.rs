use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub ignored: IgnoredConfig,
    #[serde(default)]
    pub wrapper: WrapperConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct IgnoredConfig {
    #[serde(default)]
    pub signals: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WrapperConfig {
    /// makepkg-wrapper scan mode: "online" (local files + network signals,
    /// bounded by a timeout) or "offline" (local files only).
    #[serde(default = "default_wrapper_mode")]
    pub mode: String,
}

impl Default for WrapperConfig {
    fn default() -> Self {
        Self { mode: default_wrapper_mode() }
    }
}

fn default_wrapper_mode() -> String {
    "online".to_string()
}

/// Valid wrapper modes.
pub const WRAPPER_MODES: [&str; 2] = ["online", "offline"];

/// Read the configured wrapper mode (defaults to "online").
pub fn wrapper_mode() -> String {
    load_config().wrapper.mode
}

/// Set and persist the wrapper mode.
pub fn set_wrapper_mode(mode: &str) -> Result<(), String> {
    let mut config = load_config();
    config.wrapper.mode = mode.to_string();
    save_config(&config)
}

/// Load config from ~/.config/traur/config.toml, falling back to defaults.
pub fn load_config() -> Config {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// Save config to ~/.config/traur/config.toml, creating directory if needed.
pub fn save_config(config: &Config) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
    }
    let toml_str =
        toml::to_string_pretty(config).map_err(|e| format!("Failed to serialize config: {e}"))?;
    std::fs::write(&path, toml_str).map_err(|e| format!("Failed to write config: {e}"))?;
    Ok(())
}

/// Add a signal ID to the ignored list and persist to disk.
pub fn add_to_ignored(signal_id: &str) -> Result<(), String> {
    let mut config = load_config();
    if !config.ignored.signals.contains(&signal_id.to_string()) {
        config.ignored.signals.push(signal_id.to_string());
        config.ignored.signals.sort();
    }
    save_config(&config)
}

/// Remove a signal ID from the ignored list and persist to disk.
pub fn remove_from_ignored(signal_id: &str) -> Result<(), String> {
    let mut config = load_config();
    config.ignored.signals.retain(|s| s != signal_id);
    save_config(&config)
}

/// Check if a signal should be ignored (by individual ID or by category).
/// Ignoring "SA-FOO" also suppresses "IS-SA-FOO".
#[allow(dead_code)] // Used by coordinator and traur-hook
pub fn is_signal_ignored(
    config: &Config,
    signal_id: &str,
    signal_category: &crate::shared::scoring::SignalCategory,
) -> bool {
    // Check category-level ignore
    if !config.ignored.categories.is_empty() {
        let cat_str = format!("{:?}", signal_category);
        if config.ignored.categories.iter().any(|c| c.eq_ignore_ascii_case(&cat_str)) {
            return true;
        }
    }

    if config.ignored.signals.is_empty() {
        return false;
    }
    // Exact match
    if config.ignored.signals.iter().any(|s| s == signal_id) {
        return true;
    }
    // IS-prefixed variant: if "SA-FOO" is ignored, "IS-SA-FOO" is also ignored
    if let Some(base) = signal_id.strip_prefix("IS-") {
        return config.ignored.signals.iter().any(|s| s == base);
    }
    false
}

/// Add a category to the ignored list and persist to disk.
pub fn add_category_to_ignored(category: &str) -> Result<(), String> {
    let mut config = load_config();
    if !config.ignored.categories.iter().any(|c| c.eq_ignore_ascii_case(category)) {
        config.ignored.categories.push(category.to_string());
        config.ignored.categories.sort();
    }
    save_config(&config)
}

/// Remove a category from the ignored list and persist to disk.
pub fn remove_category_from_ignored(category: &str) -> Result<(), String> {
    let mut config = load_config();
    config.ignored.categories.retain(|c| !c.eq_ignore_ascii_case(category));
    save_config(&config)
}

pub fn config_path() -> std::path::PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return std::path::PathBuf::from(xdg).join("traur").join("config.toml");
    }

    // When running under sudo/doas (e.g. ALPM hook), resolve the invoking
    // user's home so we read *their* config instead of /root's.
    if let Some(home) = calling_user_home() {
        return home.join(".config").join("traur").join("config.toml");
    }

    if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home)
            .join(".config")
            .join("traur")
            .join("config.toml")
    } else {
        std::path::PathBuf::from("/etc/traur/config.toml")
    }
}

/// Resolve the invoking user's home directory when running under sudo or doas.
fn calling_user_home() -> Option<std::path::PathBuf> {
    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("DOAS_USER"))
        .ok()?;

    if user == "root" {
        return None;
    }

    let output = std::process::Command::new("getent")
        .args(["passwd", &user])
        .output()
        .ok()?;

    let line = String::from_utf8(output.stdout).ok()?;
    // getent passwd format: name:x:uid:gid:gecos:home:shell
    let home = line.split(':').nth(5)?;
    Some(std::path::PathBuf::from(home))
}
