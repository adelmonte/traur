mod coordinator;
mod features;
mod shared;

use clap::{Parser, Subcommand};
use std::process;

#[derive(Parser)]
#[command(name = "traur", about = "Findings-based security scanner for AUR PKGBUILDs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a package (or all installed AUR packages if none specified)
    Scan {
        /// Package name to scan (or --pkgbuild for local)
        package: Option<String>,

        /// Scan a local PKGBUILD directory
        #[arg(long)]
        pkgbuild: Option<String>,

        /// Scan all installed AUR packages (default when no package given)
        #[arg(long)]
        all_installed: bool,

        /// Number of concurrent scan threads (for bulk scanning)
        #[arg(long, default_value_t = 4)]
        jobs: usize,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Show the exact line that triggered each signal
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Only show packages that have findings
        #[arg(short = 'f', long)]
        flagged_only: bool,

        /// With --pkgbuild: print the PKGBUILD/.install with flagged lines highlighted
        #[arg(long)]
        source: bool,
    },
    /// Whitelist a package (skip future scans)
    Allow {
        /// Package name to whitelist
        package: String,
    },
    /// Enable/disable the makepkg wrapper that scans PKGBUILDs before AUR builds
    Wrapper {
        /// Symlink the wrapper into /usr/local/bin/makepkg (needs root)
        #[arg(long)]
        enable: bool,

        /// Remove the wrapper symlink (needs root)
        #[arg(long)]
        disable: bool,

        /// Show whether the wrapper is enabled (default)
        #[arg(long)]
        status: bool,
    },
    /// List all available signals
    Signals {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Ignore a signal or category (exclude from output)
    Ignore {
        /// Signal ID to ignore (e.g. P-PYTHON-INLINE)
        signal_id: Option<String>,

        /// Ignore all signals in a category (Metadata, Pkgbuild, Behavioral, Temporal)
        #[arg(long)]
        category: Option<String>,
    },
    /// Unignore a previously ignored signal or category
    Unignore {
        /// Signal ID to restore
        signal_id: Option<String>,

        /// Restore all signals in a category
        #[arg(long)]
        category: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Scan {
            package,
            pkgbuild,
            all_installed,
            jobs,
            json,
            verbose,
            flagged_only,
            source,
        } => cmd_scan(package, pkgbuild, all_installed, jobs, json, verbose, flagged_only, source),
        Commands::Allow { package } => cmd_allow(&package),
        Commands::Wrapper { enable, disable, status: _ } => cmd_wrapper(enable, disable),
        Commands::Signals { json } => cmd_signals(json),
        Commands::Ignore { signal_id, category } => cmd_ignore(signal_id.as_deref(), category.as_deref()),
        Commands::Unignore { signal_id, category } => cmd_unignore(signal_id.as_deref(), category.as_deref()),
    };

    process::exit(exit_code);
}

fn cmd_scan(
    package: Option<String>,
    pkgbuild: Option<String>,
    _all_installed: bool,
    jobs: usize,
    json: bool,
    verbose: bool,
    flagged_only: bool,
    source: bool,
) -> i32 {
    if let Some(path) = pkgbuild {
        // Canonicalize so a relative "./PKGBUILD" still yields the package-dir
        // name (its parent is "." otherwise).
        let path_buf = std::fs::canonicalize(&path).unwrap_or_else(|_| std::path::PathBuf::from(&path));
        let name = path_buf
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("local");
        match coordinator::scan_local(name, &path_buf) {
            Ok(result) => {
                if json {
                    shared::output::print_json(&result);
                } else {
                    shared::output::print_text(&result, verbose);
                    if source {
                        print_flagged_source(&path_buf, &result);
                    }
                }
                return 0;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        }
    }

    if let Some(pkg) = package {
        return cmd_scan_single(&pkg, json, verbose);
    }

    // No package, no pkgbuild -> scan all installed AUR packages
    cmd_scan_all_installed(jobs, json, verbose, flagged_only)
}

/// Print the PKGBUILD and .install with traur-flagged lines highlighted.
fn print_flagged_source(pkgbuild_path: &std::path::Path, result: &shared::scoring::ScanResult) {
    let flagged = shared::output::flagged_lines(result);
    let mut w = std::io::stderr();
    if let Ok(content) = std::fs::read_to_string(pkgbuild_path) {
        shared::output::write_source(&mut w, "PKGBUILD", &content, &flagged);
        let dir = pkgbuild_path.parent().unwrap_or(std::path::Path::new("."));
        if let Some(install) = shared::aur_git::read_install_script(dir, &content) {
            shared::output::write_source(&mut w, ".install", &install, &flagged);
        }
    }
}

fn cmd_scan_single(pkg: &str, json: bool, verbose: bool) -> i32 {
    match coordinator::scan_package(pkg, json, verbose) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error scanning {pkg}: {e}");
            1
        }
    }
}

fn cmd_scan_all_installed(jobs: usize, json: bool, verbose: bool, flagged_only: bool) -> i32 {
    use crate::shared::bulk::{batch_fetch_metadata, fetch_with_retry, prefetch_maintainer_packages};
    use crate::shared::scoring::ScanResult;
    use colored::Colorize;
    use indicatif::{ProgressBar, ProgressStyle};
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut names = match get_installed_aur_packages() {
        Ok(names) if names.is_empty() => {
            eprintln!("No AUR packages installed.");
            return 0;
        }
        Ok(names) => names,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    eprintln!("  Fetching package metadata for {} installed packages...", names.len());
    let metadata = batch_fetch_metadata(&names);
    let not_found: Vec<&str> = names
        .iter()
        .filter(|n| !metadata.contains_key(n.as_str()))
        .map(|n| n.as_str())
        .collect();
    if !not_found.is_empty() {
        eprintln!("  Skipping {} not on AUR: {}", not_found.len(), not_found.join(", "));
        names.retain(|n| metadata.contains_key(n.as_str()));
    }
    let total = names.len();
    eprintln!(
        "{}",
        format!("Scanning {} AUR packages...", total).bold()
    );

    let maintainer_packages = prefetch_maintainer_packages(&metadata);

    let config = shared::config::load_config();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .expect("Failed to build thread pool");

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({per_sec})")
            .unwrap()
            .progress_chars("##-"),
    );

    let error_count = AtomicU64::new(0);
    let results = std::sync::Mutex::new(Vec::<ScanResult>::new());

    pool.install(|| {
        names.par_iter().for_each(|name| {
            let result = if let Some(meta) = metadata.get(name).cloned() {
                let maint_pkgs = meta
                    .maintainer
                    .as_deref()
                    .and_then(|m| maintainer_packages.get(m))
                    .cloned()
                    .unwrap_or_default();

                match fetch_with_retry(name, meta, maint_pkgs) {
                    Ok(ctx) => {
                        let mut scan = coordinator::run_analysis_with_config(&ctx, &config);
                        if let Some(sig) = shared::malicious_list::check(name) {
                            scan.signals.insert(0, sig);
                        }
                        Ok(scan)
                    }
                    Err(e) => Err(e),
                }
            } else {
                Err("not found on AUR".to_string())
            };

            match result {
                Ok(scan) => {
                    if !flagged_only || !scan.signals.is_empty() {
                        results.lock().unwrap().push(scan);
                    }
                }
                Err(e) => {
                    eprintln!("  error: {name}: {e}");
                    error_count.fetch_add(1, Ordering::Relaxed);
                }
            }

            pb.inc(1);
        });
    });

    pb.finish_and_clear();

    let mut results = results.into_inner().unwrap();
    let errors = error_count.load(Ordering::Relaxed) as usize;
    let scanned = total - errors;

    // Show packages with the most findings first.
    results.sort_by(|a, b| b.signals.len().cmp(&a.signals.len()));

    if json {
        let json_str = serde_json::to_string_pretty(&results).expect("Failed to serialize");
        println!("{json_str}");
    } else {
        println!();
        println!("{}", "=== traur scan results ===".bold());
        println!("  Scanned: {} packages ({} errors)", scanned, errors);

        let with_findings = results.iter().filter(|r| !r.signals.is_empty()).count();
        if with_findings > 0 {
            println!();
            println!(
                "{}",
                format!("=== {with_findings} packages with findings ===").bold()
            );
            for result in results.iter().filter(|r| !r.signals.is_empty()) {
                println!();
                shared::output::print_text(result, verbose);
            }
        } else {
            println!();
            println!("{}", "No findings in any installed AUR package.".green());
        }
    }

    0
}

/// Get list of installed AUR (foreign) package names via `pacman -Qm`.
fn get_installed_aur_packages() -> Result<Vec<String>, String> {
    use std::process::Command;

    let output = Command::new("pacman")
        .args(["-Qm"])
        .output()
        .map_err(|e| format!("Failed to run pacman: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pacman -Qm failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let names: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?;
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect();

    Ok(names)
}

fn cmd_allow(package: &str) -> i32 {
    match shared::config::add_to_whitelist(package) {
        Ok(()) => {
            eprintln!("Whitelisted: {package}");
            eprintln!("  Saved to {}", shared::config::config_path().display());
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

/// Path of the installed wrapper script and the PATH symlink that activates it.
const WRAPPER_SRC: &str = "/usr/share/traur/makepkg";
const WRAPPER_LINK: &str = "/usr/local/bin/makepkg";

fn cmd_wrapper(enable: bool, disable: bool) -> i32 {
    use std::io::ErrorKind;
    use std::path::Path;

    let src = Path::new(WRAPPER_SRC);
    let link = Path::new(WRAPPER_LINK);

    let perm_hint = |action: &str| {
        eprintln!("Permission denied. Re-run with sudo:");
        eprintln!("  sudo traur wrapper {action}");
    };

    if enable {
        if !src.exists() {
            eprintln!("Wrapper script not found at {WRAPPER_SRC} (is traur installed?)");
            return 1;
        }
        if let Ok(meta) = std::fs::symlink_metadata(link) {
            if meta.file_type().is_symlink() && std::fs::read_link(link).ok().as_deref() == Some(src) {
                eprintln!("Already enabled: {WRAPPER_LINK} -> {WRAPPER_SRC}");
                return 0;
            }
            eprintln!("{WRAPPER_LINK} already exists and is not the traur wrapper.");
            eprintln!("Refusing to overwrite it. Remove it yourself if you want to enable.");
            return 1;
        }
        if let Some(parent) = link.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::os::unix::fs::symlink(src, link) {
            Ok(()) => {
                eprintln!("Enabled: {WRAPPER_LINK} -> {WRAPPER_SRC}");
                eprintln!("AUR builds (via yay/paru) will now be scanned by traur first.");
                0
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                perm_hint("--enable");
                1
            }
            Err(e) => {
                eprintln!("Failed to create symlink: {e}");
                1
            }
        }
    } else if disable {
        match std::fs::symlink_metadata(link) {
            Ok(meta)
                if meta.file_type().is_symlink()
                    && std::fs::read_link(link).ok().as_deref() == Some(src) =>
            {
                match std::fs::remove_file(link) {
                    Ok(()) => {
                        eprintln!("Disabled: removed {WRAPPER_LINK}");
                        0
                    }
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                        perm_hint("--disable");
                        1
                    }
                    Err(e) => {
                        eprintln!("Failed to remove symlink: {e}");
                        1
                    }
                }
            }
            _ => {
                eprintln!("Not enabled (no traur wrapper symlink at {WRAPPER_LINK}).");
                0
            }
        }
    } else {
        // status (default)
        match std::fs::symlink_metadata(link) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let target = std::fs::read_link(link).unwrap_or_default();
                if target == src {
                    println!("enabled  ({WRAPPER_LINK} -> {WRAPPER_SRC})");
                } else {
                    println!("disabled (foreign symlink at {WRAPPER_LINK} -> {})", target.display());
                }
            }
            Ok(_) => println!("disabled (a non-traur makepkg exists at {WRAPPER_LINK})"),
            Err(_) => println!("disabled"),
        }
        0
    }
}

fn cmd_signals(json: bool) -> i32 {
    use shared::scoring::SignalCategory;
    use shared::signal_registry::all_signal_definitions;

    let defs = all_signal_definitions();
    let config = shared::config::load_config();
    let ignored_signals = &config.ignored.signals;
    let ignored_categories = &config.ignored.categories;

    let is_ignored = |d: &shared::signal_registry::SignalDef| -> bool {
        if ignored_signals.contains(&d.id) {
            return true;
        }
        let cat_str = format!("{:?}", d.category);
        ignored_categories.iter().any(|c| c.eq_ignore_ascii_case(&cat_str))
    };

    if json {
        let entries: Vec<serde_json::Value> = defs
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id,
                    "category": format!("{:?}", d.category),
                    "description": d.description,
                    "ignored": is_ignored(d),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).expect("Failed to serialize")
        );
        return 0;
    }

    let categories = [
        (SignalCategory::Metadata, "Metadata"),
        (SignalCategory::Pkgbuild, "Pkgbuild"),
        (SignalCategory::Behavioral, "Behavioral"),
        (SignalCategory::Temporal, "Temporal"),
    ];

    let mut total = 0;
    let mut ignored_count = 0;

    for (cat, label) in &categories {
        let cat_defs: Vec<_> = defs.iter().filter(|d| d.category == *cat).collect();
        if cat_defs.is_empty() {
            continue;
        }
        println!("\n  {label}");
        for d in &cat_defs {
            let sig_ignored = is_ignored(d);
            let marker = if sig_ignored { " [IGNORED]" } else { "" };
            println!(
                "  {:<36} {}{}",
                d.id, d.description, marker
            );
            total += 1;
            if sig_ignored {
                ignored_count += 1;
            }
        }
    }

    println!();
    if ignored_count > 0 {
        println!("  {total} signals ({ignored_count} ignored)");
    } else {
        println!("  {total} signals");
    }
    0
}

fn cmd_ignore(signal_id: Option<&str>, category: Option<&str>) -> i32 {
    match (signal_id, category) {
        (Some(id), None) => {
            if !shared::signal_registry::is_known_signal(id) {
                eprintln!("Unknown signal: {id}");
                eprintln!("Use 'traur signals' to list available signal IDs.");
                return 1;
            }
            match shared::config::add_to_ignored(id) {
                Ok(()) => {
                    eprintln!("Ignored: {id}");
                    eprintln!("  Saved to {}", shared::config::config_path().display());
                    0
                }
                Err(e) => { eprintln!("Error: {e}"); 1 }
            }
        }
        (None, Some(cat)) => {
            if shared::signal_registry::category_from_str(cat).is_none() {
                eprintln!("Unknown category: {cat}");
                eprintln!("Valid categories: Metadata, Pkgbuild, Behavioral, Temporal");
                return 1;
            }
            match shared::config::add_category_to_ignored(cat) {
                Ok(()) => {
                    eprintln!("Ignored category: {cat}");
                    eprintln!("  Saved to {}", shared::config::config_path().display());
                    0
                }
                Err(e) => { eprintln!("Error: {e}"); 1 }
            }
        }
        _ => {
            eprintln!("Provide either a signal ID or --category, not both.");
            1
        }
    }
}

fn cmd_unignore(signal_id: Option<&str>, category: Option<&str>) -> i32 {
    match (signal_id, category) {
        (Some(id), None) => {
            match shared::config::remove_from_ignored(id) {
                Ok(()) => {
                    eprintln!("Unignored: {id}");
                    eprintln!("  Saved to {}", shared::config::config_path().display());
                    0
                }
                Err(e) => { eprintln!("Error: {e}"); 1 }
            }
        }
        (None, Some(cat)) => {
            if shared::signal_registry::category_from_str(cat).is_none() {
                eprintln!("Unknown category: {cat}");
                eprintln!("Valid categories: Metadata, Pkgbuild, Behavioral, Temporal");
                return 1;
            }
            match shared::config::remove_category_from_ignored(cat) {
                Ok(()) => {
                    eprintln!("Unignored category: {cat}");
                    eprintln!("  Saved to {}", shared::config::config_path().display());
                    0
                }
                Err(e) => { eprintln!("Error: {e}"); 1 }
            }
        }
        _ => {
            eprintln!("Provide either a signal ID or --category, not both.");
            1
        }
    }
}
