use crate::features;
use crate::shared::models::PackageContext;
use crate::shared::output;
use crate::shared::scoring::{self, ScanResult};

/// Scan a package by name, printing its findings.
pub fn scan_package(package_name: &str, json: bool, verbose: bool) -> Result<(), String> {
    let ctx = build_context(package_name)?;
    let mut result = run_analysis(&ctx);

    // Online-only: known-compromised list check (fails open).
    if let Some(sig) = crate::shared::malicious_list::check(package_name) {
        result.signals.insert(0, sig);
    }

    if json {
        output::print_json(&result);
    } else {
        output::print_text(&result, verbose);
    }

    Ok(())
}

/// Build a PackageContext for a named package by fetching everything over HTTP.
///
/// The PKGBUILD and .install are pulled from AUR's cgit (no clone, no cache);
/// metadata, maintainer packages, GitHub stars and comments come from the AUR
/// RPC / GitHub APIs. There is no local git history, so the diff/git-history
/// features no-op for this path.
pub fn build_context(package_name: &str) -> Result<PackageContext, String> {
    let metadata = crate::shared::aur_rpc::fetch_package_info(package_name)?;
    let maintainer_packages = metadata
        .maintainer
        .as_deref()
        .and_then(|m| crate::shared::aur_rpc::fetch_maintainer_packages(m).ok())
        .unwrap_or_default();
    build_context_prefetched(package_name, metadata, maintainer_packages)
}

/// Build context from pre-fetched metadata, fetching the PKGBUILD/.install over
/// HTTP. Returns Err if the PKGBUILD can't be fetched (nothing to analyze).
pub fn build_context_prefetched(
    package_name: &str,
    metadata: crate::shared::models::AurPackage,
    maintainer_packages: Vec<crate::shared::models::AurPackage>,
) -> Result<PackageContext, String> {
    use crate::shared::{aur_comments, aur_fetch, github};

    let package_base = metadata.package_base.as_deref().unwrap_or(package_name);

    let pkgbuild = aur_fetch::fetch_pkgbuild(package_base)?;
    let install = aur_fetch::fetch_install_script(package_base, &pkgbuild);

    let (gh_stars, gh_not_found) = metadata
        .url
        .as_deref()
        .and_then(|url| github::fetch_github_stars(url))
        .map(|info| (if info.found { Some(info.stars) } else { None }, !info.found))
        .unwrap_or((None, false));

    let comments = aur_comments::fetch_recent_comments(package_base);

    Ok(PackageContext {
        name: package_name.to_string(),
        metadata: Some(metadata),
        pkgbuild_content: Some(pkgbuild),
        install_script_content: install,
        prior_pkgbuild_content: None,
        git_log: Vec::new(),
        maintainer_packages,
        github_stars: gh_stars,
        github_not_found: gh_not_found,
        aur_comments: comments,
    })
}

/// Scan a PKGBUILD provided as an in-memory string (no network, no git).
/// Used by the library API and integration tests.
#[allow(dead_code)]
pub fn scan_pkgbuild(name: &str, pkgbuild_content: &str) -> ScanResult {
    let ctx = PackageContext {
        name: name.to_string(),
        metadata: None,
        pkgbuild_content: Some(pkgbuild_content.to_string()),
        install_script_content: None,
        prior_pkgbuild_content: None,
        git_log: Vec::new(),
        maintainer_packages: Vec::new(),
        github_stars: None,
        github_not_found: false,
        aur_comments: vec![],
    };
    run_analysis(&ctx)
}

/// Scan a local PKGBUILD file. The PKGBUILD/.install and (when the directory is
/// a git repo) the local history are always read offline. When `online` is set,
/// the package's network signals (votes, GitHub stars, comments, known-malicious
/// list) are also fetched for `name` and merged in — callers should bound this
/// with a timeout. Online fetch failures fail open (the offline scan still runs).
pub fn scan_local(
    name: &str,
    pkgbuild_path: &std::path::Path,
    online: bool,
) -> Result<ScanResult, String> {
    use crate::shared::aur_git;

    let content = std::fs::read_to_string(pkgbuild_path)
        .map_err(|e| format!("Failed to read {}: {e}", pkgbuild_path.display()))?;
    let dir = pkgbuild_path.parent().unwrap_or(std::path::Path::new("."));

    let install_script_content = aur_git::read_install_script(dir, &content);

    let (git_log, prior_pkgbuild_content) = if dir.join(".git").exists() {
        let mut log = aur_git::read_git_log(dir, 20);
        if let Some(first) = log.first_mut() {
            first.diff = aur_git::get_latest_diff(dir);
        }
        let prior = if log.len() >= 2 {
            aur_git::read_pkgbuild_at_revision(dir, "HEAD~1")
        } else {
            None
        };
        (log, prior)
    } else {
        (Vec::new(), None)
    };

    let mut ctx = PackageContext {
        name: name.to_string(),
        metadata: None,
        pkgbuild_content: Some(content),
        install_script_content,
        prior_pkgbuild_content,
        git_log,
        maintainer_packages: Vec::new(),
        github_stars: None,
        github_not_found: false,
        aur_comments: vec![],
    };

    if online {
        enrich_online(&mut ctx);
    }

    let mut result = run_analysis(&ctx);

    if online {
        if let Some(sig) = crate::shared::malicious_list::check(name) {
            result.signals.insert(0, sig);
        }
    }

    Ok(result)
}

/// Fetch network signals for a locally-scanned package and merge them into the
/// context. Fails open: any fetch error leaves the offline context untouched.
fn enrich_online(ctx: &mut PackageContext) {
    use crate::shared::{aur_comments, aur_rpc, github};

    let Ok(metadata) = aur_rpc::fetch_package_info(&ctx.name) else {
        return;
    };

    ctx.maintainer_packages = metadata
        .maintainer
        .as_deref()
        .and_then(|m| aur_rpc::fetch_maintainer_packages(m).ok())
        .unwrap_or_default();

    let (stars, not_found) = metadata
        .url
        .as_deref()
        .and_then(|url| github::fetch_github_stars(url))
        .map(|info| (if info.found { Some(info.stars) } else { None }, !info.found))
        .unwrap_or((None, false));
    ctx.github_stars = stars;
    ctx.github_not_found = not_found;

    let package_base = metadata.package_base.as_deref().unwrap_or(&ctx.name);
    ctx.aur_comments = aur_comments::fetch_recent_comments(package_base);

    ctx.metadata = Some(metadata);
}


/// Run all registered features against the context and compute a score.
pub fn run_analysis(ctx: &PackageContext) -> ScanResult {
    let config = crate::shared::config::load_config();
    run_analysis_with_config(ctx, &config)
}

/// Run analysis with a pre-loaded config (avoids reloading per package in bulk scans).
pub fn run_analysis_with_config(
    ctx: &PackageContext,
    config: &crate::shared::config::Config,
) -> ScanResult {
    let all_features = features::all_features();

    let mut all_signals = Vec::new();
    for feature in &all_features {
        let signals = feature.analyze(ctx);
        all_signals.extend(signals);
    }

    apply_composite_gates(&mut all_signals);

    if !config.ignored.signals.is_empty() || !config.ignored.categories.is_empty() {
        all_signals
            .retain(|s| !crate::shared::config::is_signal_ignored(config, &s.id, &s.category));
    }

    ScanResult {
        package: ctx.name.clone(),
        signals: all_signals,
    }
}

/// Signals indicating a build/install step fetches a named package over the network.
const NET_INSTALL_SIGNALS: [&str; 4] = [
    "P-NET-PKG-INSTALL-JS",
    "P-NET-PKG-INSTALL",
    "P-INSTALL-PKG-MANAGER-JS",
    "P-INSTALL-PKG-MANAGER",
];

/// Apply composite findings that depend on signals emitted by multiple features.
///
/// A package that was adopted/taken over (`B-SUBMITTER-CHANGED`) AND fetches a
/// named package over the network at build time is the Atomic Arch supply-chain
/// takeover signature — emit a dedicated composite finding.
fn apply_composite_gates(signals: &mut Vec<scoring::Signal>) {
    use crate::shared::scoring::{Signal, SignalCategory};

    let taken_over = signals.iter().any(|s| s.id == "B-SUBMITTER-CHANGED");
    let net_install = signals
        .iter()
        .find(|s| NET_INSTALL_SIGNALS.contains(&s.id.as_str()));

    if let (true, Some(install)) = (taken_over, net_install) {
        let matched_line = install.matched_line.clone();
        signals.push(Signal {
            id: "B-ORPHAN-NET-INSTALL".to_string(),
            category: SignalCategory::Behavioral,
            points: 90,
            description:
                "Adopted/taken-over package fetches a named package over the network at build time — supply-chain takeover pattern"
                    .to_string(),
            is_override_gate: true,
            matched_line,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::Config;
    use crate::shared::models::AurPackage;

    fn make_pkg(maintainer: &str, submitter: &str) -> AurPackage {
        AurPackage {
            name: "test-pkg".into(),
            package_base: None,
            url: None,
            num_votes: 10,
            popularity: 1.0,
            out_of_date: None,
            maintainer: Some(maintainer.into()),
            submitter: Some(submitter.into()),
            first_submitted: 1_600_000_000,
            last_modified: 1_700_000_000,
            license: None,
        }
    }

    fn ctx_with(maintainer: &str, submitter: &str, pkgbuild: &str) -> PackageContext {
        PackageContext {
            name: "test-pkg".into(),
            metadata: Some(make_pkg(maintainer, submitter)),
            pkgbuild_content: Some(pkgbuild.into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        }
    }

    #[test]
    fn takeover_plus_net_install_emits_composite_finding() {
        let ctx = ctx_with("attacker", "original", "build() {\n  npm install evilpkg\n}\n");
        let result = run_analysis_with_config(&ctx, &Config::default());
        assert!(result.signals.iter().any(|s| s.id == "B-ORPHAN-NET-INSTALL"));
    }

    #[test]
    fn net_install_without_takeover_emits_no_composite() {
        let ctx = ctx_with("alice", "alice", "build() {\n  npm install evilpkg\n}\n");
        let result = run_analysis_with_config(&ctx, &Config::default());
        assert!(!result.signals.iter().any(|s| s.id == "B-ORPHAN-NET-INSTALL"));
        assert!(result.signals.iter().any(|s| s.id == "P-NET-PKG-INSTALL-JS"));
    }
}
