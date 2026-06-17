use crate::features;
use crate::shared::models::PackageContext;
use crate::shared::output;
use crate::shared::scoring::{self, ScanResult, Tier};

/// Scan a package by name, printing results. Returns the computed tier.
pub fn scan_package(package_name: &str, json: bool, verbose: bool) -> Result<Tier, String> {
    let ctx = build_context(package_name)?;
    let result = run_analysis(&ctx);

    if json {
        output::print_json(&result);
    } else {
        output::print_text(&result, verbose);
    }

    Ok(result.tier)
}

/// Build a PackageContext by fetching all data needed for analysis.
pub fn build_context(package_name: &str) -> Result<PackageContext, String> {
    use crate::shared::{aur_comments, aur_git, aur_rpc, cache, github};

    let metadata = aur_rpc::fetch_package_info(package_name)?;

    // Determine package base (for split packages)
    let package_base = metadata
        .package_base
        .as_deref()
        .unwrap_or(package_name);

    // Clone/pull the AUR git repo
    let git_cache = cache::git_cache_dir();
    let cache_str = git_cache.to_str().unwrap_or("/tmp/traur-git");

    let repo_path = aur_git::ensure_repo(package_base, cache_str)?;

    let pkgbuild_content = aur_git::read_pkgbuild(&repo_path).ok();
    let install_script_content = pkgbuild_content
        .as_deref()
        .and_then(|content| aur_git::read_install_script(&repo_path, content));
    let mut git_log = aur_git::read_git_log(&repo_path, 20);

    // Attach diff to the latest commit
    if let Some(first) = git_log.first_mut() {
        first.diff = aur_git::get_latest_diff(&repo_path);
    }

    // Read prior PKGBUILD for diff comparison
    let prior_pkgbuild_content = if git_log.len() >= 2 {
        aur_git::read_pkgbuild_at_revision(&repo_path, "HEAD~1")
    } else {
        None
    };

    // Fetch maintainer's other packages for reputation analysis
    let maintainer_packages = metadata
        .maintainer
        .as_deref()
        .and_then(|m| aur_rpc::fetch_maintainer_packages(m).ok())
        .unwrap_or_default();

    // Fetch GitHub stars if upstream URL points to GitHub
    let (github_stars, github_not_found) = metadata
        .url
        .as_deref()
        .and_then(|url| github::fetch_github_stars(url))
        .map(|info| (if info.found { Some(info.stars) } else { None }, !info.found))
        .unwrap_or((None, false));

    // Fetch recent AUR comments
    let aur_comments = aur_comments::fetch_recent_comments(package_base);

    Ok(PackageContext {
        name: package_name.to_string(),
        metadata: Some(metadata),
        pkgbuild_content,
        install_script_content,
        prior_pkgbuild_content,
        git_log,
        maintainer_packages,
        github_stars,
        github_not_found,
        aur_comments,
    })
}

/// Build context using pre-fetched metadata. Only the git clone hits the network.
/// Returns Err if git clone fails — no PKGBUILD means no meaningful analysis.
pub fn build_context_prefetched(
    package_name: &str,
    metadata: crate::shared::models::AurPackage,
    maintainer_packages: Vec<crate::shared::models::AurPackage>,
) -> Result<PackageContext, String> {
    use crate::shared::{aur_comments, aur_git, cache, github};

    let package_base = metadata
        .package_base
        .as_deref()
        .unwrap_or(package_name);

    let git_cache = cache::git_cache_dir();
    let cache_str = git_cache.to_str().unwrap_or("/tmp/traur-git");

    let repo_path = aur_git::ensure_repo(package_base, cache_str)?;

    let pkgbuild = aur_git::read_pkgbuild(&repo_path).ok();
    let install = pkgbuild
        .as_deref()
        .and_then(|content| aur_git::read_install_script(&repo_path, content));
    let mut log = aur_git::read_git_log(&repo_path, 20);

    if let Some(first) = log.first_mut() {
        first.diff = aur_git::get_latest_diff(&repo_path);
    }

    let prior = if log.len() >= 2 {
        aur_git::read_pkgbuild_at_revision(&repo_path, "HEAD~1")
    } else {
        None
    };

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
        pkgbuild_content: pkgbuild,
        install_script_content: install,
        prior_pkgbuild_content: prior,
        git_log: log,
        maintainer_packages,
        github_stars: gh_stars,
        github_not_found: gh_not_found,
        aur_comments: comments,
    })
}

/// Scan a local PKGBUILD string without network access.
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

    scoring::compute_score(&ctx.name, &all_signals)
}

/// Signals indicating a build/install step fetches a named package over the network.
const NET_INSTALL_SIGNALS: [&str; 4] = [
    "P-NET-PKG-INSTALL-JS",
    "P-NET-PKG-INSTALL",
    "P-INSTALL-PKG-MANAGER-JS",
    "P-INSTALL-PKG-MANAGER",
];

/// Apply composite gates that depend on signals emitted by multiple features.
///
/// A package that was adopted/taken over (`B-SUBMITTER-CHANGED`) AND fetches a
/// named package over the network at build time is the Atomic Arch supply-chain
/// takeover signature — escalate it directly to MALICIOUS.
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
    fn takeover_plus_net_install_gates_malicious() {
        let ctx = ctx_with("attacker", "original", "build() {\n  npm install evilpkg\n}\n");
        let result = run_analysis_with_config(&ctx, &Config::default());
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(result.override_gate_fired.as_deref(), Some("B-ORPHAN-NET-INSTALL"));
    }

    #[test]
    fn net_install_without_takeover_does_not_gate() {
        let ctx = ctx_with("alice", "alice", "build() {\n  npm install evilpkg\n}\n");
        let result = run_analysis_with_config(&ctx, &Config::default());
        assert!(result.override_gate_fired.is_none());
        assert_ne!(result.tier, Tier::Malicious);
        assert!(result.signals.iter().any(|s| s.id == "P-NET-PKG-INSTALL-JS"));
    }
}
