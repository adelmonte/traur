//! Integration tests that verify the full scan pipeline:
//! coordinator -> all features -> flat findings list.
//!
//! Individual pattern/signal tests live in each feature's #[cfg(test)] module.

use traur::coordinator::scan_pkgbuild;

fn signal_ids(result: &traur::shared::scoring::ScanResult) -> Vec<&str> {
    result.signals.iter().map(|s| s.id.as_str()).collect()
}

#[test]
fn malicious_curl_pipe_detected() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);
    assert!(signal_ids(&result).contains(&"P-CURL-PIPE"), "got: {:?}", signal_ids(&result));
}

#[test]
fn malicious_pkgbuild_accumulates_cross_feature_signals() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);

    let ids = signal_ids(&result);

    // pkgbuild_analysis signal
    assert!(ids.contains(&"P-CURL-PIPE"), "got: {ids:?}");
    // source_url_analysis signals
    assert!(ids.contains(&"P-URL-SHORTENER"), "got: {ids:?}");
    assert!(ids.contains(&"P-RAW-IP-URL"), "got: {ids:?}");
    // name_analysis signal
    assert!(ids.contains(&"B-NAME-IMPERSONATE"), "got: {ids:?}");
}

#[test]
fn benign_pkgbuild_has_no_severe_findings() {
    let pkgbuild = include_str!("fixtures/benign/yay.PKGBUILD");
    let result = scan_pkgbuild("yay", pkgbuild);
    let ids = signal_ids(&result);
    assert!(!ids.contains(&"P-CURL-PIPE"), "benign package should not match curl|bash, got: {ids:?}");
}

#[test]
fn python_rce_detected() {
    let pkgbuild = include_str!("fixtures/malicious/python_rce.PKGBUILD");
    let result = scan_pkgbuild("python-helper", pkgbuild);
    assert!(
        signal_ids(&result).contains(&"P-PYTHON-EXEC-URL"),
        "got: {:?}",
        signal_ids(&result)
    );
}

#[test]
fn acroread_style_multi_signal_detection() {
    let pkgbuild = include_str!("fixtures/malicious/acroread_style.PKGBUILD");
    let result = scan_pkgbuild("acroread", pkgbuild);

    let ids = signal_ids(&result);
    // Verifies signals from multiple features fire together
    assert!(ids.contains(&"P-CURL-PIPE"), "got: {ids:?}");
    assert!(ids.contains(&"P-PASTEBIN-CODE"), "got: {ids:?}");
    assert!(ids.contains(&"P-SYSINFO-RECON"), "got: {ids:?}");
    assert!(ids.contains(&"P-SYSTEMD-CREATE"), "got: {ids:?}");
}

#[test]
fn gtfobins_multi_signal_detection() {
    let pkgbuild = include_str!("fixtures/malicious/gtfobins_multi.PKGBUILD");
    let result = scan_pkgbuild("evil-tool", pkgbuild);

    let ids = signal_ids(&result);
    // gtfobins_analysis signals
    assert!(ids.contains(&"G-TAR-CHECKPOINT"), "got: {ids:?}");
    assert!(ids.contains(&"G-DOWNLOAD-ARIA2C"), "got: {ids:?}");
    assert!(ids.contains(&"G-DOWNLOAD-LWP"), "got: {ids:?}");
    assert!(ids.contains(&"G-REVSHELL-NODE"), "got: {ids:?}");
    assert!(ids.contains(&"G-PIPE-RUBY"), "got: {ids:?}");
    // source_url_analysis signal for raw IP
    assert!(ids.contains(&"P-RAW-IP-URL"), "got: {ids:?}");
}
