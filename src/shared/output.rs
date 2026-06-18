use std::collections::HashSet;
use std::io::Write;
use crate::shared::scoring::{ScanResult, Signal, SignalCategory};
use colored::{ColoredString, Colorize};

/// Categories in display order. The header is shown once per group, so the
/// ID prefix (P-/B-/T-/M-) isn't repeated on every line.
const CATEGORY_ORDER: [SignalCategory; 4] = [
    SignalCategory::Pkgbuild,
    SignalCategory::Behavioral,
    SignalCategory::Temporal,
    SignalCategory::Metadata,
];

/// Color-coded section header for a category.
fn category_header(category: SignalCategory) -> ColoredString {
    let name = format!("{category:?}");
    match category {
        SignalCategory::Pkgbuild => name.red(),
        SignalCategory::Behavioral => name.yellow(),
        SignalCategory::Temporal => name.cyan(),
        SignalCategory::Metadata => name.blue(),
    }
}

/// Print scan result as colored terminal text to stderr.
pub fn print_text(result: &ScanResult, verbose: bool) {
    write_text(&mut std::io::stderr(), result, verbose);
}

/// Write scan result as colored terminal text, grouped by category. Each
/// finding shows the offending line when one was captured.
pub fn write_text(w: &mut dyn Write, result: &ScanResult, _verbose: bool) {
    let _ = writeln!(w, "{} {}", "traur:".bold(), result.package.bold());

    if result.signals.is_empty() {
        let _ = writeln!(w, "  {}", "No findings.".green());
        return;
    }

    for category in CATEGORY_ORDER {
        let group: Vec<&Signal> = result
            .signals
            .iter()
            .filter(|s| s.category == category)
            .collect();
        if group.is_empty() {
            continue;
        }

        let _ = writeln!(w, "  {}", category_header(category).bold());
        for signal in group {
            let _ = writeln!(
                w,
                "    {}  {}",
                signal.description,
                format!("({})", signal.id).dimmed()
            );
            if let Some(ref line) = signal.matched_line {
                let _ = writeln!(w, "      {} {}", "↳".dimmed(), line.yellow());
            }
        }
    }
}

/// The set of (trimmed) lines that triggered a finding, for source annotation.
pub fn flagged_lines(result: &ScanResult) -> HashSet<String> {
    result
        .signals
        .iter()
        .filter_map(|s| s.matched_line.as_ref().map(|l| l.trim().to_string()))
        .collect()
}

/// Print a source file with line numbers, marking the lines that triggered a
/// finding so you can see exactly what traur matched and in what context.
pub fn write_source(w: &mut dyn Write, label: &str, content: &str, flagged: &HashSet<String>) {
    let _ = writeln!(w, "\n  {} {}", "──".dimmed(), label.bold());
    for (i, line) in content.lines().enumerate() {
        let num = format!("{:>4}", i + 1);
        let trimmed = line.trim();
        if !trimmed.is_empty() && flagged.contains(trimmed) {
            let _ = writeln!(w, "  {} {} {}", num.dimmed(), "▶".red().bold(), line.yellow());
        } else {
            let _ = writeln!(w, "  {}   {}", num.dimmed(), line);
        }
    }
}

/// Print scan result as JSON.
pub fn print_json(result: &ScanResult) {
    let json = serde_json::to_string_pretty(result).expect("Failed to serialize");
    println!("{json}");
}
