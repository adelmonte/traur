//! Small text helpers shared across features.

/// Blank out full-line shell comments so patterns don't match commented-out
/// code (e.g. `# modprobe configs` should not trip a kernel-module signal).
///
/// Only whole-line comments (first non-whitespace char is `#`) are removed;
/// lines are blanked rather than deleted so line positions — and therefore the
/// reported matched line — stay intact. Inline `#` is left alone, since `#` is
/// valid mid-line shell syntax (`${v#x}`, `${#a[@]}`).
pub fn strip_comment_lines(content: &str) -> String {
    content
        .lines()
        .map(|line| if line.trim_start().starts_with('#') { "" } else { line })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blanks_comment_lines_keeps_code() {
        let input = "code1\n  # a comment\ncode2\n";
        let out = strip_comment_lines(input);
        assert_eq!(out, "code1\n\ncode2");
    }

    #[test]
    fn leaves_inline_hash_alone() {
        let input = "x=${v#prefix}\n";
        assert_eq!(strip_comment_lines(input), "x=${v#prefix}");
    }
}
