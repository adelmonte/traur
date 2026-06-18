# Changelog

## 0.5.0

Major rework (this fork): traur is now a **findings reporter**, not a trust
scorer. It lists the security-relevant findings in a package and lets you
decide — no score, no tiers, no automatic blocking.

### Changed
- Output is a flat, color-coded list of findings **grouped by category**
  (Pkgbuild / Behavioral / Temporal / Metadata); each finding shows the line
  that triggered it.
- `scan <name>` now fetches the PKGBUILD and `.install` over HTTP from AUR's
  cgit instead of cloning the repo. traur keeps **no on-disk cache** of its own.
- Local/offline scans (`--pkgbuild`, the wrapper) read on-disk files and diff
  against the local `.git` when present.

### Removed
- The 0–100 trust score, the tiers (TRUSTED…MALICIOUS), category weights, and
  override-gates.
- The ALPM pre-transaction hook (`traur-hook` binary and `traur.hook`).
- The `allow` / whitelist feature.
- The `bench` subcommand and the obsolete metadata-dump cache (`flate2`,
  `MetaDumpPackage`, `~/.cache/traur`).

### Added
- Offline `makepkg` wrapper (`contrib/makepkg-traur`) plus
  `traur wrapper --enable/--disable/--status`. It scans the local
  PKGBUILD/`.install` before yay/paru builds (once, on the `--verifysource`
  pass) and never touches the network during a build, so it cannot stall an
  install. Prompt is `[Y/n/d/p]` — `d` shows the update's git diff, `p` shows
  the PKGBUILD/`.install` with the flagged lines highlighted.
- `traur scan --pkgbuild <path> --source` prints the PKGBUILD/`.install` with
  the flagged lines highlighted.
- Known-malicious-list check (`B-KNOWN-MALICIOUS`): online only, short timeout,
  cached, fails open.
- `.install` scripts are now run through the shell and GTFOBins analyses
  (`IS-`-prefixed findings), not just pattern matching.

### Fixed
- Patterns no longer match commented-out code — whole-line `#` comments are
  stripped before matching (e.g. `# modprobe configs` no longer trips a
  kernel-module finding).
- `P-CHECKSUM-MISMATCH` no longer fires on source arrays built with
  `name+=(...)` appends (common in kernel PKGBUILDs).
- AUR comment parser now matches the content div regardless of attribute order
  (`id` before `class`), so comment-based warnings are actually detected
  (issue #15).
