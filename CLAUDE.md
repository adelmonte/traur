# traur - Findings-based security scanner for AUR PKGBUILDs

Reports the security-relevant findings in an AUR package. No trust score, no
tiers, no ALPM hook, no automatic blocking — it lists what it found and (via the
makepkg wrapper) asks before building.

## Architecture

Feature-based with coordinator pattern:

```
PackageContext (pkgbuild + .install + optional metadata/git)
  -> Coordinator runs all Features
  -> Each Feature returns Vec<Signal>   (a "Signal" is one finding)
  -> ScanResult { package, signals }    (flat list, no score/tier)
```

**Features** (`src/features/`): Self-contained analysis modules, each implementing the `Feature` trait. Each detects specific findings and returns `Vec<Signal>`.

**Shared** (`src/shared/`): Reusable components (AUR RPC client, cgit PKGBUILD fetcher, GitHub API client, AUR comments scraper, local-git read helpers, known-malicious list check, pattern loader, config, output).

**Coordinator** (`src/coordinator.rs`): Orchestrates features and assembles the flat `ScanResult`.

## Scan modes

- **Offline / local** (`scan --pkgbuild <path>`, and the makepkg wrapper):
  reads the local PKGBUILD + `.install`, and diffs against the local `.git` if
  present. No network — cannot hang.
- **Online by name** (`scan <package>`): fetches PKGBUILD + `.install` over HTTP
  from AUR cgit (no clone, no cache), plus metadata/maintainer/GitHub/comments
  and the known-malicious-list check. Adds findings the offline path can't see.

`Signal` retains inert `points`/`is_override_gate` fields (still populated by
some features) but they no longer affect anything and are not serialized.

## Build

```bash
cargo build --release
```

Single binary: `target/release/traur`.

## makepkg wrapper

`contrib/makepkg-traur` is the wrapper script, installed to
`/usr/share/traur/makepkg`. `traur wrapper --enable` symlinks it into
`/usr/local/bin/makepkg` so it shadows `/usr/bin/makepkg` in PATH and scans
PKGBUILDs (offline) before yay/paru builds them. `--disable` removes the
symlink; bare `traur wrapper` reports status.

## Adding a new feature

1. Create `src/features/your_feature/` with `mod.rs` and `CLAUDE.md`
2. Implement the `Feature` trait (return `Vec<Signal>` from `analyze()`)
3. Register in `src/features/mod.rs` (`all_features()`)
4. If pattern-based, add rules to `data/patterns.toml`

Network-dependent features must no-op when their inputs are absent (e.g.
`ctx.metadata.is_none()`), so the offline/wrapper path stays offline.

## Adding new detection patterns

Edit `data/patterns.toml`. Each pattern has: `id`, `pattern` (regex), `description`, and legacy `points`/`override_gate` fields (parsed but unused). Patterns are grouped by feature section name.

## Key files

| File | Purpose |
|------|---------|
| `src/coordinator.rs` | Orchestrates features; builds context (HTTP online / local offline); returns flat `ScanResult` |
| `src/features/mod.rs` | Feature trait + registry |
| `src/shared/scoring.rs` | `Signal` (a finding), `SignalCategory`, `ScanResult` — no scoring logic |
| `src/shared/aur_rpc.rs` | AUR RPC v5 API client |
| `src/shared/aur_fetch.rs` | Fetch PKGBUILD + `.install` over HTTP from cgit (no clone/cache) |
| `src/shared/aur_git.rs` | Read helpers for a *local* repo (PKGBUILD/.install/git log/diff) |
| `src/shared/malicious_list.rs` | Known-compromised list check (online, cached, fail-open) |
| `src/shared/bulk.rs` | Batch metadata fetch, maintainer prefetch, fetch-with-retry |
| `src/features/shell_analysis/` | Beyond-regex static analysis (also over `.install`, IS- prefix) |
| `src/features/gtfobins_analysis/` | GTFOBins-derived patterns (also over `.install`, IS- prefix) |
| `src/features/pkgbuild_diff_analysis/` | PKGBUILD diff vs prior revision (local git only) |
| `src/shared/github.rs` | GitHub API client (star count, repo existence) |
| `src/shared/aur_comments.rs` | AUR package page comment scraper |
| `src/shared/signal_registry.rs` | Central registry of all signal definitions (pattern + hardcoded) |
| `src/shared/config.rs` | User config: whitelist, ignored signals/categories |
| `data/patterns.toml` | Regex pattern database |
| `contrib/makepkg-traur` | Offline makepkg wrapper (shipped, opt-in) |
