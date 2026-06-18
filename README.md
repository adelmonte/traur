# traur

A findings-based security scanner for AUR PKGBUILDs, written in Rust. It
analyzes PKGBUILDs, `.install` scripts, source URLs, metadata, and git history
and reports the security-relevant **findings** it detects — no opaque trust
score, no tiers, no automatic blocking. You decide what the findings mean.

It can also wrap `makepkg` so that every AUR build (via yay/paru) is scanned
**offline** before it runs.

## Installation

```bash
paru -S traur
```

## Usage

```bash
traur scan <package>                 # fetch a package's PKGBUILD over HTTP and scan it
traur scan                           # scan all installed AUR packages
traur scan --pkgbuild ./PKGBUILD     # scan a local PKGBUILD (offline)
traur scan --pkgbuild ./PKGBUILD --source  # ...and print the PKGBUILD with flagged lines highlighted
traur ignore <SIGNAL-ID>             # suppress a specific finding
traur signals                        # list every finding traur can emit
```

Scanning a package by name pulls just the PKGBUILD and `.install` over HTTP from
AUR's cgit — nothing is cloned and no cache is kept on disk.

## makepkg wrapper

Scan PKGBUILDs automatically right before yay/paru builds them:

```bash
sudo traur wrapper --enable      # symlink the wrapper into /usr/local/bin/makepkg
traur wrapper                    # show status
sudo traur wrapper --disable     # remove it
```

The wrapper scans the local PKGBUILD/`.install` **offline** (it reads the files
the helper already downloaded), prints the findings, then asks before building
(`[Y/n]`, default yes; auto-proceeds when run non-interactively). Because it
never touches the network during a build, it cannot stall an install.

## How it works

Independent features each emit the findings they detect:

| Feature | What it checks |
|---------|---------------|
| PKGBUILD analysis | Dangerous shell code |
| Install script analysis | Suspicious `.install` hooks |
| Source URL analysis | Untrusted source domains |
| Checksum analysis | Missing, skipped, or weak checksums |
| Shell analysis | Beyond-regex obfuscation (var concat, indirect exec, data blobs) — also over `.install` |
| GTFOBins analysis | Legitimate binary abuse — also over `.install` |
| Bin source verification | `-bin` package source domain vs upstream URL mismatch |
| Metadata analysis | AUR votes, popularity, maintainer status (online) |
| Name analysis | Typosquatting and brand impersonation |
| Maintainer analysis | New accounts, batch uploads (online) |
| Orphan takeover analysis | Submitter != maintainer, orphan takeover patterns (online) |
| Git history analysis | New network code, author changes (local git) |
| GitHub stars | Upstream repo missing or unpopular (online) |
| AUR comments analysis | Security warnings in recent comments (online) |
| Known-malicious list | Package appears on Arch's compromised-package list (online) |

Features marked *(online)* only run when scanning a package by name; the
offline wrapper / `--pkgbuild` path runs the file-based and local-git checks
only. *(local git)* features run when a `.git` is present (the helper's build
dir).

## Detection coverage

Patterns derived from real AUR malware incidents:
- **CHAOS RAT (2025)** — browser impersonation packages, RAT distribution
- **Google Chrome RAT (2025)** — `.install` script, Python download+execute
- **Acroread (2018)** — orphan takeover, curl from paste service, systemd persistence

Categories: download-and-execute, reverse shells, credential theft, persistence
mechanisms, privilege escalation, C2/exfiltration, cryptocurrency mining, code
obfuscation, kernel module loading, environment variable theft, system
reconnaissance.

## License

MIT
