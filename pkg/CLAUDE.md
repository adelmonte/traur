# Package

Local Arch packaging for this fork. Follows [Rust package guidelines](https://wiki.archlinux.org/title/Rust_package_guidelines).

## PKGBUILD

- `PKGBUILD` — `traur-findings-git`, built from `github.com/adelmonte/traur` HEAD.
  `provides=(traur)` and `conflicts=(traur traur-bin)` so it replaces upstream's
  AUR packages; the distinct name keeps AUR helpers from mistaking it for
  upstream `traur`. Not published to the AUR.

Install / update:

```bash
cd pkg && makepkg -si
```

## Installed files

| File | Path |
|------|------|
| CLI binary | `/usr/bin/traur` |
| makepkg wrapper (inactive until `traur wrapper --enable`) | `/usr/share/traur/makepkg` |
| Pattern DB | `/usr/share/traur/patterns.toml` |
| License | `/usr/share/licenses/traur-findings-git/LICENSE` |
