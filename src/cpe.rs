//! CPE 2.3 construction for Windows inventory.
//!
//! Windows apps (registry / winget / Appx / Chocolatey / Scoop) and the OS
//! itself have no canonical Package-URL, so they are matched against NVD-derived
//! data via a best-effort CPE 2.3 formatted string. Everything here is pure and
//! fixture-tested — no host interaction — so it builds and tests on any platform.
//!
//! Philosophy (matches how mature scanners do it, e.g. Wazuh's `cpe_helper`):
//! a curated DisplayName → (vendor, product) table first, and emit **nothing**
//! when there's no confident mapping. A wrong CPE produces wrong CVE
//! attributions, which is worse than a gap the caller fills with `?search=`.

use crate::engine::WinOs;

/// Build an application CPE from an already-cleaned display name + version.
/// Returns `None` when the name isn't in the curated table (caller falls back to
/// `?search=`), so naive guesses never become false-positive CVE matches.
pub fn cpe_for_app(clean_name: &str, version: &str) -> Option<String> {
    let (vendor, product) = lookup_alias(clean_name)?;
    let ver = if version.trim().is_empty() {
        "*".to_string()
    } else {
        escape_cpe(&version.to_lowercase())
    };
    Some(format!(
        "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
        escape_cpe(vendor),
        escape_cpe(product),
        ver
    ))
}

/// Build the OS CPE for the running Windows. Always succeeds: the product token
/// and version are derived at detection time. `target_hw` carries the arch.
pub fn cpe_for_os(w: &WinOs) -> String {
    let product = if w.product.is_empty() {
        // Last-resort family when detection couldn't pin a feature update.
        if w.is_server { "windows_server".to_string() } else { "windows".to_string() }
    } else {
        w.product.clone()
    };
    let hw = if w.arch.is_empty() { "*" } else { &w.arch };
    format!(
        "cpe:2.3:o:microsoft:{}:{}:*:*:*:*:*:{}:*",
        escape_cpe(&product),
        escape_cpe(&w.version_string()),
        escape_cpe(hw)
    )
}

/// Map a Windows build number to its NVD CPE product token. `feature` is the
/// reported feature-update string (`23H2`, `2004`, …) used as the token suffix
/// when present; otherwise a build→suffix table fills it in. NVD moved to
/// feature-qualified product tokens (`windows_11_23h2`) with the full
/// `10.0.build.ubr` in the version field.
pub fn win_os_product(build: u32, is_server: bool, feature: &str) -> String {
    if is_server {
        let token = match build {
            n if n >= 26100 => "windows_server_2025",
            25398 => "windows_server_2022_23h2",
            n if n >= 20348 => "windows_server_2022",
            n if n >= 17763 => "windows_server_2019",
            n if n >= 14393 => "windows_server_2016",
            n if n >= 9600 => "windows_server_2012",
            _ => "windows_server",
        };
        return token.to_string();
    }

    let major = if build >= 22000 { "11" } else { "10" };
    let suffix = if !feature.trim().is_empty() {
        feature.trim().to_lowercase()
    } else {
        build_to_feature(build).to_string()
    };
    if suffix.is_empty() {
        format!("windows_{major}")
    } else {
        format!("windows_{major}_{suffix}")
    }
}

/// Fallback build→feature-update suffix when the registry didn't report one.
fn build_to_feature(build: u32) -> &'static str {
    match build {
        // Windows 11
        26100 => "24h2",
        22631 => "23h2",
        22621 => "22h2",
        22000 => "21h2",
        // Windows 10
        19045 => "22h2",
        19044 => "21h2",
        19043 => "21h1",
        19042 => "20h2",
        19041 => "2004",
        18363 => "1909",
        18362 => "1903",
        17763 => "1809",
        17134 => "1803",
        16299 => "1709",
        15063 => "1703",
        14393 => "1607",
        10240 => "1507",
        _ => "",
    }
}

/// Backslash-escape a value for the CPE 2.3 formatted-string binding (NISTIR
/// 7695 §6.2): spaces become `_`; the punctuation set and any literal `*`/`?`
/// are escaped; alphanumerics and `_ - .` pass through. Input is expected lower-
/// case already (vendor/product come from the table, versions are lowercased).
pub fn escape_cpe(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            ' ' => out.push('_'),
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' => out.push(c),
            // Everything else (incl. + : / @ ! and the wildcards) is escaped so
            // it is treated as a literal, never as an ANY/NA wildcard.
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// Strip version / architecture / locale / edition / marketing noise from a raw
/// registry or winget DisplayName, leaving a stable product phrase to look up
/// (and to use as the `?search=` term when unmapped). Conservative: only trims
/// trailing noise tokens, never interior words, so "7-Zip 23.01 (x64)" → "7-Zip"
/// but "Visual Studio Code" is untouched.
pub fn clean_app_name(raw: &str) -> String {
    // Drop any parenthesised suffix: "(x64)", "(64-bit)", "(en-US)", "(KB...)".
    let mut s = raw.trim();
    if let Some(idx) = s.find('(') {
        s = s[..idx].trim();
    }

    let tokens: Vec<&str> = s.split_whitespace().collect();
    // Trim trailing noise tokens (version-like, arch, locale, edition words).
    let mut end = tokens.len();
    while end > 0 && is_trailing_noise(tokens[end - 1]) {
        end -= 1;
    }
    let kept = if end == 0 { &tokens[..] } else { &tokens[..end] };
    kept.join(" ").trim().to_string()
}

fn is_trailing_noise(tok: &str) -> bool {
    let t = tok.trim_matches(|c: char| !c.is_alphanumeric());
    if t.is_empty() {
        return true;
    }
    let lower = t.to_lowercase();
    // Version-like: starts with a digit and is all digits/dots/punct.
    if t.chars().next().is_some_and(|c| c.is_ascii_digit())
        && t.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
    {
        return true;
    }
    // A leading 'v' version, e.g. v1.2.3.
    if lower.starts_with('v') && lower[1..].chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return true;
    }
    matches!(
        lower.as_str(),
        "x64" | "x86" | "x86_64" | "amd64" | "arm64" | "aarch64"
            | "32-bit" | "64-bit" | "win32" | "win64"
            | "edition" | "version" | "setup" | "installer" | "update" | "lts" | "stable"
    ) || is_locale(&lower)
}

fn is_locale(s: &str) -> bool {
    // e.g. en, en-us, zh-cn, pt-br
    let parts: Vec<&str> = s.split('-').collect();
    (parts.len() == 1 && parts[0].len() == 2 && parts[0].chars().all(|c| c.is_ascii_alphabetic()))
        || (parts.len() == 2
            && parts[0].len() == 2
            && parts[1].len() == 2
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_alphabetic())))
}

/// Curated DisplayName → (vendor, product) table. Keys are lowercase product
/// phrases matched as a prefix of the cleaned name (longest key first), so
/// "Mozilla Firefox" and "Mozilla Firefox ESR" both resolve correctly. Values
/// are the real NVD vendor:product pairs (stored unescaped; escaped at emit).
const ALIASES: &[(&str, &str, &str)] = &[
    // key (lowercase prefix), vendor, product
    ("google chrome", "google", "chrome"),
    ("mozilla firefox esr", "mozilla", "firefox_esr"),
    ("mozilla firefox", "mozilla", "firefox"),
    ("mozilla thunderbird", "mozilla", "thunderbird"),
    ("microsoft edge", "microsoft", "edge_chromium"),
    ("microsoft visual studio code", "microsoft", "visual_studio_code"),
    ("visual studio code", "microsoft", "visual_studio_code"),
    ("microsoft office", "microsoft", "office"),
    ("microsoft teams", "microsoft", "teams"),
    ("notepad++", "notepad-plus-plus", "notepad++"),
    ("7-zip", "7-zip", "7-zip"),
    ("winrar", "rarlab", "winrar"),
    ("adobe acrobat reader", "adobe", "acrobat_reader_dc"),
    ("adobe acrobat", "adobe", "acrobat_dc"),
    ("oracle vm virtualbox", "oracle", "vm_virtualbox"),
    ("virtualbox", "oracle", "vm_virtualbox"),
    ("java", "oracle", "java_se"),
    ("python", "python", "python"),
    ("node.js", "nodejs", "node.js"),
    ("nodejs", "nodejs", "node.js"),
    ("git", "git-scm", "git"),
    ("vlc media player", "videolan", "vlc_media_player"),
    ("vlc", "videolan", "vlc_media_player"),
    ("wireshark", "wireshark", "wireshark"),
    ("openssl", "openssl", "openssl"),
    ("openvpn", "openvpn", "openvpn"),
    ("putty", "putty", "putty"),
    ("filezilla", "filezilla-project", "filezilla_client"),
    ("apache tomcat", "apache", "tomcat"),
    ("nginx", "nginx", "nginx"),
    ("zoom", "zoom", "meetings"),
    ("docker desktop", "docker", "desktop"),
    ("curl", "curl", "curl"),
    ("gimp", "gimp", "gimp"),
    ("audacity", "audacityteam", "audacity"),
    ("postgresql", "postgresql", "postgresql"),
    ("mysql", "oracle", "mysql"),
    ("mariadb", "mariadb", "mariadb"),
    ("php", "php", "php"),
    ("teamviewer", "teamviewer", "teamviewer"),
    ("foxit reader", "foxit", "reader"),
    ("foxit pdf reader", "foxit", "pdf_reader"),
    ("greenshot", "greenshot", "greenshot"),
];

/// Resolve a cleaned display name to an NVD (vendor, product). Prefix match,
/// longest key first, with a word boundary so "git" matches "Git" / "Git 2.x"
/// but not "GitHub Desktop".
fn lookup_alias(clean_name: &str) -> Option<(&'static str, &'static str)> {
    let name = clean_name.trim().to_lowercase();
    if name.is_empty() {
        return None;
    }
    // ALIASES is authored roughly specific→general; pick the longest matching key
    // to avoid a short key shadowing a more specific one.
    let mut best: Option<(usize, &'static str, &'static str)> = None;
    for (key, vendor, product) in ALIASES {
        if prefix_word_match(&name, key) {
            let klen = key.len();
            if best.map(|(b, _, _)| klen > b).unwrap_or(true) {
                best = Some((klen, vendor, product));
            }
        }
    }
    best.map(|(_, v, p)| (v, p))
}

/// True when `key` is a prefix of `name` ending on a word boundary (end of
/// string or a non-alphanumeric char). Prevents "git" from matching "github".
fn prefix_word_match(name: &str, key: &str) -> bool {
    if !name.starts_with(key) {
        return false;
    }
    match name[key.len()..].chars().next() {
        None => true,
        Some(c) => !c.is_alphanumeric(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_formatted_string_specials() {
        assert_eq!(escape_cpe("notepad++"), "notepad\\+\\+");
        assert_eq!(escape_cpe("node.js"), "node.js");
        assert_eq!(escape_cpe("7-zip"), "7-zip");
        assert_eq!(escape_cpe("vlc media player"), "vlc_media_player");
        assert_eq!(escape_cpe("a:b/c@d"), "a\\:b\\/c\\@d");
    }

    #[test]
    fn cleans_display_names() {
        assert_eq!(clean_app_name("7-Zip 23.01 (x64)"), "7-Zip");
        assert_eq!(clean_app_name("Mozilla Firefox (x64 en-US)"), "Mozilla Firefox");
        assert_eq!(clean_app_name("Python 3.12.1 (64-bit)"), "Python");
        assert_eq!(clean_app_name("Google Chrome"), "Google Chrome");
        assert_eq!(clean_app_name("Microsoft Visual Studio Code"), "Microsoft Visual Studio Code");
        assert_eq!(clean_app_name("Git version 2.43.0"), "Git");
        assert_eq!(clean_app_name("VLC media player 3.0.20"), "VLC media player");
    }

    #[test]
    fn app_cpe_from_alias() {
        assert_eq!(
            cpe_for_app("Google Chrome", "120.0.6099.130"),
            Some("cpe:2.3:a:google:chrome:120.0.6099.130:*:*:*:*:*:*:*".into())
        );
        assert_eq!(
            cpe_for_app("Notepad++", "8.6.2"),
            Some("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6.2:*:*:*:*:*:*:*".into())
        );
        assert_eq!(
            cpe_for_app("7-Zip", "23.01"),
            Some("cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*".into())
        );
        // Empty version → ANY in the version field.
        assert_eq!(
            cpe_for_app("Wireshark", ""),
            Some("cpe:2.3:a:wireshark:wireshark:*:*:*:*:*:*:*:*".into())
        );
    }

    #[test]
    fn unmapped_app_returns_none() {
        assert_eq!(cpe_for_app("Some Internal LOB Tool", "1.0"), None);
        // Word boundary: a more specific product must not be shadowed by "git".
        assert_eq!(cpe_for_app("GitHub Desktop", "3.3.6"), None);
    }

    #[test]
    fn longest_alias_wins() {
        // "Mozilla Firefox ESR" must beat the "Mozilla Firefox" prefix.
        assert_eq!(
            cpe_for_app("Mozilla Firefox ESR", "115.6.0"),
            Some("cpe:2.3:a:mozilla:firefox_esr:115.6.0:*:*:*:*:*:*:*".into())
        );
    }

    #[test]
    fn os_product_tokens() {
        assert_eq!(win_os_product(22631, false, "23H2"), "windows_11_23h2");
        assert_eq!(win_os_product(19045, false, "22H2"), "windows_10_22h2");
        assert_eq!(win_os_product(19045, false, ""), "windows_10_22h2"); // build fallback
        assert_eq!(win_os_product(20348, true, ""), "windows_server_2022");
        assert_eq!(win_os_product(17763, true, ""), "windows_server_2019");
        assert_eq!(win_os_product(26100, true, ""), "windows_server_2025");
        assert_eq!(win_os_product(22000, false, ""), "windows_11_21h2");
    }

    #[test]
    fn os_cpe_full_string() {
        let w = WinOs {
            product: "windows_11_23h2".into(),
            display_name: "Windows 11 Pro".into(),
            feature: "23H2".into(),
            build: 22631,
            ubr: 3155,
            is_server: false,
            edition: "Professional".into(),
            arch: "x64".into(),
        };
        assert_eq!(
            cpe_for_os(&w),
            "cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.3155:*:*:*:*:*:x64:*"
        );
    }
}
