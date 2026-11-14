//! Shannon entropy, encoded payload heuristics, and hidden Unicode detection.

/// Computes Shannon entropy in bits per character for `s`.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Returns true if `s` looks like a high-entropy base64 or hex encoded payload.
pub fn is_suspicious_encoded_literal(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < 40 {
        return false;
    }
    // Ignore URLs, file paths, or whitespace-separated prose.
    if trimmed.contains(' ') || trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return false;
    }

    let is_base64_like = trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    let is_hex_like = trimmed.len() >= 48 && trimmed.bytes().all(|b| b.is_ascii_hexdigit());

    if !is_base64_like && !is_hex_like {
        return false;
    }

    let entropy = shannon_entropy(trimmed);
    (is_base64_like && entropy >= 4.5) || (is_hex_like && entropy >= 3.5)
}

/// Checks whether a line contains invisible, zero-width, or bidirectional override Unicode characters.
pub fn find_hidden_unicode(line: &str) -> Option<(usize, char)> {
    for (idx, ch) in line.char_indices() {
        let suspicious = matches!(
            ch,
            '\u{200B}' // Zero Width Space
            | '\u{200C}' // Zero Width Non-Joiner
            | '\u{200D}' // Zero Width Joiner
            | '\u{200E}' // Left-To-Right Mark
            | '\u{200F}' // Right-To-Left Mark
            | '\u{202A}'..='\u{202E}' // Bidi embeddings / overrides (Trojan Source)
            | '\u{2066}'..='\u{2069}' // Bidi isolates
            | '\u{FEFF}' // BOM / Zero Width No-Break Space
        );
        if suspicious {
            return Some((idx + 1, ch));
        }
    }
    None
}

/// Checks if a string literal contains a sensitive credential path or secret file reference.
pub fn match_sensitive_path(s: &str) -> Option<&'static str> {
    let lower = s.to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        ".ssh/",
        ".ssh\\",
        "id_rsa",
        "id_ed25519",
        ".aws/credentials",
        ".aws\\credentials",
        ".npmrc",
        ".cargo/credentials",
        ".cargo\\credentials",
        "/etc/passwd",
        "/etc/shadow",
    ];
    for pat in PATTERNS {
        if lower.contains(pat) {
            return Some(pat);
        }
    }
    if lower == ".env" || lower.ends_with("/.env") || lower.ends_with("\\.env") {
        return Some(".env");
    }
    None
}

/// Checks if a string literal contains a suspicious hardcoded IPv4 address or non-standard URL.
pub fn match_hardcoded_network_target(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let host = trimmed
            .split("://")
            .nth(1)
            .unwrap_or("")
            .split(['/', ':', '?', '#'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        const BENIGN_HOSTS: &[&str] = &[
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "example.com",
            "example.org",
            "schema.org",
            "www.w3.org",
            "github.com",
            "crates.io",
            "docs.rs",
            "registry.npmjs.org",
            "nodejs.org",
            "rust-lang.org",
        ];
        if !host.is_empty()
            && !BENIGN_HOSTS
                .iter()
                .any(|b| host == *b || host.ends_with(&format!(".{b}")))
        {
            return Some(trimmed.chars().take(80).collect());
        }
    }

    // Check for raw IPv4 address (e.g. "45.33.32.156:4444").
    for token in trimmed.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
            && token != "127.0.0.1"
            && token != "0.0.0.0"
            && !token.starts_with("192.168.")
            && !token.starts_with("10.")
        {
            return Some(token.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_high_entropy_base64() {
        let payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS5jb20vc2guc2ggfCBzaA==";
        assert!(is_suspicious_encoded_literal(payload));
        assert!(!is_suspicious_encoded_literal(
            "hello_world_this_is_a_normal_string_constant"
        ));
    }

    #[test]
    fn detects_hidden_bidi_unicode() {
        let line = "let is_admin = false; // \u{202E}evil";
        assert!(find_hidden_unicode(line).is_some());
    }
}
