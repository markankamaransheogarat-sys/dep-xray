//! Tree-sitter AST behavioral analyzer for Rust source files.

use crate::analyzer::entropy::{
    is_suspicious_encoded_literal, match_hardcoded_network_target, match_sensitive_path,
};
use crate::diff::ChangedFile;
use crate::types::{CapabilityCategory, Ecosystem, Finding, PackageChange, Severity};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

fn overlaps_added_lines(node: Node<'_>, added_lines: &BTreeSet<usize>) -> bool {
    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    added_lines.range(start_line..=end_line).next().is_some()
}

fn node_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn line_snippet(src: &str, line_1_based: usize) -> String {
    src.lines()
        .nth(line_1_based.saturating_sub(1))
        .unwrap_or("")
        .trim()
        .chars()
        .take(160)
        .collect()
}

fn strip_rust_string_quotes(raw: &str) -> &str {
    if let Some(s) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return s;
    }
    if raw.starts_with('r') {
        let after_r = raw.trim_start_matches('r');
        let hashes = after_r.chars().take_while(|&c| c == '#').count();
        let prefix = format!("{}\"", "#".repeat(hashes));
        let suffix = format!("\"{}", "#".repeat(hashes));
        if let Some(inner) = after_r
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(&suffix))
        {
            return inner;
        }
    }
    raw
}

/// Analyzes added/modified AST nodes in a Rust file.
pub fn analyze_rust_file(change: &PackageChange, file: &ChangedFile) -> Vec<Finding> {
    let mut parser = Parser::new();
    let language = tree_sitter_rust::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(&file.new_content, None) else {
        return Vec::new();
    };

    let is_build_rs = file.path == "build.rs" || file.path.ends_with("/build.rs");
    let src_bytes = file.new_content.as_bytes();
    let mut findings = Vec::new();
    let mut cursor = tree.walk();

    visit_node(
        &mut cursor,
        change,
        file,
        src_bytes,
        is_build_rs,
        &mut findings,
    );

    if is_build_rs && findings.is_empty() && !file.added_lines.is_empty() {
        let first_line = *file.added_lines.iter().next().unwrap_or(&1);
        findings.push(Finding {
            id: "DX001".to_string(),
            package_name: change.name.clone(),
            package_version: change.new_version.clone(),
            ecosystem: Ecosystem::Cargo,
            file_path: file.path.clone(),
            line: first_line,
            column: 1,
            severity: Severity::Medium,
            category: CapabilityCategory::ExecutionHook,
            title: "Modified or added `build.rs` script".to_string(),
            description: "`build.rs` executes arbitrary Rust code at compile time.".to_string(),
            snippet: line_snippet(&file.new_content, first_line),
            is_new_package: change.is_new(),
        });
    }

    findings
}

fn visit_node(
    cursor: &mut tree_sitter::TreeCursor<'_>,
    change: &PackageChange,
    file: &ChangedFile,
    src: &[u8],
    is_build_rs: bool,
    findings: &mut Vec<Finding>,
) {
    let node = cursor.node();
    let kind = node.kind();

    // Skip comments and subtrees that do not touch any added lines.
    if kind == "line_comment" || kind == "block_comment" {
        return;
    }
    if !overlaps_added_lines(node, &file.added_lines) {
        return;
    }

    let line = node.start_position().row + 1;
    let col = node.start_position().column + 1;
    let text = node_text(node, src);

    let mut make_finding = |id: &str,
                            severity: Severity,
                            category: CapabilityCategory,
                            title: &str,
                            description: &str| {
        findings.push(Finding {
            id: id.to_string(),
            package_name: change.name.clone(),
            package_version: change.new_version.clone(),
            ecosystem: Ecosystem::Cargo,
            file_path: file.path.clone(),
            line,
            column: col,
            severity,
            category,
            title: title.to_string(),
            description: description.to_string(),
            snippet: line_snippet(&file.new_content, line),
            is_new_package: change.is_new(),
        });
    };

    match kind {
        "unsafe_block" => {
            make_finding(
                "DX010",
                Severity::High,
                CapabilityCategory::UnsafeDynamic,
                "New `unsafe` block",
                "Introduces an `unsafe` block that bypasses Rust memory-safety guarantees.",
            );
        }
        "function_modifiers" if text.split_whitespace().any(|w| w == "unsafe") => {
            make_finding(
                "DX010",
                Severity::High,
                CapabilityCategory::UnsafeDynamic,
                "New `unsafe` function",
                "Declares an `unsafe fn`.",
            );
        }
        "use_declaration" | "scoped_identifier" | "call_expression" => {
            if text.contains("process::Command") {
                let sev = if is_build_rs {
                    Severity::Critical
                } else {
                    Severity::High
                };
                make_finding(
                    "DX003",
                    sev,
                    CapabilityCategory::ExecutionHook,
                    "Process execution via `Command`",
                    "Spawns external OS processes via `process::Command`.",
                );
            }
            if text.contains("reqwest::")
                || text.contains("ureq::")
                || text.contains("TcpStream")
                || text.contains("UdpSocket")
                || text.contains("hyper::Client")
            {
                let sev = if is_build_rs {
                    Severity::Critical
                } else {
                    Severity::High
                };
                make_finding(
                    "DX005",
                    sev,
                    CapabilityCategory::Network,
                    "Network client or socket usage",
                    "Uses HTTP client or raw TCP/UDP socket APIs.",
                );
            }
            if text.contains("env::var") || text.contains("env::vars") {
                let sev = if is_build_rs {
                    Severity::Critical
                } else {
                    Severity::Medium
                };
                make_finding(
                    "DX008",
                    sev,
                    CapabilityCategory::SensitiveRead,
                    "Environment variable read (`std::env::var`)",
                    "Reads runtime or build-time environment variables.",
                );
            }
            if text.contains("mem::transmute") || text.contains("transmute_copy") {
                make_finding(
                    "DX010",
                    Severity::High,
                    CapabilityCategory::UnsafeDynamic,
                    "Unsafe type reinterpretation (`transmute`)",
                    "Uses `std::mem::transmute` for raw bit-level reinterpretation.",
                );
            }
        }
        "macro_invocation" => {
            if text.starts_with("env!") || text.starts_with("option_env!") {
                let sev = if is_build_rs {
                    Severity::High
                } else {
                    Severity::Medium
                };
                make_finding(
                    "DX008",
                    sev,
                    CapabilityCategory::SensitiveRead,
                    "Compile-time environment variable read (`env!`)",
                    "Captures environment variable values into the compiled binary.",
                );
            }
        }
        "string_literal" | "raw_string_literal" => {
            let inner = strip_rust_string_quotes(text);
            if let Some(pat) = match_sensitive_path(inner) {
                make_finding(
                    "DX009",
                    Severity::Critical,
                    CapabilityCategory::SensitiveRead,
                    &format!("Sensitive credential path reference (`{pat}`)"),
                    "References a sensitive credential, key, or environment file path.",
                );
            } else if is_suspicious_encoded_literal(inner) {
                make_finding(
                    "DX012",
                    Severity::High,
                    CapabilityCategory::Obfuscation,
                    "High-entropy encoded string literal",
                    "Contains a long high-entropy base64/hex string literal.",
                );
            } else if let Some(target) = match_hardcoded_network_target(inner) {
                let sev = if is_build_rs {
                    Severity::High
                } else {
                    Severity::Medium
                };
                make_finding(
                    "DX007",
                    sev,
                    CapabilityCategory::Network,
                    &format!("Hardcoded network target (`{target}`)"),
                    "Contains a hardcoded external URL or IPv4 address in source code.",
                );
            }
        }
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, change, file, src, is_build_rs, findings);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}
