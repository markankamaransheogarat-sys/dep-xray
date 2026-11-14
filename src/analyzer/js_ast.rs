//! Tree-sitter AST behavioral analyzer for JavaScript and TypeScript files.

use crate::analyzer::entropy::{
    is_suspicious_encoded_literal, match_hardcoded_network_target, match_sensitive_path,
};
use crate::diff::ChangedFile;
use crate::types::{CapabilityCategory, Ecosystem, Finding, PackageChange, Severity};
use std::collections::BTreeSet;
use tree_sitter::{Language, Node, Parser};

fn language_for_path(path: &str) -> Option<Language> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".tsx") {
        Some(tree_sitter_typescript::LANGUAGE_TSX.into())
    } else if lower.ends_with(".ts") || lower.ends_with(".mts") || lower.ends_with(".cts") {
        Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
    } else if lower.ends_with(".js")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
        || lower.ends_with(".jsx")
    {
        Some(tree_sitter_javascript::LANGUAGE.into())
    } else {
        None
    }
}

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

fn strip_js_quotes(raw: &str) -> &str {
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\''))
            || (raw.starts_with('`') && raw.ends_with('`')))
    {
        return &raw[1..raw.len() - 1];
    }
    raw
}

/// Analyzes added/modified AST nodes in a JS/TS/JSX/TSX file.
pub fn analyze_js_file(change: &PackageChange, file: &ChangedFile) -> Vec<Finding> {
    let Some(language) = language_for_path(&file.path) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(&file.new_content, None) else {
        return Vec::new();
    };

    let src_bytes = file.new_content.as_bytes();
    let mut findings = Vec::new();
    let mut cursor = tree.walk();

    visit_node(&mut cursor, change, file, src_bytes, &mut findings);

    // Escalate base64 decoding + eval/exec combinations in the same file to CRITICAL.
    let has_decode = findings.iter().any(|f| f.id == "DX013");
    let has_exec_or_eval = findings.iter().any(|f| f.id == "DX011" || f.id == "DX004");
    if has_decode && has_exec_or_eval {
        for f in &mut findings {
            if f.id == "DX013" || f.id == "DX011" {
                f.severity = Severity::Critical;
            }
        }
    }

    findings
}

fn visit_node(
    cursor: &mut tree_sitter::TreeCursor<'_>,
    change: &PackageChange,
    file: &ChangedFile,
    src: &[u8],
    findings: &mut Vec<Finding>,
) {
    let node = cursor.node();
    let kind = node.kind();

    if kind == "comment" {
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
            ecosystem: Ecosystem::Npm,
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
        "import_statement" => {
            if text.contains("child_process") {
                make_finding(
                    "DX004",
                    Severity::High,
                    CapabilityCategory::ExecutionHook,
                    "Imports `child_process`",
                    "Imports Node.js `child_process` module for OS command execution.",
                );
            }
        }
        "call_expression" => {
            let func_name = node
                .child_by_field_name("function")
                .map(|n| node_text(n, src))
                .unwrap_or("");
            let args_node = node.child_by_field_name("arguments");
            let args_text = args_node.map(|n| node_text(n, src)).unwrap_or("");

            if func_name == "eval" {
                make_finding(
                    "DX011",
                    Severity::High,
                    CapabilityCategory::UnsafeDynamic,
                    "Dynamic code execution (`eval()`)",
                    "Executes arbitrary JavaScript strings via `eval()`.",
                );
            } else if func_name == "require" {
                if args_text.contains("child_process") {
                    make_finding(
                        "DX004",
                        Severity::High,
                        CapabilityCategory::ExecutionHook,
                        "Loads `child_process` via `require()`",
                        "Loads Node.js `child_process` module for OS command execution.",
                    );
                } else if let Some(args) = args_node {
                    // Check if the first named argument is NOT a static string literal.
                    let first_named = (0..args.named_child_count())
                        .filter_map(|i| args.named_child(i))
                        .next();
                    if let Some(arg) = first_named
                        && arg.kind() != "string"
                    {
                        make_finding(
                            "DX011",
                            Severity::High,
                            CapabilityCategory::UnsafeDynamic,
                            "Dynamic `require()` with non-literal argument",
                            "Loads a module path computed at runtime.",
                        );
                    }
                }
            } else if matches!(
                func_name,
                "exec" | "execSync" | "spawn" | "spawnSync" | "execFile" | "execFileSync"
            ) || func_name.ends_with(".exec")
                || func_name.ends_with(".execSync")
                || func_name.ends_with(".spawn")
                || func_name.ends_with(".spawnSync")
            {
                make_finding(
                    "DX004",
                    Severity::High,
                    CapabilityCategory::ExecutionHook,
                    &format!("OS command execution (`{func_name}`)"),
                    "Spawns external shell or system processes.",
                );
            } else if func_name == "fetch"
                || func_name == "http.request"
                || func_name == "https.request"
                || func_name == "http.get"
                || func_name == "https.get"
                || func_name == "net.connect"
                || func_name == "net.createConnection"
                || func_name == "dgram.createSocket"
            {
                make_finding(
                    "DX006",
                    Severity::High,
                    CapabilityCategory::Network,
                    &format!("Outbound network call (`{func_name}`)"),
                    "Initiates outbound HTTP or raw socket connections.",
                );
            } else if func_name == "WebAssembly.instantiate"
                || func_name == "WebAssembly.instantiateStreaming"
            {
                make_finding(
                    "DX011",
                    Severity::High,
                    CapabilityCategory::UnsafeDynamic,
                    "Dynamic WebAssembly instantiation",
                    "Instantiates WebAssembly bytecode dynamically at runtime.",
                );
            } else if func_name == "atob"
                || (func_name == "Buffer.from"
                    && (args_text.contains("'base64'")
                        || args_text.contains("\"base64\"")
                        || args_text.contains("'hex'")
                        || args_text.contains("\"hex\"")))
            {
                make_finding(
                    "DX013",
                    Severity::High,
                    CapabilityCategory::Obfuscation,
                    &format!("Encoded payload decoding (`{func_name}`)"),
                    "Decodes base64 or hex data at runtime.",
                );
            }
        }
        "new_expression" => {
            let ctor = node
                .child_by_field_name("constructor")
                .map(|n| node_text(n, src))
                .unwrap_or("");
            if ctor == "Function" {
                make_finding(
                    "DX011",
                    Severity::High,
                    CapabilityCategory::UnsafeDynamic,
                    "Dynamic code generation (`new Function()`)",
                    "Constructs executable functions from runtime strings.",
                );
            } else if ctor == "WebSocket" {
                make_finding(
                    "DX006",
                    Severity::High,
                    CapabilityCategory::Network,
                    "WebSocket connection (`new WebSocket()`)",
                    "Opens a persistent bidirectional WebSocket connection.",
                );
            }
        }
        "member_expression" if text == "process.env" => {
            make_finding(
                "DX008",
                Severity::Medium,
                CapabilityCategory::SensitiveRead,
                "Environment variable access (`process.env`)",
                "Reads environment variables at runtime or install time.",
            );
        }
        "string" | "template_string" => {
            let inner = strip_js_quotes(text);
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
                make_finding(
                    "DX007",
                    Severity::Medium,
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
            visit_node(cursor, change, file, src, findings);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}
