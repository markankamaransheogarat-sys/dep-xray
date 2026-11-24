//! Behavioral AST & capability analyzer orchestrator.

pub mod entropy;
pub mod js_ast;
pub mod manifest;
pub mod rust_ast;

use crate::diff::{ChangedFile, PackageDiff};
use crate::types::{CapabilityCategory, Finding, PackageChange, Severity};
use std::collections::BTreeMap;

fn is_source_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".rs")
        || lower.ends_with(".js")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
        || lower.ends_with(".jsx")
        || lower.ends_with(".ts")
        || lower.ends_with(".mts")
        || lower.ends_with(".cts")
        || lower.ends_with(".tsx")
}

fn is_package_json(path: &str) -> bool {
    path == "package.json" || path.ends_with("/package.json")
}

fn is_cargo_toml(path: &str) -> bool {
    path == "Cargo.toml" || path.ends_with("/Cargo.toml")
}

fn check_hidden_unicode(change: &PackageChange, file: &ChangedFile) -> Vec<Finding> {
    let mut findings = Vec::new();
    for &line_num in &file.added_lines {
        if let Some(line_text) = file.new_content.lines().nth(line_num.saturating_sub(1))
            && let Some((col, ch)) = entropy::find_hidden_unicode(line_text)
        {
            findings.push(Finding {
                id: "DX014".to_string(),
                package_name: change.name.clone(),
                package_version: change.new_version.clone(),
                ecosystem: change.ecosystem,
                file_path: file.path.clone(),
                line: line_num,
                column: col,
                severity: Severity::Critical,
                category: CapabilityCategory::Obfuscation,
                title: format!("Hidden Unicode character (`U+{:04X}`)", ch as u32),
                description: "Contains invisible or bidirectional override Unicode characters (potential Trojan Source).".to_string(),
                snippet: line_text.trim().chars().take(160).collect(),
                is_new_package: change.is_new(),
            });
        }
    }
    findings
}

/// Analyzes all changed/added files in a `PackageDiff` and returns deduplicated findings.
pub fn analyze_package_diff(change: &PackageChange, diff: &PackageDiff) -> Vec<Finding> {
    let mut raw_findings = Vec::new();

    for file in &diff.changed_files {
        if is_package_json(&file.path) {
            raw_findings.extend(manifest::analyze_package_json(change, file));
            continue;
        }
        if is_cargo_toml(&file.path) {
            raw_findings.extend(manifest::analyze_cargo_toml(change, file));
            continue;
        }
        if !is_source_file(&file.path) {
            continue;
        }

        raw_findings.extend(check_hidden_unicode(change, file));

        if file.path.ends_with(".rs") {
            raw_findings.extend(rust_ast::analyze_rust_file(change, file));
        } else {
            raw_findings.extend(js_ast::analyze_js_file(change, file));
        }
    }

    // Deduplicate by (id, file_path, line), keeping the highest severity if duplicated.
    let mut deduped: BTreeMap<(String, String, usize), Finding> = BTreeMap::new();
    for finding in raw_findings {
        let key = (finding.id.clone(), finding.file_path.clone(), finding.line);
        match deduped.get_mut(&key) {
            Some(existing) => {
                if finding.severity > existing.severity {
                    *existing = finding;
                }
            }
            None => {
                deduped.insert(key, finding);
            }
        }
    }

    let mut result: Vec<Finding> = deduped.into_values().collect();
    result.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line.cmp(&b.line))
    });
    result
}
