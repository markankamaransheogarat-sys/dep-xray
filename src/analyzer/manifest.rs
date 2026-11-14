//! Manifest and build-script hook analysis (`package.json` lifecycle scripts and `build.rs`).

use crate::diff::ChangedFile;
use crate::types::{CapabilityCategory, Ecosystem, Finding, PackageChange, Severity};
use serde::Deserialize;
use std::collections::BTreeMap;

const INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

#[derive(Debug, Deserialize, Default)]
struct PackageJson {
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

fn find_line_of_key(content: &str, key: &str) -> usize {
    let needle = format!("\"{key}\"");
    for (idx, line) in content.lines().enumerate() {
        if line.contains(&needle) {
            return idx + 1;
        }
    }
    1
}

fn is_dangerous_hook_command(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    let indicators = [
        "curl ",
        "curl\t",
        "wget ",
        "| sh",
        "|sh",
        "| bash",
        "|bash",
        "bash -c",
        "sh -c",
        "powershell",
        "node -e",
        "eval ",
        "base64",
        "http://",
        "https://",
        "nc ",
        "python -c",
    ];
    indicators.iter().any(|ind| lower.contains(ind))
}

/// Analyzes `package.json` for newly added or modified install lifecycle hooks.
pub fn analyze_package_json(change: &PackageChange, file: &ChangedFile) -> Vec<Finding> {
    let Ok(new_pkg) = serde_json::from_str::<PackageJson>(&file.new_content) else {
        return Vec::new();
    };
    let old_scripts = file
        .old_content
        .as_deref()
        .and_then(|old| serde_json::from_str::<PackageJson>(old).ok())
        .map(|p| p.scripts)
        .unwrap_or_default();

    let mut findings = Vec::new();
    for hook in INSTALL_HOOKS {
        let Some(new_cmd) = new_pkg.scripts.get(*hook) else {
            continue;
        };
        if old_scripts.get(*hook) == Some(new_cmd) {
            continue;
        }

        let dangerous = is_dangerous_hook_command(new_cmd);
        let severity = if dangerous {
            Severity::Critical
        } else {
            Severity::High
        };
        let line = find_line_of_key(&file.new_content, hook);

        findings.push(Finding {
            id: "DX002".to_string(),
            package_name: change.name.clone(),
            package_version: change.new_version.clone(),
            ecosystem: Ecosystem::Npm,
            file_path: file.path.clone(),
            line,
            column: 1,
            severity,
            category: CapabilityCategory::ExecutionHook,
            title: format!("Modified or added npm `{hook}` script"),
            description: if dangerous {
                format!(
                    "Lifecycle hook `{hook}` executes shell/network commands during package installation."
                )
            } else {
                format!(
                    "Lifecycle hook `{hook}` was added or modified and runs automatically during install."
                )
            },
            snippet: format!("\"{hook}\": \"{new_cmd}\""),
            is_new_package: change.is_new(),
        });
    }

    findings
}
