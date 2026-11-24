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
    let json_needle = format!("\"{key}\"");
    for (idx, line) in content.lines().enumerate() {
        if line.contains(&json_needle) || line.trim_start().starts_with(key) {
            return idx + 1;
        }
    }
    return 1;
    #[allow(unreachable_code)]
    let needle = json_needle;
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

#[derive(Debug, Deserialize, Default)]
struct CargoPackageSection {
    build: Option<toml::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct CargoLibSection {
    #[serde(rename = "proc-macro", default)]
    proc_macro: bool,
}

#[derive(Debug, Deserialize, Default)]
struct CargoToml {
    package: Option<CargoPackageSection>,
    lib: Option<CargoLibSection>,
    #[serde(rename = "build-dependencies", default)]
    build_dependencies: BTreeMap<String, toml::Value>,
}

/// Analyzes `Cargo.toml` for newly added build scripts, `build-dependencies`, or `proc-macro` targets.
pub fn analyze_cargo_toml(change: &PackageChange, file: &ChangedFile) -> Vec<Finding> {
    let Ok(new_cargo) = toml::from_str::<CargoToml>(&file.new_content) else {
        return Vec::new();
    };
    let old_cargo = file
        .old_content
        .as_deref()
        .and_then(|old| toml::from_str::<CargoToml>(old).ok())
        .unwrap_or_default();

    let mut findings = Vec::new();

    let new_build = new_cargo.package.as_ref().and_then(|p| p.build.as_ref());
    let old_build = old_cargo.package.as_ref().and_then(|p| p.build.as_ref());
    if let Some(build_val) = new_build
        && old_build != Some(build_val)
        && *build_val != toml::Value::Boolean(false)
    {
        findings.push(Finding {
            id: "DX015".to_string(),
            package_name: change.name.clone(),
            package_version: change.new_version.clone(),
            ecosystem: Ecosystem::Cargo,
            file_path: file.path.clone(),
            line: find_line_of_key(&file.new_content, "build").max(1),
            column: 1,
            severity: Severity::High,
            category: CapabilityCategory::ExecutionHook,
            title: "Custom Cargo build script configured".to_string(),
            description: "Cargo.toml configures a custom `package.build` script that executes at compile time.".to_string(),
            snippet: format!("build = {build_val}"),
            is_new_package: change.is_new(),
        });
    }

    let new_proc_macro = new_cargo.lib.as_ref().is_some_and(|l| l.proc_macro);
    let old_proc_macro = old_cargo.lib.as_ref().is_some_and(|l| l.proc_macro);
    if new_proc_macro && !old_proc_macro {
        findings.push(Finding {
            id: "DX016".to_string(),
            package_name: change.name.clone(),
            package_version: change.new_version.clone(),
            ecosystem: Ecosystem::Cargo,
            file_path: file.path.clone(),
            line: find_line_of_key(&file.new_content, "proc-macro").max(1),
            column: 1,
            severity: Severity::High,
            category: CapabilityCategory::ExecutionHook,
            title: "Crate enabled `proc-macro = true`".to_string(),
            description: "Procedural macros execute arbitrary code on the host during compilation."
                .to_string(),
            snippet: "proc-macro = true".to_string(),
            is_new_package: change.is_new(),
        });
    }

    let newly_added_build_deps: Vec<&String> = new_cargo
        .build_dependencies
        .keys()
        .filter(|dep| !old_cargo.build_dependencies.contains_key(*dep))
        .collect();
    if !newly_added_build_deps.is_empty() {
        let joined = newly_added_build_deps
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            id: "DX015".to_string(),
            package_name: change.name.clone(),
            package_version: change.new_version.clone(),
            ecosystem: Ecosystem::Cargo,
            file_path: file.path.clone(),
            line: find_line_of_key(&file.new_content, "build-dependencies").max(1),
            column: 1,
            severity: Severity::Medium,
            category: CapabilityCategory::ExecutionHook,
            title: format!("Added [build-dependencies]: {joined}"),
            description: "New compile-time build dependencies were added to Cargo.toml."
                .to_string(),
            snippet: format!("[build-dependencies] -> {joined}"),
            is_new_package: change.is_new(),
        });
    }

    findings
}
