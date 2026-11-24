//! Baseline suppression policy (`.dep-xray.toml`) for CI workflows.

use crate::error::{DepXrayError, Result};
use crate::types::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Policy configuration loaded from `.dep-xray.toml` (or `--config`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IgnorePolicy {
    /// Package names to exclude from findings (all rules suppressed).
    pub ignore_packages: Vec<String>,
    /// Rule IDs (e.g. `DX004`, `DX014`) to suppress globally.
    pub ignore_rules: Vec<String>,
    /// Per-package rule IDs to suppress (key: package name, value: list of rule IDs).
    pub package_rules: BTreeMap<String, Vec<String>>,
}

impl IgnorePolicy {
    /// Load policy from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        toml::from_str(&raw).map_err(|e| DepXrayError::LockfileParse {
            path: path.display().to_string(),
            message: format!("invalid .dep-xray.toml policy: {e}"),
        })
    }

    /// Filter findings for a given package according to suppression rules.
    pub fn filter_findings(&self, package_name: &str, findings: Vec<Finding>) -> Vec<Finding> {
        if self.ignore_packages.iter().any(|p| p == package_name) {
            return Vec::new();
        }
        let pkg_ignored = self.package_rules.get(package_name);
        findings
            .into_iter()
            .filter(|f| {
                !self.ignore_rules.iter().any(|r| r == &f.id)
                    && !pkg_ignored.is_some_and(|rules| rules.iter().any(|r| r == &f.id))
            })
            .collect()
    }
}
