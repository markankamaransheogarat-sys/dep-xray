//! Core domain types shared across lockfile parsing, diffing, analysis, and reporting.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported package ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo,
    Npm,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cargo => write!(f, "cargo"),
            Self::Npm => write!(f, "npm"),
        }
    }
}

/// A dependency version change extracted from a lockfile diff.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageChange {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub old_version: Option<String>,
    pub new_version: String,
    pub source: Option<String>,
    pub resolved_tarball_url: Option<String>,
}

impl PackageChange {
    /// Returns true if the package was newly added rather than upgraded.
    pub fn is_new(&self) -> bool {
        self.old_version.is_none()
    }

    /// Formats a human-readable version transition string.
    pub fn version_transition(&self) -> String {
        match &self.old_version {
            Some(old) => format!("{old} -> {}", self.new_version),
            None => format!("(new) {}", self.new_version),
        }
    }
}

/// Finding severity ordered from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Numeric risk weight contributed by a single finding of this severity.
    pub fn risk_weight(self) -> u32 {
        match self {
            Self::Info => 2,
            Self::Medium => 10,
            Self::High => 25,
            Self::Critical => 50,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Behavioral capability category detected in source code or package manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCategory {
    ExecutionHook,
    Network,
    SensitiveRead,
    UnsafeDynamic,
    Obfuscation,
}

impl fmt::Display for CapabilityCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExecutionHook => write!(f, "Execution / Install Hook"),
            Self::Network => write!(f, "Network / Exfiltration"),
            Self::SensitiveRead => write!(f, "Sensitive Read / Env"),
            Self::UnsafeDynamic => write!(f, "Unsafe / Dynamic Code"),
            Self::Obfuscation => write!(f, "Obfuscation / Entropy"),
        }
    }
}

/// A single behavioral capability finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub package_name: String,
    pub package_version: String,
    pub ecosystem: Ecosystem,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub severity: Severity,
    pub category: CapabilityCategory,
    pub title: String,
    pub description: String,
    pub snippet: String,
    pub is_new_package: bool,
}

/// Analysis result for a single updated or added package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageReport {
    pub change: PackageChange,
    pub files_changed: usize,
    pub lines_added: usize,
    pub risk_score: u32,
    pub max_severity: Option<Severity>,
    pub findings: Vec<Finding>,
}

/// Overall gate verdict for the analyzed diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Warn => write!(f, "WARN"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

/// Top-level report across all analyzed dependency changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub base_ref: Option<String>,
    pub head_ref: Option<String>,
    pub total_packages_changed: usize,
    pub total_findings: usize,
    pub max_severity: Option<Severity>,
    pub total_risk_score: u32,
    pub verdict: Verdict,
    pub packages: Vec<PackageReport>,
}
