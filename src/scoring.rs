//! Risk scoring and verdict calculation for analyzed dependency updates.

use crate::diff::PackageDiff;
use crate::types::{AnalysisReport, Finding, PackageChange, PackageReport, Severity, Verdict};

/// Threshold at which `dep-xray` exits with `Verdict::Fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailThreshold {
    Medium,
    High,
    Critical,
    Never,
}

impl FailThreshold {
    pub fn matches(self, severity: Severity) -> bool {
        match self {
            Self::Medium => severity >= Severity::Medium,
            Self::High => severity >= Severity::High,
            Self::Critical => severity >= Severity::Critical,
            Self::Never => false,
        }
    }
}

/// Builds a `PackageReport` from a `PackageChange`, its `PackageDiff`, and detected `Finding`s.
pub fn score_package(
    change: PackageChange,
    diff: &PackageDiff,
    findings: Vec<Finding>,
) -> PackageReport {
    let mut risk_score: u32 = findings.iter().map(|f| f.severity.risk_weight()).sum();
    // Slight cap/normalization isn't strictly required, or we can cap at 100?
    // Keeping raw additive score (or capped at 100) — let's keep raw score so multiple CRITICALs stand out,
    // or cap at 100 if desired. Raw score is transparent and monotonic.
    if change.is_new() && !findings.is_empty() {
        risk_score += 5;
    }

    let max_severity = findings.iter().map(|f| f.severity).max();

    PackageReport {
        change,
        files_changed: diff.changed_files.len(),
        lines_added: diff.total_lines_added,
        risk_score,
        max_severity,
        findings,
    }
}

/// Aggregates package reports into a final `AnalysisReport` with an overall `Verdict`.
pub fn build_analysis_report(
    base_ref: Option<String>,
    head_ref: Option<String>,
    mut packages: Vec<PackageReport>,
    threshold: FailThreshold,
) -> AnalysisReport {
    packages.sort_by(|a, b| {
        b.max_severity
            .cmp(&a.max_severity)
            .then_with(|| b.risk_score.cmp(&a.risk_score))
            .then_with(|| a.change.name.cmp(&b.change.name))
    });

    let total_packages_changed = packages.len();
    let total_findings: usize = packages.iter().map(|p| p.findings.len()).sum();
    let max_severity = packages.iter().filter_map(|p| p.max_severity).max();
    let total_risk_score: u32 = packages.iter().map(|p| p.risk_score).sum();

    let verdict = match max_severity {
        Some(sev) if threshold.matches(sev) => Verdict::Fail,
        Some(_) => Verdict::Warn,
        None => Verdict::Pass,
    };

    AnalysisReport {
        base_ref,
        head_ref,
        total_packages_changed,
        total_findings,
        max_severity,
        total_risk_score,
        verdict,
        packages,
    }
}
