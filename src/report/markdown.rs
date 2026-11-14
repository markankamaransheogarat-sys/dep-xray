//! GitHub PR comment Markdown report renderer.

use crate::types::{AnalysisReport, Severity, Verdict};
use std::fmt::Write;

fn severity_icon(sev: Option<Severity>) -> &'static str {
    match sev {
        Some(Severity::Critical) => "CRITICAL",
        Some(Severity::High) => "HIGH",
        Some(Severity::Medium) => "MEDIUM",
        Some(Severity::Info) => "INFO",
        None => "CLEAN",
    }
}

/// Renders a Markdown report suitable for posting as a GitHub Pull Request comment.
pub fn render(report: &AnalysisReport) -> String {
    let mut out = String::new();

    let status_label = match report.verdict {
        Verdict::Pass => "PASS",
        Verdict::Warn => "WARN",
        Verdict::Fail => "FAIL",
    };

    let _ = writeln!(
        out,
        "## dep-xray Behavioral Diff Report — **{status_label}**\n"
    );
    let _ = writeln!(
        out,
        "- **Packages analyzed:** {}",
        report.total_packages_changed
    );
    let _ = writeln!(out, "- **Capability signals:** {}", report.total_findings);
    let _ = writeln!(out, "- **Total risk score:** {}\n", report.total_risk_score);

    if report.packages.is_empty() {
        let _ = writeln!(out, "_No dependency changes detected in this diff._");
        return out;
    }

    let _ = writeln!(
        out,
        "| Package | Ecosystem | Version | Risk Score | Max Severity | Signals |"
    );
    let _ = writeln!(out, "| --- | --- | --- | ---: | --- | ---: |");

    for pkg in &report.packages {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | {} | **{}** | {} |",
            pkg.change.name,
            pkg.change.ecosystem,
            pkg.change.version_transition(),
            pkg.risk_score,
            severity_icon(pkg.max_severity),
            pkg.findings.len()
        );
    }

    let all_findings: Vec<_> = report
        .packages
        .iter()
        .flat_map(|p| p.findings.iter())
        .collect();

    if !all_findings.is_empty() {
        let _ = writeln!(out, "\n### Capability Signals\n");
        for f in all_findings {
            let _ = writeln!(
                out,
                "- **[{}]** `{}` `{}` (`{}@{}:{}:{}`): {}",
                f.severity,
                f.id,
                f.title,
                f.package_name,
                f.package_version,
                f.file_path,
                f.line,
                f.description
            );
            if !f.snippet.is_empty() {
                let _ = writeln!(out, "  ```\n  {}\n  ```", f.snippet);
            }
        }
    } else {
        let _ = writeln!(
            out,
            "\n_All updated dependencies passed behavioral AST inspection with 0 capability signals._"
        );
    }

    out
}
