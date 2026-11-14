//! Rich terminal table and snippet renderer.

use crate::types::{AnalysisReport, Severity, Verdict};
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use owo_colors::OwoColorize;
use std::fmt::Write;

fn severity_cell(sev: Option<Severity>) -> Cell {
    match sev {
        Some(Severity::Critical) => Cell::new("CRITICAL").fg(Color::Red),
        Some(Severity::High) => Cell::new("HIGH").fg(Color::Yellow),
        Some(Severity::Medium) => Cell::new("MEDIUM").fg(Color::Cyan),
        Some(Severity::Info) => Cell::new("INFO").fg(Color::Blue),
        None => Cell::new("CLEAN").fg(Color::Green),
    }
}

/// Renders a human-friendly terminal report with summary table and code snippets.
pub fn render(report: &AnalysisReport) -> String {
    let mut out = String::new();

    let verdict_str = match report.verdict {
        Verdict::Pass => "PASS".green().bold().to_string(),
        Verdict::Warn => "WARN".yellow().bold().to_string(),
        Verdict::Fail => "FAIL".red().bold().to_string(),
    };

    let _ = writeln!(
        out,
        "{}  verdict={}  packages={}  findings={}  risk_score={}",
        "dep-xray".bold(),
        verdict_str,
        report.total_packages_changed,
        report.total_findings,
        report.total_risk_score
    );

    if report.packages.is_empty() {
        let _ = writeln!(out, "No dependency changes detected.");
        return out;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "Package",
            "Ecosystem",
            "Version",
            "Risk",
            "Max Severity",
            "Findings",
        ]);

    for pkg in &report.packages {
        table.add_row(vec![
            Cell::new(&pkg.change.name),
            Cell::new(pkg.change.ecosystem.to_string()),
            Cell::new(pkg.change.version_transition()),
            Cell::new(pkg.risk_score),
            severity_cell(pkg.max_severity),
            Cell::new(pkg.findings.len()),
        ]);
    }
    let _ = writeln!(out, "\n{table}");

    let flagged: Vec<_> = report
        .packages
        .iter()
        .flat_map(|p| p.findings.iter())
        .collect();

    if !flagged.is_empty() {
        let _ = writeln!(out, "\n{}", "Detected Capability Signals:".bold());
        for f in flagged {
            let sev_badge = match f.severity {
                Severity::Critical => format!("[{}]", f.severity).red().bold().to_string(),
                Severity::High => format!("[{}]", f.severity).yellow().bold().to_string(),
                Severity::Medium => format!("[{}]", f.severity).cyan().bold().to_string(),
                Severity::Info => format!("[{}]", f.severity).blue().to_string(),
            };
            let _ = writeln!(
                out,
                "  {sev_badge} {} {} — {}",
                f.id.dimmed(),
                format!(
                    "{}@{}:{}:{}",
                    f.package_name, f.package_version, f.file_path, f.line
                )
                .bold(),
                f.title
            );
            if !f.snippet.is_empty() {
                let _ = writeln!(out, "      {}", f.snippet.dimmed());
            }
        }
    }

    out
}
