//! `dep-xray`: Behavioral AST diff analyzer for dependency updates.

#![forbid(unsafe_code)]

pub mod analyzer;
pub mod cli;
pub mod diff;
pub mod error;
pub mod fetcher;
pub mod git;
pub mod lockfile;
pub mod report;
pub mod scoring;
pub mod types;

use crate::analyzer::analyze_package_diff;
use crate::diff::compute_package_diff;
use crate::error::Result;
use crate::fetcher::{FetcherConfig, PackageFetcher};
use crate::scoring::{FailThreshold, build_analysis_report, score_package};
use crate::types::{AnalysisReport, PackageChange};

/// Runs the full fetch -> diff -> AST analysis -> scoring pipeline for a list of `PackageChange`s.
pub async fn analyze_changes(
    changes: Vec<PackageChange>,
    base_ref: Option<String>,
    head_ref: Option<String>,
    fetcher_config: FetcherConfig,
    threshold: FailThreshold,
) -> Result<AnalysisReport> {
    let fetcher = PackageFetcher::new(fetcher_config)?;
    let pairs = fetcher.fetch_all(changes).await?;

    let mut package_reports = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let pkg_diff = compute_package_diff(pair.old_files.as_ref(), &pair.new_files);
        let findings = analyze_package_diff(&pair.change, &pkg_diff);
        let pkg_report = score_package(pair.change, &pkg_diff, findings);
        package_reports.push(pkg_report);
    }

    Ok(build_analysis_report(
        base_ref,
        head_ref,
        package_reports,
        threshold,
    ))
}
