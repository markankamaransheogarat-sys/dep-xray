//! `dep-xray`: Behavioral AST diff analyzer for dependency updates.

#![forbid(unsafe_code)]

pub mod analyzer;
pub mod cli;
pub mod diff;
pub mod error;
pub mod fetcher;
pub mod git;
pub mod lockfile;
pub mod policy;
pub mod report;
pub mod scoring;
pub mod types;

use crate::analyzer::analyze_package_diff;
use crate::diff::compute_package_diff;
use crate::error::Result;
use crate::fetcher::archive::extract_tar_gz;
use crate::fetcher::{FetcherConfig, PackageFetcher};
use crate::policy::IgnorePolicy;
use crate::scoring::{FailThreshold, build_analysis_report, score_package};
use crate::types::{AnalysisReport, Ecosystem, PackageChange};

/// Runs the full fetch -> diff -> AST analysis -> scoring pipeline for a list of `PackageChange`s.
pub async fn analyze_changes(
    changes: Vec<PackageChange>,
    base_ref: Option<String>,
    head_ref: Option<String>,
    fetcher_config: FetcherConfig,
    threshold: FailThreshold,
) -> Result<AnalysisReport> {
    analyze_changes_with_policy(
        changes,
        base_ref,
        head_ref,
        fetcher_config,
        threshold,
        &IgnorePolicy::default(),
    )
    .await
}

/// Runs the analysis pipeline and filters findings through an `IgnorePolicy`.
pub async fn analyze_changes_with_policy(
    changes: Vec<PackageChange>,
    base_ref: Option<String>,
    head_ref: Option<String>,
    fetcher_config: FetcherConfig,
    threshold: FailThreshold,
    policy: &IgnorePolicy,
) -> Result<AnalysisReport> {
    let fetcher = PackageFetcher::new(fetcher_config)?;
    let pairs = fetcher.fetch_all(changes).await?;

    let mut package_reports = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let pkg_diff = compute_package_diff(pair.old_files.as_ref(), &pair.new_files);
        let raw_findings = analyze_package_diff(&pair.change, &pkg_diff);
        let findings = policy.filter_findings(&pair.change.name, raw_findings);
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

/// Directly inspects a single `.crate` or `.tgz` archive against an empty baseline.
pub fn inspect_archive(
    archive_path: &std::path::Path,
    threshold: FailThreshold,
    policy: &IgnorePolicy,
) -> Result<AnalysisReport> {
    let bytes = std::fs::read(archive_path)?;
    let file_name = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("archive");
    let ecosystem = if file_name.ends_with(".crate") {
        Ecosystem::Cargo
    } else {
        Ecosystem::Npm
    };
    let pkg_name = file_name
        .trim_end_matches(".crate")
        .trim_end_matches(".tgz")
        .to_string();
    let files = extract_tar_gz(file_name, &bytes)?;
    let change = PackageChange {
        name: pkg_name.clone(),
        ecosystem,
        old_version: None,
        new_version: "local".to_string(),
        source: None,
        resolved_tarball_url: None,
    };
    let pkg_diff = compute_package_diff(None, &files);
    let raw_findings = analyze_package_diff(&change, &pkg_diff);
    let findings = policy.filter_findings(&change.name, raw_findings);
    let pkg_report = score_package(change, &pkg_diff, findings);

    Ok(build_analysis_report(
        None,
        Some(archive_path.display().to_string()),
        vec![pkg_report],
        threshold,
    ))
}
