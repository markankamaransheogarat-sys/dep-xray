//! Offline integration tests using mock `.crate` and `.tgz` archives in `tests/fixtures/`.

use dep_xray::analyze_changes;
use dep_xray::fetcher::FetcherConfig;
use dep_xray::git::collect_changes_from_git;
use dep_xray::report::{OutputFormat, render_report};
use dep_xray::scoring::FailThreshold;
use dep_xray::types::{Ecosystem, PackageChange, Severity, Verdict};
use std::path::PathBuf;
use std::process::Command;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn offline_config(cache_dir: PathBuf) -> FetcherConfig {
    FetcherConfig {
        cache_dir,
        offline_dir: Some(fixtures_dir()),
        offline_only: true,
        max_concurrency: 4,
    }
}

#[tokio::test]
async fn benign_minor_update_passes_with_zero_findings() {
    let tmp = tempfile::tempdir().unwrap();
    let changes = vec![PackageChange {
        ecosystem: Ecosystem::Cargo,
        name: "benign-crate".to_string(),
        old_version: Some("1.0.0".to_string()),
        new_version: "1.0.1".to_string(),
        source: Some("registry+https://github.com/rust-lang/crates.io-index".to_string()),
        resolved_tarball_url: None,
    }];

    let report = analyze_changes(
        changes,
        None,
        None,
        offline_config(tmp.path().to_path_buf()),
        FailThreshold::High,
    )
    .await
    .unwrap();

    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.total_findings, 0);
    assert_eq!(report.total_risk_score, 0);
}

#[tokio::test]
async fn evil_build_rs_with_reqwest_and_env_is_critical() {
    let tmp = tempfile::tempdir().unwrap();
    let changes = vec![PackageChange {
        ecosystem: Ecosystem::Cargo,
        name: "evil-build".to_string(),
        old_version: Some("0.1.0".to_string()),
        new_version: "0.1.1".to_string(),
        source: Some("registry+https://github.com/rust-lang/crates.io-index".to_string()),
        resolved_tarball_url: None,
    }];

    let report = analyze_changes(
        changes,
        None,
        None,
        offline_config(tmp.path().to_path_buf()),
        FailThreshold::Critical,
    )
    .await
    .unwrap();

    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.max_severity, Some(Severity::Critical));
    let findings = &report.packages[0].findings;
    assert!(
        findings
            .iter()
            .any(|f| f.id == "DX005" && f.severity == Severity::Critical)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.id == "DX008" && f.severity == Severity::Critical)
    );
}

#[tokio::test]
async fn evil_npm_postinstall_and_base64_eval_is_critical() {
    let tmp = tempfile::tempdir().unwrap();
    let changes = vec![PackageChange {
        ecosystem: Ecosystem::Npm,
        name: "evil-npm".to_string(),
        old_version: Some("1.0.0".to_string()),
        new_version: "1.0.1".to_string(),
        source: None,
        resolved_tarball_url: None,
    }];

    let report = analyze_changes(
        changes,
        None,
        None,
        offline_config(tmp.path().to_path_buf()),
        FailThreshold::Critical,
    )
    .await
    .unwrap();

    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.max_severity, Some(Severity::Critical));
    let findings = &report.packages[0].findings;
    assert!(
        findings
            .iter()
            .any(|f| f.id == "DX002" && f.severity == Severity::Critical)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.id == "DX011" && f.severity == Severity::Critical)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.id == "DX013" && f.severity == Severity::Critical)
    );
}

#[tokio::test]
async fn new_unsafe_block_in_rust_is_high() {
    let tmp = tempfile::tempdir().unwrap();
    let changes = vec![PackageChange {
        ecosystem: Ecosystem::Cargo,
        name: "unsafe-crate".to_string(),
        old_version: Some("0.2.0".to_string()),
        new_version: "0.2.1".to_string(),
        source: Some("registry+https://github.com/rust-lang/crates.io-index".to_string()),
        resolved_tarball_url: None,
    }];

    let report = analyze_changes(
        changes,
        None,
        None,
        offline_config(tmp.path().to_path_buf()),
        FailThreshold::High,
    )
    .await
    .unwrap();

    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.max_severity, Some(Severity::High));
    assert!(
        report.packages[0]
            .findings
            .iter()
            .any(|f| f.id == "DX010" && f.severity == Severity::High)
    );
}

#[tokio::test]
async fn sarif_and_markdown_outputs_are_well_formed() {
    let tmp = tempfile::tempdir().unwrap();
    let changes = vec![PackageChange {
        ecosystem: Ecosystem::Npm,
        name: "evil-npm".to_string(),
        old_version: Some("1.0.0".to_string()),
        new_version: "1.0.1".to_string(),
        source: None,
        resolved_tarball_url: None,
    }];

    let report = analyze_changes(
        changes,
        Some("main".to_string()),
        Some("HEAD".to_string()),
        offline_config(tmp.path().to_path_buf()),
        FailThreshold::High,
    )
    .await
    .unwrap();

    // Verify SARIF 2.1.0 structure.
    let sarif_str = render_report(&report, OutputFormat::Sarif).unwrap();
    let sarif_json: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
    assert_eq!(sarif_json["version"], "2.1.0");
    assert_eq!(sarif_json["runs"][0]["tool"]["driver"]["name"], "dep-xray");
    assert!(
        !sarif_json["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !sarif_json["runs"][0]["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Verify Markdown PR comment.
    let md = render_report(&report, OutputFormat::Markdown).unwrap();
    assert!(md.contains("dep-xray Behavioral Diff Report"));
    assert!(md.contains("evil-npm"));
    assert!(md.contains("CRITICAL"));
    assert!(md.contains("DX002"));
}

#[tokio::test]
async fn end_to_end_git_diff_with_cargo_and_npm_lockfiles() {
    let repo = tempfile::tempdir().unwrap();
    let run_git = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(repo.path())
            .status()
            .unwrap();
        assert!(status.success(), "git {:?} failed", args);
    };

    run_git(&["init"]);
    run_git(&["config", "user.email", "ci@example.com"]);
    run_git(&["config", "user.name", "CI"]);

    let cargo_old = r#"
version = 3

[[package]]
name = "benign-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    let npm_old = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/evil-npm": { "version": "1.0.0" }
  }
}"#;
    std::fs::write(repo.path().join("Cargo.lock"), cargo_old).unwrap();
    std::fs::write(repo.path().join("package-lock.json"), npm_old).unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "base"]);

    let cargo_new = r#"
version = 3

[[package]]
name = "benign-crate"
version = "1.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    let npm_new = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/evil-npm": { "version": "1.0.1" }
  }
}"#;
    std::fs::write(repo.path().join("Cargo.lock"), cargo_new).unwrap();
    std::fs::write(repo.path().join("package-lock.json"), npm_new).unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "bump"]);

    let changes = collect_changes_from_git(repo.path(), "HEAD~1", "HEAD")
        .await
        .unwrap();
    assert_eq!(changes.len(), 2);

    let cache_dir = tempfile::tempdir().unwrap();
    let report = analyze_changes(
        changes,
        Some("HEAD~1".to_string()),
        Some("HEAD".to_string()),
        offline_config(cache_dir.path().to_path_buf()),
        FailThreshold::High,
    )
    .await
    .unwrap();

    assert_eq!(report.total_packages_changed, 2);
    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.max_severity, Some(Severity::Critical));
}

#[test]
fn cargo_toml_detects_build_script_and_proc_macro() {
    let change = PackageChange {
        name: "sneaky-crate".to_string(),
        ecosystem: Ecosystem::Cargo,
        old_version: Some("0.1.0".to_string()),
        new_version: "0.1.1".to_string(),
        source: None,
        resolved_tarball_url: None,
    };
    let mut new_files = std::collections::BTreeMap::new();
    new_files.insert(
        "Cargo.toml".to_string(),
        r#"[package]
name = "sneaky-crate"
version = "0.1.1"
build = "custom_build.rs"

[lib]
proc-macro = true

[build-dependencies]
cc = "1.0"
"#
        .to_string(),
    );
    let mut old_files = std::collections::BTreeMap::new();
    old_files.insert(
        "Cargo.toml".to_string(),
        r#"[package]
name = "sneaky-crate"
version = "0.1.0"
"#
        .to_string(),
    );
    let diff = dep_xray::diff::compute_package_diff(Some(&old_files), &new_files);
    let findings = dep_xray::analyzer::analyze_package_diff(&change, &diff);
    assert!(findings.iter().any(|f| f.id == "DX015"));
    assert!(findings.iter().any(|f| f.id == "DX016"));
}

#[test]
fn inspect_archive_and_ignore_policy_work() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/evil-build-0.1.1.crate");
    let report = dep_xray::inspect_archive(
        &fixture,
        FailThreshold::High,
        &dep_xray::policy::IgnorePolicy::default(),
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.total_findings > 0);

    let suppress = dep_xray::policy::IgnorePolicy {
        ignore_packages: vec!["evil-build-0.1.1".to_string()],
        ..Default::default()
    };
    let clean = dep_xray::inspect_archive(&fixture, FailThreshold::High, &suppress).unwrap();
    assert_eq!(clean.verdict, Verdict::Pass);
    assert_eq!(clean.total_findings, 0);
}
