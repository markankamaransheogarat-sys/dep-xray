//! CLI entry point for `dep-xray`.

#![forbid(unsafe_code)]

use clap::Parser;
use dep_xray::analyze_changes;
use dep_xray::cli::{Cli, Command, SharedOptions};
use dep_xray::error::{DepXrayError, Result};
use dep_xray::fetcher::FetcherConfig;
use dep_xray::fetcher::cache::default_cache_dir;
use dep_xray::git::collect_changes_from_git;
use dep_xray::lockfile::{LockfileKind, diff_lockfiles};
use dep_xray::report::render_report;
use dep_xray::types::Verdict;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(verdict) => {
            if verdict == Verdict::Fail {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}

fn build_fetcher_config(shared: &SharedOptions) -> FetcherConfig {
    FetcherConfig {
        cache_dir: shared.cache_dir.clone().unwrap_or_else(default_cache_dir),
        offline_dir: shared.offline_dir.clone(),
        offline_only: shared.offline,
        max_concurrency: shared.concurrency,
    }
}

async fn run(cli: Cli) -> Result<Verdict> {
    let (changes, base_ref, head_ref, shared) = match cli.command {
        Command::Diff(args) => {
            let (base, head) = args.resolve_refs();
            let changes = collect_changes_from_git(&args.repo, &base, &head).await?;
            (changes, Some(base), Some(head), args.shared)
        }
        Command::Lockfiles(args) => {
            let new_path_str = args.new_lockfile.to_string_lossy().into_owned();
            let kind = LockfileKind::from_path(&new_path_str).ok_or_else(|| {
                DepXrayError::LockfileParse {
                    path: new_path_str.clone(),
                    message: "unsupported lockfile name (expected Cargo.lock, package-lock.json, or pnpm-lock.yaml)".to_string(),
                }
            })?;
            let old_content = tokio::fs::read_to_string(&args.old_lockfile).await?;
            let new_content = tokio::fs::read_to_string(&args.new_lockfile).await?;
            let changes = diff_lockfiles(kind, Some(&old_content), &new_content)?;
            (
                changes,
                Some(args.old_lockfile.to_string_lossy().into_owned()),
                Some(new_path_str),
                args.shared,
            )
        }
    };

    let report = analyze_changes(
        changes,
        base_ref,
        head_ref,
        build_fetcher_config(&shared),
        shared.fail_on.into(),
    )
    .await?;

    let rendered = render_report(&report, shared.format)?;
    if let Some(output_path) = shared.output {
        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&output_path, rendered.as_bytes()).await?;
    } else {
        println!("{rendered}");
    }

    Ok(report.verdict)
}
