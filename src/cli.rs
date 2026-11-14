//! Command-line interface definitions for `dep-xray`.

use crate::report::OutputFormat;
use crate::scoring::FailThreshold;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Behavioral AST diff analyzer for dependency updates.
#[derive(Debug, Parser)]
#[command(name = "dep-xray", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyze dependency updates between two git revisions.
    Diff(DiffArgs),
    /// Directly diff two lockfile paths without git.
    Lockfiles(LockfileDiffArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOnArg {
    Medium,
    High,
    Critical,
    Never,
}

impl From<FailOnArg> for FailThreshold {
    fn from(val: FailOnArg) -> Self {
        match val {
            FailOnArg::Medium => Self::Medium,
            FailOnArg::High => Self::High,
            FailOnArg::Critical => Self::Critical,
            FailOnArg::Never => Self::Never,
        }
    }
}

#[derive(Debug, Args)]
pub struct SharedOptions {
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Minimum severity that causes a non-zero exit code.
    #[arg(long, value_enum, default_value_t = FailOnArg::High)]
    pub fail_on: FailOnArg,

    /// Write rendered report to a file instead of stdout.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Custom cache directory for downloaded tarballs.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,

    /// Directory containing pre-downloaded `.crate` / `.tgz` tarballs.
    #[arg(long)]
    pub offline_dir: Option<PathBuf>,

    /// Disallow network requests and rely solely on cache / offline-dir.
    #[arg(long)]
    pub offline: bool,

    /// Maximum concurrent tarball downloads.
    #[arg(long, default_value_t = 16)]
    pub concurrency: usize,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Git revision range (e.g. `HEAD~1..HEAD` or `main..HEAD`).
    pub range: Option<String>,

    /// Base git ref (used when `range` is not provided).
    #[arg(long)]
    pub base: Option<String>,

    /// Head git ref (used when `range` is not provided).
    #[arg(long)]
    pub head: Option<String>,

    /// Path to the git repository.
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    #[command(flatten)]
    pub shared: SharedOptions,
}

#[derive(Debug, Args)]
pub struct LockfileDiffArgs {
    /// Path to the base (old) lockfile.
    pub old_lockfile: PathBuf,

    /// Path to the head (new) lockfile.
    pub new_lockfile: PathBuf,

    #[command(flatten)]
    pub shared: SharedOptions,
}

impl DiffArgs {
    /// Resolves `(base_ref, head_ref)` from `range` or `--base`/`--head`, defaulting to `HEAD~1..HEAD`.
    pub fn resolve_refs(&self) -> (String, String) {
        if let Some(range) = &self.range {
            if let Some((base, head)) = range.split_once("..") {
                let b = if base.is_empty() { "HEAD~1" } else { base };
                let h = if head.is_empty() { "HEAD" } else { head };
                return (b.to_string(), h.to_string());
            }
            return (range.clone(), "HEAD".to_string());
        }
        let base = self.base.clone().unwrap_or_else(|| "HEAD~1".to_string());
        let head = self.head.clone().unwrap_or_else(|| "HEAD".to_string());
        (base, head)
    }
}
