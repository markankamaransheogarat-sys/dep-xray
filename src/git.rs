//! Git integration for discovering changed lockfiles and reading their contents across revisions.

use crate::error::{DepXrayError, Result};
use crate::lockfile::{LockfileKind, diff_lockfiles};
use crate::types::PackageChange;
use std::path::Path;
use tokio::process::Command;

/// Runs a git command in `repo_dir` and returns stdout as UTF-8.
async fn run_git(repo_dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_dir)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DepXrayError::Git {
            message: format!("`git {}` failed: {}", args.join(" "), stderr.trim()),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Reads a file at a specific git revision, returning `Ok(None)` if the file did not exist at that revision.
async fn git_show_optional(repo_dir: &Path, rev: &str, path: &str) -> Result<Option<String>> {
    let spec = format!("{rev}:{path}");
    let output = Command::new("git")
        .args(["show", &spec])
        .current_dir(repo_dir)
        .output()
        .await?;

    if output.status.success() {
        Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
    } else {
        Ok(None)
    }
}

/// Lists all lockfile paths that changed between `base_ref` and `head_ref`.
pub async fn changed_lockfiles(
    repo_dir: &Path,
    base_ref: &str,
    head_ref: &str,
) -> Result<Vec<(String, LockfileKind)>> {
    let stdout = run_git(repo_dir, &["diff", "--name-only", base_ref, head_ref]).await?;
    let mut found = Vec::new();
    for line in stdout.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        if let Some(kind) = LockfileKind::from_path(path) {
            found.push((path.to_string(), kind));
        }
    }
    Ok(found)
}

/// Collects all dependency changes across every lockfile modified between `base_ref` and `head_ref`.
pub async fn collect_changes_from_git(
    repo_dir: &Path,
    base_ref: &str,
    head_ref: &str,
) -> Result<Vec<PackageChange>> {
    let lockfiles = changed_lockfiles(repo_dir, base_ref, head_ref).await?;
    let mut all_changes = Vec::new();

    for (path, kind) in lockfiles {
        let old_content = git_show_optional(repo_dir, base_ref, &path).await?;
        let Some(new_content) = git_show_optional(repo_dir, head_ref, &path).await? else {
            // Lockfile was deleted in head_ref; nothing new to audit.
            continue;
        };
        let changes = diff_lockfiles(kind, old_content.as_deref(), &new_content)?;
        all_changes.extend(changes);
    }

    Ok(all_changes)
}
