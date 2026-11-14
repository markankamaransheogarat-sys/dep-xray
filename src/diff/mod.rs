//! File-level and line-level diff computation between package versions.

use crate::fetcher::archive::PackageFiles;
use similar::{ChangeTag, TextDiff};
use std::collections::BTreeSet;

/// A single new or modified file in a package update, along with the 1-based
/// line numbers of newly added lines in `new_content`.
#[derive(Debug, Clone)]
pub struct ChangedFile {
    pub path: String,
    pub old_content: Option<String>,
    pub new_content: String,
    pub added_lines: BTreeSet<usize>,
    pub is_new_file: bool,
}

/// Result of diffing an old and new version of a package.
#[derive(Debug, Clone)]
pub struct PackageDiff {
    pub changed_files: Vec<ChangedFile>,
    pub total_lines_added: usize,
}

/// Computes changed/added files and added 1-based line numbers in `new_files`.
pub fn compute_package_diff(
    old_files: Option<&PackageFiles>,
    new_files: &PackageFiles,
) -> PackageDiff {
    let mut changed_files = Vec::new();
    let mut total_lines_added = 0usize;

    for (path, new_content) in new_files {
        match old_files.and_then(|old| old.get(path)) {
            None => {
                let line_count = new_content.lines().count().max(1);
                let added_lines: BTreeSet<usize> = (1..=line_count).collect();
                total_lines_added += added_lines.len();
                changed_files.push(ChangedFile {
                    path: path.clone(),
                    old_content: None,
                    new_content: new_content.clone(),
                    added_lines,
                    is_new_file: true,
                });
            }
            Some(old_content) if old_content != new_content => {
                let diff = TextDiff::from_lines(old_content.as_str(), new_content.as_str());
                let mut added_lines = BTreeSet::new();
                for change in diff.iter_all_changes() {
                    if change.tag() == ChangeTag::Insert
                        && let Some(new_idx) = change.new_index()
                    {
                        added_lines.insert(new_idx + 1);
                    }
                }
                if !added_lines.is_empty() {
                    total_lines_added += added_lines.len();
                    changed_files.push(ChangedFile {
                        path: path.clone(),
                        old_content: Some(old_content.clone()),
                        new_content: new_content.clone(),
                        added_lines,
                        is_new_file: false,
                    });
                }
            }
            Some(_) => {}
        }
    }

    PackageDiff {
        changed_files,
        total_lines_added,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_only_inserted_lines() {
        let mut old = PackageFiles::new();
        old.insert("src/lib.rs".into(), "pub fn a() {}\npub fn b() {}\n".into());

        let mut new = PackageFiles::new();
        new.insert(
            "src/lib.rs".into(),
            "pub fn a() {}\npub fn sneaky() { unsafe {} }\npub fn b() {}\n".into(),
        );

        let diff = compute_package_diff(Some(&old), &new);
        assert_eq!(diff.changed_files.len(), 1);
        assert_eq!(diff.total_lines_added, 1);
        assert!(diff.changed_files[0].added_lines.contains(&2));
        assert!(!diff.changed_files[0].added_lines.contains(&1));
    }
}
