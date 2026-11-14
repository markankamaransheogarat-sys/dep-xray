//! Lockfile parsers and diffing for Cargo, npm, and pnpm.

pub mod cargo_lock;
pub mod npm_lock;
pub mod pnpm_lock;

use crate::error::Result;
use crate::types::PackageChange;
use std::collections::{BTreeMap, BTreeSet};

/// Supported lockfile formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileKind {
    CargoLock,
    PackageLockJson,
    PnpmLockYaml,
}

impl LockfileKind {
    /// Detects the lockfile kind from a file path or filename.
    pub fn from_path(path: &str) -> Option<Self> {
        let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);
        match filename {
            "Cargo.lock" => Some(Self::CargoLock),
            "package-lock.json" => Some(Self::PackageLockJson),
            "pnpm-lock.yaml" => Some(Self::PnpmLockYaml),
            _ => None,
        }
    }
}

/// Computes `PackageChange` entries between two lockfile contents of the given kind.
pub fn diff_lockfiles(
    kind: LockfileKind,
    old_content: Option<&str>,
    new_content: &str,
) -> Result<Vec<PackageChange>> {
    match kind {
        LockfileKind::CargoLock => cargo_lock::diff(old_content, new_content),
        LockfileKind::PackageLockJson => npm_lock::diff(old_content, new_content),
        LockfileKind::PnpmLockYaml => pnpm_lock::diff(old_content, new_content),
    }
}

/// Shared helper to diff maps of `package_name -> (version, source, tarball_url)`
/// where multiple versions per package name may exist.
pub(crate) fn diff_version_maps(
    ecosystem: crate::types::Ecosystem,
    old_map: BTreeMap<String, Vec<VersionEntry>>,
    new_map: BTreeMap<String, Vec<VersionEntry>>,
) -> Vec<PackageChange> {
    let mut changes = Vec::new();

    for (name, new_entries) in new_map {
        let old_entries = old_map.get(&name);
        let old_versions: BTreeSet<&str> = old_entries
            .map(|v| v.iter().map(|e| e.version.as_str()).collect())
            .unwrap_or_default();
        let new_versions: BTreeSet<&str> = new_entries.iter().map(|e| e.version.as_str()).collect();

        // Versions that are in `new` but not in `old`.
        let added_entries: Vec<&VersionEntry> = new_entries
            .iter()
            .filter(|e| !old_versions.contains(e.version.as_str()))
            .collect();

        if added_entries.is_empty() {
            continue;
        }

        // Versions that were in `old` and removed in `new` (candidates for pairing as upgrades).
        let removed_versions: Vec<String> = old_entries
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| !new_versions.contains(e.version.as_str()))
                    .map(|e| e.version.clone())
                    .collect()
            })
            .unwrap_or_default();

        for (idx, new_entry) in added_entries.into_iter().enumerate() {
            let old_version = removed_versions.get(idx).cloned();
            changes.push(PackageChange {
                ecosystem,
                name: name.clone(),
                old_version,
                new_version: new_entry.version.clone(),
                source: new_entry.source.clone(),
                resolved_tarball_url: new_entry.tarball_url.clone(),
            });
        }
    }

    changes.sort_by(|a, b| {
        a.ecosystem
            .cmp(&b.ecosystem)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.new_version.cmp(&b.new_version))
    });
    changes.dedup();
    changes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionEntry {
    pub version: String,
    pub source: Option<String>,
    pub tarball_url: Option<String>,
}
