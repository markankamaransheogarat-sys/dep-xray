//! `pnpm-lock.yaml` (v5, v6, v9) parser and differ.

use crate::error::{DepXrayError, Result};
use crate::lockfile::{VersionEntry, diff_version_maps};
use crate::types::{Ecosystem, PackageChange};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct PnpmLockFile {
    #[serde(default)]
    packages: BTreeMap<String, PnpmPackageEntry>,
}

#[derive(Debug, Deserialize)]
struct PnpmPackageEntry {
    #[serde(default)]
    resolution: Option<PnpmResolution>,
}

#[derive(Debug, Deserialize)]
struct PnpmResolution {
    #[serde(default)]
    tarball: Option<String>,
}

/// Parses pnpm package keys across lockfile versions:
/// - v6/v9: `lodash@4.17.21`, `/lodash@4.17.21`, `@babel/core@7.24.0`, `lodash@4.17.21(peer@1.0.0)`
/// - v5: `/lodash/4.17.21`, `/@babel/core/7.24.0`
fn parse_pnpm_package_key(raw_key: &str) -> Option<(String, String)> {
    let key = raw_key.strip_prefix('/').unwrap_or(raw_key);
    // Strip peer dependency suffix like `(react@18.2.0)` or `_react@18.2.0`.
    let key = key.split('(').next().unwrap_or(key);
    let key = key.split('_').next().unwrap_or(key);

    // v6/v9 format uses `@` between name and version (skipping leading `@` for scoped packages).
    let search_start = if key.starts_with('@') { 1 } else { 0 };
    if let Some(rel_idx) = key[search_start..].find('@') {
        let at_idx = search_start + rel_idx;
        let name = &key[..at_idx];
        let version = &key[at_idx + 1..];
        if !name.is_empty() && !version.is_empty() {
            return Some((name.to_string(), version.to_string()));
        }
    }

    // v5 format uses `/` between name and version: `@scope/name/1.2.3` or `name/1.2.3`.
    if let Some(slash_idx) = key.rfind('/') {
        let name = &key[..slash_idx];
        let version = &key[slash_idx + 1..];
        if !name.is_empty() && !version.is_empty() {
            return Some((name.to_string(), version.to_string()));
        }
    }

    None
}

fn parse_pnpm_lock(content: &str) -> Result<BTreeMap<String, Vec<VersionEntry>>> {
    let parsed: PnpmLockFile =
        serde_yaml::from_str(content).map_err(|e| DepXrayError::LockfileParse {
            path: "pnpm-lock.yaml".to_string(),
            message: e.to_string(),
        })?;

    let mut map: BTreeMap<String, Vec<VersionEntry>> = BTreeMap::new();
    for (key, entry) in parsed.packages {
        let Some((name, version)) = parse_pnpm_package_key(&key) else {
            continue;
        };
        let tarball = entry.resolution.and_then(|r| r.tarball);
        map.entry(name).or_default().push(VersionEntry {
            version,
            source: tarball.clone(),
            tarball_url: tarball,
        });
    }
    Ok(map)
}

/// Diffs two `pnpm-lock.yaml` contents and returns updated/added npm packages.
pub fn diff(old_content: Option<&str>, new_content: &str) -> Result<Vec<PackageChange>> {
    let old_map = match old_content {
        Some(c) if !c.trim().is_empty() => parse_pnpm_lock(c)?,
        _ => BTreeMap::new(),
    };
    let new_map = parse_pnpm_lock(new_content)?;
    Ok(diff_version_maps(Ecosystem::Npm, old_map, new_map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pnpm_v9_and_v5_keys() {
        assert_eq!(
            parse_pnpm_package_key("lodash@4.17.21"),
            Some(("lodash".to_string(), "4.17.21".to_string()))
        );
        assert_eq!(
            parse_pnpm_package_key("/@babel/core@7.24.0(typescript@5.4.5)"),
            Some(("@babel/core".to_string(), "7.24.0".to_string()))
        );
        assert_eq!(
            parse_pnpm_package_key("/@scope/pkg/1.2.3"),
            Some(("@scope/pkg".to_string(), "1.2.3".to_string()))
        );
    }

    #[test]
    fn diffs_pnpm_lock_yaml() {
        let old = r#"
lockfileVersion: '9.0'
packages:
  chalk@5.2.0:
    resolution: {integrity: sha512-abc}
"#;
        let new = r#"
lockfileVersion: '9.0'
packages:
  chalk@5.3.0:
    resolution: {integrity: sha512-def}
  evil-pkg@1.0.0:
    resolution: {integrity: sha512-xyz}
"#;
        let changes = diff(Some(old), new).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].name, "chalk");
        assert_eq!(changes[0].old_version.as_deref(), Some("5.2.0"));
        assert_eq!(changes[0].new_version, "5.3.0");
        assert_eq!(changes[1].name, "evil-pkg");
        assert_eq!(changes[1].old_version, None);
    }
}
