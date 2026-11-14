//! `package-lock.json` (v1, v2, v3) parser and differ.

use crate::error::{DepXrayError, Result};
use crate::lockfile::{VersionEntry, diff_version_maps};
use crate::types::{Ecosystem, PackageChange};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct PackageLockFile {
    #[serde(default)]
    packages: BTreeMap<String, NpmPackageEntry>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmLegacyDep>,
}

#[derive(Debug, Deserialize)]
struct NpmPackageEntry {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    link: bool,
}

#[derive(Debug, Deserialize)]
struct NpmLegacyDep {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmLegacyDep>,
}

fn extract_name_from_node_modules_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let idx = path.rfind("node_modules/")?;
    let name = &path[idx + "node_modules/".len()..];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn collect_legacy_deps(
    deps: &BTreeMap<String, NpmLegacyDep>,
    map: &mut BTreeMap<String, Vec<VersionEntry>>,
) {
    for (name, dep) in deps {
        if let Some(version) = &dep.version {
            // Skip file:/git:/workspace specs when they are not semver/registry versions.
            if !version.starts_with("file:") && !version.starts_with("link:") {
                map.entry(name.clone()).or_default().push(VersionEntry {
                    version: version.clone(),
                    source: dep.resolved.clone(),
                    tarball_url: dep.resolved.clone(),
                });
            }
        }
        collect_legacy_deps(&dep.dependencies, map);
    }
}

fn parse_package_lock(content: &str) -> Result<BTreeMap<String, Vec<VersionEntry>>> {
    let parsed: PackageLockFile =
        serde_json::from_str(content).map_err(|e| DepXrayError::LockfileParse {
            path: "package-lock.json".to_string(),
            message: e.to_string(),
        })?;

    let mut map: BTreeMap<String, Vec<VersionEntry>> = BTreeMap::new();

    if !parsed.packages.is_empty() {
        for (path, entry) in parsed.packages {
            if entry.link {
                continue;
            }
            let Some(name) = extract_name_from_node_modules_path(&path) else {
                continue;
            };
            let Some(version) = entry.version else {
                continue;
            };
            map.entry(name).or_default().push(VersionEntry {
                version,
                source: entry.resolved.clone(),
                tarball_url: entry.resolved,
            });
        }
    } else {
        collect_legacy_deps(&parsed.dependencies, &mut map);
    }

    Ok(map)
}

/// Diffs two `package-lock.json` contents and returns updated/added npm packages.
pub fn diff(old_content: Option<&str>, new_content: &str) -> Result<Vec<PackageChange>> {
    let old_map = match old_content {
        Some(c) if !c.trim().is_empty() => parse_package_lock(c)?,
        _ => BTreeMap::new(),
    };
    let new_map = parse_package_lock(new_content)?;
    Ok(diff_version_maps(Ecosystem::Npm, old_map, new_map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_npm_v3_upgrade_and_addition() {
        let old = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    }
  }
}"#;

        let new = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    },
    "node_modules/@types/node": {
      "version": "22.0.0",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-22.0.0.tgz"
    }
  }
}"#;

        let changes = diff(Some(old), new).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].name, "@types/node");
        assert_eq!(changes[0].old_version, None);
        assert_eq!(changes[0].new_version, "22.0.0");

        assert_eq!(changes[1].name, "lodash");
        assert_eq!(changes[1].old_version.as_deref(), Some("4.17.20"));
        assert_eq!(changes[1].new_version, "4.17.21");
    }
}
