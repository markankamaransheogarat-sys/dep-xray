//! `Cargo.lock` parser and differ.

use crate::error::{DepXrayError, Result};
use crate::lockfile::{VersionEntry, diff_version_maps};
use crate::types::{Ecosystem, PackageChange};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct CargoLockFile {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

fn parse_cargo_lock(content: &str) -> Result<BTreeMap<String, Vec<VersionEntry>>> {
    let parsed: CargoLockFile =
        toml::from_str(content).map_err(|e| DepXrayError::LockfileParse {
            path: "Cargo.lock".to_string(),
            message: e.to_string(),
        })?;

    let mut map: BTreeMap<String, Vec<VersionEntry>> = BTreeMap::new();
    for pkg in parsed.package {
        // Skip workspace/path packages that have no external source.
        let Some(source) = pkg.source else {
            continue;
        };
        if !source.starts_with("registry+") {
            continue;
        }
        map.entry(pkg.name).or_default().push(VersionEntry {
            version: pkg.version,
            source: Some(source),
            tarball_url: None,
        });
    }
    Ok(map)
}

/// Diffs two `Cargo.lock` contents and returns updated/added registry crates.
pub fn diff(old_content: Option<&str>, new_content: &str) -> Result<Vec<PackageChange>> {
    let old_map = match old_content {
        Some(c) if !c.trim().is_empty() => parse_cargo_lock(c)?,
        _ => BTreeMap::new(),
    };
    let new_map = parse_cargo_lock(new_content)?;
    Ok(diff_version_maps(Ecosystem::Cargo, old_map, new_map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_upgrade_and_addition_in_cargo_lock() {
        let old = r#"
version = 3

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        let new = r#"
version = 3

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "reqwest"
version = "0.12.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        let changes = diff(Some(old), new).unwrap();
        assert_eq!(changes.len(), 2);

        assert_eq!(changes[0].name, "reqwest");
        assert_eq!(changes[0].old_version, None);
        assert_eq!(changes[0].new_version, "0.12.9");

        assert_eq!(changes[1].name, "serde");
        assert_eq!(changes[1].old_version.as_deref(), Some("1.0.200"));
        assert_eq!(changes[1].new_version, "1.0.210");
    }
}
