//! Local disk cache lookup for `.crate` and `.tgz` tarballs, including Cargo's registry cache.

use crate::types::Ecosystem;
use std::path::{Path, PathBuf};

/// Resolves the `dep-xray` cache directory.
pub fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("dep-xray")
}

/// Sanitizes a package name for safe filename usage (e.g. `@scope/pkg` -> `@scope__pkg`).
pub fn cache_filename(ecosystem: Ecosystem, name: &str, version: &str) -> String {
    let safe_name = name.replace('/', "__");
    let ext = match ecosystem {
        Ecosystem::Cargo => "crate",
        Ecosystem::Npm => "tgz",
    };
    format!("{safe_name}-{version}.{ext}")
}

/// Searches `~/.cargo/registry/cache/*/<name>-<version>.crate` for an existing tarball.
pub fn find_in_cargo_registry_cache(name: &str, version: &str) -> Option<PathBuf> {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".cargo")))?;

    let cache_root = cargo_home.join("registry").join("cache");
    let entries = std::fs::read_dir(cache_root).ok()?;
    let target_name = format!("{name}-{version}.crate");

    for entry in entries.flatten() {
        let candidate = entry.path().join(&target_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Checks `offline_dir`, `dep-xray` cache, and (for Cargo) Cargo's registry cache.
pub fn find_cached_tarball(
    cache_dir: &Path,
    offline_dir: Option<&Path>,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Option<PathBuf> {
    let filename = cache_filename(ecosystem, name, version);

    if let Some(dir) = offline_dir {
        let candidate = dir.join(&filename);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    let own_cached = cache_dir.join(ecosystem.to_string()).join(&filename);
    if own_cached.is_file() {
        return Some(own_cached);
    }

    if ecosystem == Ecosystem::Cargo {
        return find_in_cargo_registry_cache(name, version);
    }

    None
}
