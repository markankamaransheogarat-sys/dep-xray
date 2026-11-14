//! Tarball extraction for `.crate` and `.tgz` archives into normalized in-memory file maps.

use crate::error::{DepXrayError, Result};
use flate2::read::GzDecoder;
use std::collections::BTreeMap;
use std::io::Read;
use tar::Archive;

/// Maximum individual file size (2 MiB) to read into memory for AST analysis.
const MAX_SOURCE_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Map of normalized relative file path -> UTF-8 source contents.
pub type PackageFiles = BTreeMap<String, String>;

/// Strips the standard top-level archive directory prefix:
/// - `.crate` archives wrap files in `<name>-<version>/...`
/// - `.tgz` npm tarballs wrap files in `package/...` (or `<name>/...`)
fn normalize_archive_path(raw: &str) -> Option<String> {
    let cleaned = raw.trim_start_matches("./").replace('\\', "/");
    let stripped = match cleaned.split_once('/') {
        Some((_top, rest)) if !rest.is_empty() => rest,
        _ => return None,
    };
    Some(stripped.to_string())
}

/// Extracts all UTF-8 text/source files from a `.crate` or `.tgz` gzipped tarball.
pub fn extract_tar_gz(package_label: &str, bytes: &[u8]) -> Result<PackageFiles> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = Archive::new(decoder);
    let mut files = BTreeMap::new();

    let entries = archive.entries().map_err(|e| DepXrayError::Archive {
        package: package_label.to_string(),
        message: e.to_string(),
    })?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| DepXrayError::Archive {
            package: package_label.to_string(),
            message: e.to_string(),
        })?;

        if !entry.header().entry_type().is_file() {
            continue;
        }
        if entry.size() > MAX_SOURCE_FILE_BYTES {
            continue;
        }

        let raw_path = entry
            .path()
            .map_err(|e| DepXrayError::Archive {
                package: package_label.to_string(),
                message: e.to_string(),
            })?
            .to_string_lossy()
            .into_owned();

        let Some(rel_path) = normalize_archive_path(&raw_path) else {
            continue;
        };

        let mut buf = Vec::with_capacity(entry.size() as usize);
        if entry.read_to_end(&mut buf).is_err() {
            continue;
        }

        // Skip binary files; only keep valid UTF-8 text.
        if let Ok(text) = String::from_utf8(buf) {
            files.insert(rel_path, text);
        }
    }

    Ok(files)
}
