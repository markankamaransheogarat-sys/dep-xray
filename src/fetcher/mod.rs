//! Asynchronous parallel package tarball fetcher with local caching and offline fixture support.

pub mod archive;
pub mod cache;

use crate::error::{DepXrayError, Result};
use crate::types::{Ecosystem, PackageChange};
use archive::{PackageFiles, extract_tar_gz};
use cache::{cache_filename, default_cache_dir, find_cached_tarball};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Configuration for fetching package tarballs.
#[derive(Debug, Clone)]
pub struct FetcherConfig {
    pub cache_dir: PathBuf,
    pub offline_dir: Option<PathBuf>,
    pub offline_only: bool,
    pub max_concurrency: usize,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            offline_dir: None,
            offline_only: false,
            max_concurrency: 16,
        }
    }
}

/// Extracted source files for the old (if any) and new versions of a package.
#[derive(Debug, Clone)]
pub struct FetchedPackagePair {
    pub change: PackageChange,
    pub old_files: Option<PackageFiles>,
    pub new_files: PackageFiles,
}

/// Fetches and unpacks tarballs from local cache, offline fixtures, or upstream registries.
#[derive(Clone)]
pub struct PackageFetcher {
    client: reqwest::Client,
    config: FetcherConfig,
    semaphore: Arc<Semaphore>,
}

impl PackageFetcher {
    /// Creates a new `PackageFetcher` with the given configuration.
    pub fn new(config: FetcherConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("dep-xray/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        let concurrency = config.max_concurrency.max(1);
        Ok(Self {
            client,
            config,
            semaphore: Arc::new(Semaphore::new(concurrency)),
        })
    }

    /// Fetches both old (if upgrade) and new tarballs for a single `PackageChange`.
    pub async fn fetch_pair(&self, change: PackageChange) -> Result<FetchedPackagePair> {
        let new_fut = self.fetch_one(
            change.ecosystem,
            &change.name,
            &change.new_version,
            change.resolved_tarball_url.as_deref(),
        );

        let old_fut = async {
            if let Some(old_ver) = &change.old_version {
                Ok(Some(
                    self.fetch_one(change.ecosystem, &change.name, old_ver, None)
                        .await?,
                ))
            } else {
                Ok(None)
            }
        };

        let (old_files, new_files) = tokio::try_join!(old_fut, new_fut)?;
        Ok(FetchedPackagePair {
            change,
            old_files,
            new_files,
        })
    }

    /// Fetches all changed packages concurrently.
    pub async fn fetch_all(&self, changes: Vec<PackageChange>) -> Result<Vec<FetchedPackagePair>> {
        let mut handles = Vec::with_capacity(changes.len());
        for change in changes {
            let fetcher = self.clone();
            handles.push(tokio::spawn(
                async move { fetcher.fetch_pair(change).await },
            ));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            let pair = handle.await.map_err(|e| DepXrayError::Analysis {
                message: format!("fetch task panicked: {e}"),
            })??;
            results.push(pair);
        }
        Ok(results)
    }

    async fn fetch_one(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        resolved_url: Option<&str>,
    ) -> Result<PackageFiles> {
        let label = format!("{name}@{version}");

        if let Some(cached_path) = find_cached_tarball(
            &self.config.cache_dir,
            self.config.offline_dir.as_deref(),
            ecosystem,
            name,
            version,
        ) {
            let bytes = tokio::fs::read(&cached_path).await?;
            return extract_tar_gz(&label, &bytes);
        }

        if self.config.offline_only {
            return Err(DepXrayError::Archive {
                package: label,
                message: "tarball not found in local cache or offline directory".to_string(),
            });
        }

        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| DepXrayError::Analysis {
                message: format!("semaphore closed: {e}"),
            })?;

        let bytes = self
            .download_tarball(ecosystem, name, version, resolved_url)
            .await?;

        // Persist to dep-xray cache for future runs.
        let dest_dir = self.config.cache_dir.join(ecosystem.to_string());
        let _ = tokio::fs::create_dir_all(&dest_dir).await;
        let dest_file = dest_dir.join(cache_filename(ecosystem, name, version));
        let _ = tokio::fs::write(&dest_file, &bytes).await;

        extract_tar_gz(&label, &bytes)
    }

    async fn download_tarball(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        resolved_url: Option<&str>,
    ) -> Result<Vec<u8>> {
        let urls = tarball_urls(ecosystem, name, version, resolved_url);
        let label = format!("{name}@{version}");
        let mut last_status = 0u16;
        let mut last_err = String::new();

        for url in urls {
            match self.client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if resp.status().is_success() {
                        let data = resp.bytes().await?;
                        return Ok(data.to_vec());
                    }
                    last_status = status;
                    last_err = format!("HTTP {status} from {url}");
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
        }

        Err(DepXrayError::Registry {
            package: label,
            status: last_status,
            message: last_err,
        })
    }
}

fn tarball_urls(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    resolved_url: Option<&str>,
) -> Vec<String> {
    match ecosystem {
        Ecosystem::Cargo => vec![
            format!("https://static.crates.io/crates/{name}/{name}-{version}.crate"),
            format!("https://crates.io/api/v1/crates/{name}/{version}/download"),
        ],
        Ecosystem::Npm => {
            let mut urls = Vec::new();
            if let Some(u) = resolved_url {
                urls.push(u.to_string());
            }
            let unscoped = name.rsplit('/').next().unwrap_or(name);
            urls.push(format!(
                "https://registry.npmjs.org/{name}/-/{unscoped}-{version}.tgz"
            ));
            urls
        }
    }
}
