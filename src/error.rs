//! Error types for `dep-xray`.

use thiserror::Error;

/// Unified result type for `dep-xray`.
pub type Result<T> = std::result::Result<T, DepXrayError>;

/// Errors produced by `dep-xray`.
#[derive(Debug, Error)]
pub enum DepXrayError {
    /// Git command failed or repository state could not be read.
    #[error("git error: {message}")]
    Git { message: String },

    /// Failed to parse a lockfile.
    #[error("failed to parse lockfile `{path}`: {message}")]
    LockfileParse { path: String, message: String },

    /// HTTP request error while fetching a package tarball.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// Registry returned a non-success response or invalid metadata.
    #[error("registry error for `{package}` (status {status}): {message}")]
    Registry {
        package: String,
        status: u16,
        message: String,
    },

    /// Failed to unpack or read a package archive.
    #[error("archive error for `{package}`: {message}")]
    Archive { package: String, message: String },

    /// Filesystem I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Tree-sitter or AST analysis error.
    #[error("analysis error: {message}")]
    Analysis { message: String },

    /// JSON serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
