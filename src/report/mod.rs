//! Report renderers for Terminal, Markdown PR comments, SARIF 2.1.0, and JSON.

pub mod json;
pub mod markdown;
pub mod sarif;
pub mod terminal;

use crate::error::Result;
use crate::types::AnalysisReport;
use clap::ValueEnum;

/// Output format for `dep-xray` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Markdown,
    Sarif,
    Json,
}

/// Renders an `AnalysisReport` in the requested format.
pub fn render_report(report: &AnalysisReport, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Terminal => Ok(terminal::render(report)),
        OutputFormat::Markdown => Ok(markdown::render(report)),
        OutputFormat::Sarif => sarif::render(report),
        OutputFormat::Json => json::render(report),
    }
}
