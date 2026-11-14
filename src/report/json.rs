//! Pretty JSON report renderer.

use crate::error::Result;
use crate::types::AnalysisReport;

/// Renders an `AnalysisReport` as pretty-printed JSON.
pub fn render(report: &AnalysisReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
