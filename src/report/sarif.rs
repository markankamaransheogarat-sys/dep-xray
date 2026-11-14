//! SARIF 2.1.0 report renderer for GitHub Code Scanning / Security integration.

use crate::error::Result;
use crate::types::{AnalysisReport, Finding, Severity};
use serde::Serialize;
use std::collections::BTreeMap;

const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

#[derive(Serialize)]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver<'a> {
    name: &'static str,
    version: &'a str,
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
    start_column: usize,
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Info => "note",
    }
}

/// Renders an `AnalysisReport` as a SARIF 2.1.0 JSON document.
pub fn render(report: &AnalysisReport) -> Result<String> {
    let mut rules_map: BTreeMap<String, SarifRule> = BTreeMap::new();
    let mut results = Vec::new();

    for pkg in &report.packages {
        for f in &pkg.findings {
            insert_rule(&mut rules_map, f);
            results.push(SarifResult {
                rule_id: f.id.clone(),
                level: sarif_level(f.severity),
                message: SarifMessage {
                    text: format!(
                        "[{}] {}@{} ({}): {} — {}",
                        f.severity,
                        f.package_name,
                        f.package_version,
                        f.category,
                        f.title,
                        f.description
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: format!(
                                "{}/{}/{}",
                                f.package_name, f.package_version, f.file_path
                            ),
                        },
                        region: SarifRegion {
                            start_line: f.line.max(1),
                            start_column: f.column.max(1),
                        },
                    },
                }],
            });
        }
    }

    let log = SarifLog {
        schema: SARIF_SCHEMA,
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "dep-xray",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/markankamaransheogarat-sys/dep-xray",
                    rules: rules_map.into_values().collect(),
                },
            },
            results,
        }],
    };

    Ok(serde_json::to_string_pretty(&log)?)
}

fn insert_rule(rules_map: &mut BTreeMap<String, SarifRule>, f: &Finding) {
    rules_map.entry(f.id.clone()).or_insert_with(|| SarifRule {
        id: f.id.clone(),
        name: f.category.to_string(),
        short_description: SarifMessage {
            text: f.title.clone(),
        },
    });
}
