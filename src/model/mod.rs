use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessStart,
    ProcessExit,
    ProcessObserved,
    NetworkConnection,
    FileAccess,
    LibraryLoaded,
    DnsLookup,
    EnvironmentVariableUsed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sensitivity {
    SystemMetadata,
    PotentiallySensitive,
    Sensitive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub executable: String,
    pub command_line: Option<String>,
    pub parent_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub id: String,
    pub timestamp_ms: i64,
    pub event_type: EventType,
    pub process: ProcessIdentity,
    pub subject: String,
    pub target: Option<String>,
    pub metadata: serde_json::Value,
    pub source: String,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSnapshot {
    pub schema_version: String,
    pub snapshot_id: String,
    pub application: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub events: Vec<RuntimeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorChange {
    pub kind: ChangeKind,
    pub category: String,
    pub subject: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePassport {
    pub schema_version: String,
    pub passport_id: String,
    pub generated_at_ms: i64,
    pub application: String,
    pub observations: PassportObservations,
    pub changes: Vec<BehaviorChange>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PassportObservations {
    pub processes: Vec<String>,
    pub network_targets: Vec<String>,
    pub files: Vec<String>,
    pub libraries: Vec<String>,
}

/// Portable evidence for one saved TraceFact run.
/// This format is independent of the local UI and SQLite database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub bundle_schema_version: String,
    pub exported_at_ms: i64,
    pub run: EvidenceRunMetadata,
    pub scope: EvidenceScope,
    pub coverage: EvidenceCoverage,
    pub passport: RuntimePassport,
    pub events: Vec<EvidenceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRunMetadata {
    pub run_id: String,
    pub application: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub status: String,
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceScope {
    /// Operating system inferred from the collector provenance, or "unknown".
    pub platform: String,
    /// "selected_process_tree_snapshot", "selected_process_tree_watch", or "unknown".
    pub kind: String,
    /// The root PID when it can be recovered from stored metadata.
    pub root_pid: Option<u32>,
    /// Whether the collector scope is intended to include descendants. This does not
    /// prove that descendants existed or that all descendants were observed.
    pub includes_descendants: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCoverage {
    pub event_count: u64,
    pub event_counts_by_type: BTreeMap<String, u64>,
    pub collector_sources: Vec<String>,
    pub limitations: Vec<String>,
}

/// A named, local baseline captured from a finalized Runtime Passport.
/// `name` is the user-facing identity and is unique case-insensitively in local storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePassportBaseline {
    pub baseline_schema_version: String,
    pub name: String,
    pub created_at_ms: i64,
    pub source_run_id: String,
    pub application: String,
    pub passport: RuntimePassport,
    pub scope: EvidenceScope,
    pub coverage: EvidenceCoverage,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEvent {
    pub event_id: String,
    pub timestamp_ms: i64,
    pub event_type: String,
    pub pid: Option<u32>,
    pub executable: Option<String>,
    pub subject: Option<String>,
    pub target: Option<String>,
    pub metadata: serde_json::Value,
    pub source: String,
    pub sensitivity: String,
}

/// Deterministic comparison of a saved Runtime Passport baseline and a completed run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorDriftReport {
    pub comparison_schema_version: String,
    pub generated_at_ms: i64,
    pub baseline_name: String,
    pub baseline_source_run_id: String,
    pub current_run_id: String,
    pub application: String,
    /// False when the scope is not like-for-like or cannot be identified.
    pub comparable: bool,
    pub baseline_scope: EvidenceScope,
    pub current_scope: EvidenceScope,
    pub baseline_collector_sources: Vec<String>,
    pub current_collector_sources: Vec<String>,
    pub baseline_event_count: u64,
    pub current_event_count: u64,
    pub baseline_event_counts_by_type: BTreeMap<String, u64>,
    pub current_event_counts_by_type: BTreeMap<String, u64>,
    pub compared_categories: Vec<String>,
    pub skipped_categories: Vec<String>,
    pub findings: Vec<DriftFinding>,
    pub coverage_changes: Vec<CoverageChange>,
    pub limitations: Vec<String>,
}

/// A Passport observation difference with references to the source event records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftFinding {
    pub finding_id: String,
    /// `added` or `not_observed`; absence is not represented as proof of removal.
    pub kind: String,
    pub category: String,
    pub observation: String,
    pub explanation: String,
    /// Event IDs in the baseline source run that match the observation.
    pub baseline_event_ids: Vec<String>,
    /// Event IDs in the current run that directly match the observation.
    pub current_event_ids: Vec<String>,
    /// Same-category current-run event IDs reviewed for `not_observed` findings.
    pub current_context_event_ids: Vec<String>,
}

/// A difference in the recorded collection scope or event-source provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageChange {
    pub kind: String,
    pub category: String,
    pub baseline_value: Option<String>,
    pub current_value: Option<String>,
    pub explanation: String,
}
