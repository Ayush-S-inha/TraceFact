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
    pub root_pid: Option<u32>,
    pub includes_descendants: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCoverage {
    pub event_count: u64,
    pub event_counts_by_type: BTreeMap<String, u64>,
    pub collector_sources: Vec<String>,
    pub limitations: Vec<String>,
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
