use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessStart,
    ProcessExit,
    NetworkConnection,
    FileAccess,
    LibraryLoaded,
    DnsLookup,
    EnvironmentVariableUsed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sensitivity {
    PublicMetadata,
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
