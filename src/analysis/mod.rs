use std::collections::BTreeSet;

use crate::model::{
    BehaviorChange, ChangeKind, EventType, EvidenceBundle, EvidenceCoverage, EvidenceEvent,
    EvidenceRunMetadata, EvidenceScope, PassportObservations, RuntimeEvent, RuntimePassport,
    RuntimeSnapshot,
};
use crate::storage::StoredRun;

#[derive(Debug, Default)]
pub struct PassportAccumulator {
    processes: BTreeSet<String>,
    network_targets: BTreeSet<String>,
    files: BTreeSet<String>,
    libraries: BTreeSet<String>,
}

impl PassportAccumulator {
    pub fn observe(&mut self, event: &RuntimeEvent) {
        match event.event_type {
            EventType::ProcessStart | EventType::ProcessExit | EventType::ProcessObserved => {
                self.processes.insert(event.process.executable.clone());
            }
            EventType::NetworkConnection | EventType::DnsLookup => {
                if let Some(target) = &event.target {
                    self.network_targets.insert(target.clone());
                }
            }
            EventType::FileAccess => {
                if let Some(target) = &event.target {
                    self.files.insert(target.clone());
                }
            }
            EventType::LibraryLoaded => {
                if let Some(target) = &event.target {
                    self.libraries.insert(target.clone());
                }
            }
            EventType::EnvironmentVariableUsed => {}
        }
    }

    pub fn finish(
        self,
        snapshot_id: &str,
        generated_at_ms: i64,
        application: &str,
    ) -> RuntimePassport {
        RuntimePassport {
            schema_version: "0.1".into(),
            passport_id: format!("passport-{snapshot_id}"),
            generated_at_ms,
            application: application.to_string(),
            observations: PassportObservations {
                processes: self.processes.into_iter().collect(),
                network_targets: self.network_targets.into_iter().collect(),
                files: self.files.into_iter().collect(),
                libraries: self.libraries.into_iter().collect(),
            },
            changes: vec![],
        }
    }
}

pub fn passport_from_snapshot(snapshot: &RuntimeSnapshot, generated_at_ms: i64) -> RuntimePassport {
    let mut accumulator = PassportAccumulator::default();

    for event in &snapshot.events {
        accumulator.observe(event);
    }

    accumulator.finish(
        &snapshot.snapshot_id,
        generated_at_ms,
        &snapshot.application,
    )
}

pub fn compare(a: &RuntimePassport, b: &RuntimePassport) -> Vec<BehaviorChange> {
    let mut changes = Vec::new();
    compare_set(
        &mut changes,
        "process",
        &a.observations.processes,
        &b.observations.processes,
    );
    compare_set(
        &mut changes,
        "network",
        &a.observations.network_targets,
        &b.observations.network_targets,
    );
    compare_set(
        &mut changes,
        "filesystem",
        &a.observations.files,
        &b.observations.files,
    );
    compare_set(
        &mut changes,
        "library",
        &a.observations.libraries,
        &b.observations.libraries,
    );
    changes
}

fn compare_set(changes: &mut Vec<BehaviorChange>, category: &str, old: &[String], new: &[String]) {
    let old_set: BTreeSet<&str> = old.iter().map(String::as_str).collect();
    let new_set: BTreeSet<&str> = new.iter().map(String::as_str).collect();

    for item in new_set.difference(&old_set) {
        changes.push(BehaviorChange {
            kind: ChangeKind::Added,
            category: category.into(),
            subject: (*item).into(),
            reason: format!("It was seen in the current run but not in the baseline."),
        });
    }

    for item in old_set.difference(&new_set) {
        changes.push(BehaviorChange {
            kind: ChangeKind::Removed,
            category: category.into(),
            subject: (*item).into(),
            reason: format!("It was seen in the baseline but not in the current run."),
        });
    }
}

/// Builds a portable evidence bundle from a saved run.
/// Empty categories are described as unobserved, never as proof that behavior did not occur.
pub fn evidence_bundle_from_run(
    run: &StoredRun,
    exported_at_ms: i64,
) -> Result<EvidenceBundle, String> {
    use std::collections::BTreeMap;

    let mut event_counts_by_type = BTreeMap::<String, u64>::new();
    let mut collector_sources = BTreeSet::<String>::new();
    let mut events = Vec::with_capacity(run.events.len());
    let mut root_pid = None;

    for event in &run.events {
        collector_sources.insert(event.source.clone());
        *event_counts_by_type
            .entry(event.event_type.clone())
            .or_insert(0) += 1;

        let metadata: serde_json::Value =
            serde_json::from_str(&event.metadata_json).map_err(|error| {
                format!(
                    "Stored event {} contains invalid metadata JSON: {error}",
                    event.event_id
                )
            })?;
        if !metadata.is_object() {
            return Err(format!(
                "Stored event {} metadata must be a JSON object.",
                event.event_id
            ));
        }

        if root_pid.is_none() {
            root_pid = metadata
                .get("root_pid")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());
        }

        if root_pid.is_none()
            && event.event_type.starts_with("process_")
            && metadata.get("depth").and_then(serde_json::Value::as_u64) == Some(0)
        {
            root_pid = event.pid;
        }

        events.push(EvidenceEvent {
            event_id: event.event_id.clone(),
            timestamp_ms: event.timestamp_ms,
            event_type: event.event_type.clone(),
            pid: event.pid,
            executable: event.executable.clone(),
            subject: event.subject.clone(),
            target: event.target.clone(),
            metadata,
            source: event.source.clone(),
            sensitivity: event.sensitivity.clone(),
        });
    }

    let has_windows_provenance = collector_sources
        .iter()
        .any(|source| source.starts_with("windows_"));
    let is_watch = collector_sources
        .iter()
        .any(|source| source == "windows_process_watch");
    let network_event_count = event_counts_by_type
        .get("network_connection")
        .copied()
        .unwrap_or(0);

    let scope_kind = if is_watch {
        "selected_process_tree_watch"
    } else if has_windows_provenance {
        "selected_process_tree_snapshot"
    } else {
        "unknown"
    };
    let platform = if has_windows_provenance {
        "windows"
    } else {
        "unknown"
    };

    let mut limitations = vec![
        "An absent event is not proof that the behavior did not occur.".to_string(),
        "Filesystem access and loaded-library observation are not implemented in this checkpoint."
            .to_string(),
    ];

    if !is_watch {
        limitations.push(
            "This is a point-in-time process snapshot; network collection runs only in watch mode."
                .to_string(),
        );
    } else if network_event_count == 0 {
        limitations.push(
            "No network connection events were stored. This is not proof that no network activity occurred."
                .to_string(),
        );
    }

    if run.status != "completed" {
        limitations.push(format!(
            "The source run status is '{}'; treat this evidence as potentially incomplete.",
            run.status
        ));
    }

    Ok(EvidenceBundle {
        bundle_schema_version: "1.0".to_string(),
        exported_at_ms,
        run: EvidenceRunMetadata {
            run_id: run.run_id.clone(),
            application: run.application.clone(),
            started_at_ms: run.started_at_ms,
            ended_at_ms: run.ended_at_ms,
            status: run.status.clone(),
            schema_version: run.schema_version.clone(),
        },
        scope: EvidenceScope {
            platform: platform.to_string(),
            kind: scope_kind.to_string(),
            root_pid,
            includes_descendants: has_windows_provenance,
        },
        coverage: EvidenceCoverage {
            event_count: events.len() as u64,
            event_counts_by_type,
            collector_sources: collector_sources.into_iter().collect(),
            limitations,
        },
        passport: run.passport.clone(),
        events,
    })
}

#[cfg(test)]
mod evidence_bundle_tests {
    use super::evidence_bundle_from_run;
    use crate::model::{PassportObservations, RuntimePassport};
    use crate::storage::{StoredEvent, StoredRun};

    fn sample_run(status: &str) -> StoredRun {
        StoredRun {
            run_id: "watch-100-42".to_string(),
            application: "demo.exe".to_string(),
            started_at_ms: 100,
            ended_at_ms: Some(200),
            status: status.to_string(),
            schema_version: "0.1".to_string(),
            passport: RuntimePassport {
                schema_version: "0.1".to_string(),
                passport_id: "passport-watch-100-42".to_string(),
                generated_at_ms: 200,
                application: "demo.exe".to_string(),
                observations: PassportObservations {
                    processes: vec!["demo.exe".to_string()],
                    network_targets: vec![],
                    files: vec![],
                    libraries: vec![],
                },
                changes: vec![],
            },
            events: vec![
                StoredEvent {
                    event_id: "process-event".to_string(),
                    timestamp_ms: 110,
                    event_type: "process_observed".to_string(),
                    pid: Some(42),
                    executable: Some("demo.exe".to_string()),
                    subject: Some("process".to_string()),
                    target: Some("demo.exe".to_string()),
                    metadata_json: r#"{"root_pid":42,"depth":0}"#.to_string(),
                    source: "windows_process_watch".to_string(),
                    sensitivity: "SystemMetadata".to_string(),
                },
                StoredEvent {
                    event_id: "network-event".to_string(),
                    timestamp_ms: 120,
                    event_type: "network_connection".to_string(),
                    pid: Some(42),
                    executable: Some("demo.exe".to_string()),
                    subject: Some("tcp".to_string()),
                    target: Some("203.0.113.10:443".to_string()),
                    metadata_json: r#"{"protocol":"tcp","operation":"connect"}"#.to_string(),
                    source: "windows_network_watch".to_string(),
                    sensitivity: "SystemMetadata".to_string(),
                },
            ],
        }
    }

    #[test]
    fn evidence_bundle_preserves_provenance_and_coverage_limitations() {
        let run = sample_run("completed");
        let bundle = evidence_bundle_from_run(&run, 300).expect("bundle should be built");

        assert_eq!(bundle.bundle_schema_version, "1.0");
        assert_eq!(bundle.run.run_id, "watch-100-42");
        assert_eq!(bundle.scope.platform, "windows");
        assert_eq!(bundle.scope.kind, "selected_process_tree_watch");
        assert_eq!(bundle.scope.root_pid, Some(42));
        assert!(bundle.scope.includes_descendants);
        assert_eq!(bundle.coverage.event_count, 2);
        assert_eq!(
            bundle.coverage.event_counts_by_type["network_connection"],
            1
        );
        assert_eq!(bundle.coverage.collector_sources.len(), 2);
        assert_eq!(bundle.events[1].metadata["protocol"], "tcp");
        assert!(bundle
            .coverage
            .limitations
            .iter()
            .any(|note| note.contains("not implemented")));
    }

    #[test]
    fn incomplete_source_run_is_explicit_in_evidence_limitations() {
        let run = sample_run("interrupted");
        let bundle = evidence_bundle_from_run(&run, 300).expect("bundle should be built");
        assert!(bundle
            .coverage
            .limitations
            .iter()
            .any(|note| note.contains("interrupted")));
    }

    #[test]
    fn malformed_stored_metadata_prevents_silent_export() {
        let mut run = sample_run("completed");
        run.events[0].metadata_json = "{not valid JSON".to_string();
        let error = evidence_bundle_from_run(&run, 300).expect_err("invalid metadata must fail");
        assert!(error.contains("invalid metadata JSON"));
    }

    #[test]
    fn non_object_metadata_is_rejected_by_evidence_export() {
        let mut run = sample_run("completed");
        run.events[0].metadata_json = "42".to_string();
        let error = evidence_bundle_from_run(&run, 300).expect_err("non-object metadata must fail");
        assert!(error.contains("must be a JSON object"));
    }
}
