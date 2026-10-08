use std::collections::BTreeSet;

use crate::model::{
    BehaviorChange, ChangeKind, EventType, PassportObservations, RuntimeEvent, RuntimePassport,
    RuntimeSnapshot,
};

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
