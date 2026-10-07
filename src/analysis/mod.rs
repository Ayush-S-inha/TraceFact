use std::collections::BTreeSet;

use crate::model::{
    BehaviorChange, ChangeKind, PassportObservations, RuntimePassport, RuntimeSnapshot,
};

pub fn passport_from_snapshot(snapshot: &RuntimeSnapshot, generated_at_ms: i64) -> RuntimePassport {
    let mut observations = PassportObservations::default();

    for event in &snapshot.events {
        match event.event_type {
            crate::model::EventType::ProcessStart
            | crate::model::EventType::ProcessExit
            | crate::model::EventType::ProcessObserved => {
                observations
                    .processes
                    .push(event.process.executable.clone());
            }
            crate::model::EventType::NetworkConnection | crate::model::EventType::DnsLookup => {
                if let Some(target) = &event.target {
                    observations.network_targets.push(target.clone());
                }
            }
            crate::model::EventType::FileAccess => {
                if let Some(target) = &event.target {
                    observations.files.push(target.clone());
                }
            }
            crate::model::EventType::LibraryLoaded => {
                if let Some(target) = &event.target {
                    observations.libraries.push(target.clone());
                }
            }
            crate::model::EventType::EnvironmentVariableUsed => {}
        }
    }

    dedupe(&mut observations.processes);
    dedupe(&mut observations.network_targets);
    dedupe(&mut observations.files);
    dedupe(&mut observations.libraries);

    RuntimePassport {
        schema_version: "0.1".into(),
        passport_id: format!("passport-{}", snapshot.snapshot_id),
        generated_at_ms,
        application: snapshot.application.clone(),
        observations,
        changes: vec![],
    }
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

fn dedupe(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}
