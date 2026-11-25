use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    BehaviorDriftReport, CoverageChange, DriftFinding, EventType, EvidenceBundle, EvidenceCoverage,
    EvidenceEvent, EvidenceRunMetadata, EvidenceScope, PassportObservations, RuntimeEvent,
    RuntimePassport, RuntimePassportBaseline, RuntimeSnapshot,
};
use crate::storage::StoredRun;

const MAX_INITIAL_FILES_EVIDENCE_NOTE: u64 = 10_000;

#[derive(Debug, Default, Clone)]
pub struct PassportAccumulator {
    processes: BTreeSet<String>,
    network_targets: BTreeSet<String>,
    files: BTreeSet<String>,
    libraries: BTreeSet<String>,
}

impl PassportAccumulator {
    pub fn observe(&mut self, event: &RuntimeEvent) {
        match event.event_type {
            EventType::ProcessStart | EventType::ProcessExit | EventType::ProcessObserved
                if event.subject != "watch_summary" =>
            {
                self.processes.insert(event.process.executable.clone());
            }
            EventType::ProcessStart | EventType::ProcessExit | EventType::ProcessObserved => {}
            EventType::NetworkConnection | EventType::DnsLookup => {
                if let Some(target) = &event.target {
                    self.network_targets.insert(target.clone());
                }
            }
            EventType::NetworkWatchSummary => {}
            EventType::FileAccess | EventType::FileObserved => {
                if let Some(target) = &event.target {
                    self.files.insert(target.clone());
                }
            }
            EventType::FileChange => {
                if let Some(target) = &event.target {
                    match event
                        .metadata
                        .get("operation")
                        .and_then(serde_json::Value::as_str)
                    {
                        Some("removed") => {
                            remove_path_and_descendants(&mut self.files, target);
                        }
                        Some("renamed_from") => {
                            if let Some(new_path) = event
                                .metadata
                                .get("related_path")
                                .and_then(serde_json::Value::as_str)
                            {
                                rename_path_and_descendants(&mut self.files, target, new_path);
                            } else {
                                remove_path_and_descendants(&mut self.files, target);
                            }
                        }
                        Some("created" | "modified" | "renamed_to" | "renamed") => {
                            self.files.insert(target.clone());
                        }
                        _ => {}
                    }
                }
            }
            EventType::LibraryLoaded => {
                if let Some(target) = &event.target {
                    self.libraries.insert(target.clone());
                }
            }
            EventType::EnvironmentVariableUsed | EventType::LibraryInventoryStatus => {}
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

fn remove_path_and_descendants(files: &mut BTreeSet<String>, path: &str) {
    let prefix = format!("{}/", path.trim_end_matches('/'));
    files.retain(|item| item != path && !item.starts_with(&prefix));
}

fn rename_path_and_descendants(files: &mut BTreeSet<String>, old_path: &str, new_path: &str) {
    let prefix = format!("{}/", old_path.trim_end_matches('/'));
    let affected: Vec<String> = files
        .iter()
        .filter(|item| *item == old_path || item.starts_with(&prefix))
        .cloned()
        .collect();
    for item in affected {
        files.remove(&item);
        let suffix = if item == old_path {
            ""
        } else {
            item.strip_prefix(&prefix).unwrap_or_default()
        };
        let renamed = if suffix.is_empty() {
            new_path.to_string()
        } else {
            format!("{}/{}", new_path.trim_end_matches('/'), suffix)
        };
        files.insert(renamed);
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

/// Builds a portable evidence bundle from a saved run.
/// Empty categories are described as unobserved, never as proof that behavior did not occur.
pub fn evidence_bundle_from_run(
    run: &StoredRun,
    exported_at_ms: i64,
) -> Result<EvidenceBundle, String> {
    let mut event_counts_by_type = BTreeMap::<String, u64>::new();
    let mut collector_sources = BTreeSet::<String>::new();
    let mut events = Vec::with_capacity(run.events.len());
    let mut root_pids = BTreeSet::new();
    let mut module_summary_count = 0usize;
    let mut module_inventory_complete = false;

    for event in &run.events {
        collector_sources.insert(event.source.clone());
        let count = event_counts_by_type
            .entry(event.event_type.clone())
            .or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or_else(|| "An event-type count exceeds the evidence format limit.".to_string())?;

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

        if event.source == "windows_module_snapshot"
            && event.event_type == "library_inventory_status"
            && event.subject.as_deref() == Some("inventory_summary")
        {
            module_summary_count += 1;
            module_inventory_complete = metadata
                .get("complete")
                .and_then(serde_json::Value::as_bool)
                == Some(true);
        }

        if let Some(pid) = metadata
            .get("root_pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|pid| *pid > 0)
        {
            root_pids.insert(pid);
        } else if event.event_type.starts_with("process_")
            && metadata.get("depth").and_then(serde_json::Value::as_u64) == Some(0)
        {
            if let Some(pid) = event.pid.filter(|pid| *pid > 0) {
                root_pids.insert(pid);
            }
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

    let root_pid = if root_pids.len() == 1 {
        root_pids.iter().next().copied()
    } else {
        None
    };
    let event_count = u64::try_from(events.len()).map_err(|_| {
        "The run contains more events than the evidence format can represent.".to_string()
    })?;

    let has_windows_provenance = collector_sources
        .iter()
        .any(|source| source.starts_with("windows_"));
    let is_watch = collector_sources
        .iter()
        .any(|source| source == "windows_process_watch");
    let is_filesystem_watch = collector_sources
        .iter()
        .any(|source| source == "windows_filesystem_watch");
    let is_module_snapshot = collector_sources
        .iter()
        .any(|source| source == "windows_module_snapshot");
    let network_event_count = event_counts_by_type
        .get("network_connection")
        .copied()
        .unwrap_or(0);

    let scope_kind = if is_filesystem_watch {
        "selected_directory_watch"
    } else if is_watch {
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

    let mut limitations =
        vec!["An absent event is not proof that the behavior did not occur.".to_string()];
    if root_pids.len() > 1 {
        limitations.push(
            "Stored events identify multiple root process IDs; the evidence bundle leaves the root PID unspecified.".to_string(),
        );
    }

    if is_watch {
        match process_watch_loss_counts(run) {
            Some((0, 0, 0, 0)) => {}
            Some((dropped_starts, dropped_exits, unpersisted, unclassified)) => {
                limitations.push(format!(
                    "The process watch did not persist {dropped_starts} start-event records, {dropped_exits} exit-event records, {unpersisted} queued or failed event records, and {unclassified} events that could not be reconciled; process-set comparison is skipped."
                ));
            }
            None => limitations.push(
                "The process watch has no single valid queue-coverage summary; process-set comparison is skipped."
                    .to_string(),
            ),
        }

        if !network_watch_coverage_complete(run) {
            limitations.push(
                "The network observer has no valid complete coverage summary, or it reported dropped, undecodable, unattributed, or unpersisted observations; network-target comparison is skipped.".to_string(),
            );
        }
        limitations.push(
            "A complete observer summary covers TraceFact's visible queues and persistence accounting; it does not prove Windows or ETW delivered every event that could have matched the selected process tree.".to_string(),
        );
    }

    if is_filesystem_watch {
        limitations.push(
            "Filesystem observation covers a bounded initial directory inventory and change notifications; it does not record file contents, file reads, or the process responsible for a change.".to_string(),
        );
        limitations.push(
            "Filesystem notifications may be coalesced or lost under load. Inspect the watch summary and queue-drop count before interpreting the run.".to_string(),
        );
        for event in &events {
            if event.source != "windows_filesystem_watch" || event.event_type != "file_change" {
                continue;
            }
            let metadata = &event.metadata;
            if metadata
                .get("operation")
                .and_then(serde_json::Value::as_str)
                == Some("watch_summary")
            {
                if metadata
                    .get("initial_inventory_truncated")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    let maximum = metadata
                        .get("maximum_initial_inventory_entries")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(MAX_INITIAL_FILES_EVIDENCE_NOTE);
                    limitations.push(format!("The initial filesystem inventory was capped at {maximum} entries; the directory baseline is incomplete."));
                }
                if metadata
                    .get("initial_inventory_unreadable")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    > 0
                {
                    limitations.push("Some filesystem entries could not be read during the initial inventory because of enumeration or permission errors.".to_string());
                }
                if metadata
                    .get("notification_queue_dropped")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    > 0
                {
                    limitations.push("The bounded filesystem notification queue dropped events; change observations are incomplete.".to_string());
                }
                if metadata
                    .get("filesystem_coverage_requires_review")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    limitations.push("A directory create/rename or an unclassified/rescan notification may have changed the tree without a complete path list; filesystem-path comparison is skipped for this run.".to_string());
                }
            }
        }
    } else if is_module_snapshot {
        limitations.push(
            "Filesystem observation is limited to the separate selected-directory watch."
                .to_string(),
        );
        limitations.push(
            "Loaded modules are captured by a point-in-time Windows Toolhelp snapshot. Transient loads are not captured, inaccessible or exited processes and modules without resolved paths can be omitted from reliable comparison, and this inventory does not verify file hashes, signatures, versions, or trust.".to_string(),
        );
        if module_summary_count != 1 || !module_inventory_complete {
            limitations.push(
                "The loaded-module inventory summary reports incomplete coverage. Library comparison is skipped for this run.".to_string(),
            );
        }
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
    } else {
        limitations.push(
            "Filesystem observation is limited to the separate selected-directory watch, and loaded-library observation was not captured in this run.".to_string(),
        );
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
            event_count,
            event_counts_by_type,
            collector_sources: collector_sources.into_iter().collect(),
            limitations,
        },
        passport: run.passport.clone(),
        events,
    })
}

/// Creates a named baseline from a completed saved run.
/// Observation lists are normalized so later comparisons do not depend on vector order.
pub fn baseline_from_run(
    run: &StoredRun,
    name: &str,
    created_at_ms: i64,
) -> Result<RuntimePassportBaseline, String> {
    crate::storage::validate_baseline_name(name).map_err(|error| error.to_string())?;
    if run.status != "completed" || run.ended_at_ms.is_none() {
        return Err(format!(
            "Run {} is not a completed run; only completed runs can become baselines.",
            run.run_id
        ));
    }

    // Reuse the evidence builder so baseline scope and coverage carry the same limitations.
    let evidence = evidence_bundle_from_run(run, created_at_ms)?;
    let mut passport = run.passport.clone();
    passport.observations.processes.sort();
    passport.observations.processes.dedup();
    passport.observations.network_targets.sort();
    passport.observations.network_targets.dedup();
    passport.observations.files.sort();
    passport.observations.files.dedup();
    passport.observations.libraries.sort();
    passport.observations.libraries.dedup();
    // A baseline captures observations, not a previous comparison's findings.
    passport.changes.clear();

    let mut coverage = evidence.coverage;
    if run.events.is_empty() {
        coverage.limitations.push(
            "No events were stored for the source run; the baseline may contain limited observations."
                .to_string(),
        );
    }

    Ok(RuntimePassportBaseline {
        baseline_schema_version: "1.0".to_string(),
        name: name.to_string(),
        created_at_ms,
        source_run_id: run.run_id.clone(),
        application: run.application.clone(),
        passport,
        scope: evidence.scope,
        coverage,
    })
}

/// Compares a completed run with a named Passport baseline. This deliberately reports
/// missing observations as `not_observed`, never as proof that behavior was removed.
pub fn compare_baseline_to_run(
    baseline: &RuntimePassportBaseline,
    baseline_run: &StoredRun,
    current_run: &StoredRun,
    generated_at_ms: i64,
) -> Result<BehaviorDriftReport, String> {
    if baseline.source_run_id != baseline_run.run_id {
        return Err(format!(
            "Baseline source run '{}' does not match loaded run '{}'.",
            baseline.source_run_id, baseline_run.run_id
        ));
    }
    if baseline_run.status != "completed" || baseline_run.ended_at_ms.is_none() {
        return Err(format!(
            "Baseline source run {} is no longer a completed run.",
            baseline_run.run_id
        ));
    }
    if !baseline
        .application
        .eq_ignore_ascii_case(&baseline_run.application)
        || !baseline
            .passport
            .application
            .eq_ignore_ascii_case(&baseline_run.application)
        || !baseline
            .passport
            .passport_id
            .eq(&baseline_run.passport.passport_id)
        || !passport_observations_match(
            &baseline.passport.observations,
            &baseline_run.passport.observations,
        )
    {
        return Err(
            "Stored baseline identity or observations do not match its source run. Recreate the baseline from that run."
                .to_string(),
        );
    }
    if current_run.status != "completed" || current_run.ended_at_ms.is_none() {
        return Err(format!(
            "Run {} is not completed; only completed runs can be compared.",
            current_run.run_id
        ));
    }
    if !current_run
        .passport
        .application
        .eq_ignore_ascii_case(&current_run.application)
    {
        return Err(
            "The current Runtime Passport application does not match its saved run.".to_string(),
        );
    }
    if !baseline
        .application
        .eq_ignore_ascii_case(&current_run.application)
    {
        return Err(format!(
            "Run application '{}' does not match baseline application '{}'. Compare the same application.",
            current_run.application, baseline.application
        ));
    }

    // Validate the original evidence records on both sides before linking their IDs.
    let baseline_evidence = evidence_bundle_from_run(baseline_run, generated_at_ms)?;
    let current_evidence = evidence_bundle_from_run(current_run, generated_at_ms)?;
    if !same_scope(&baseline.scope, &baseline_evidence.scope)
        || baseline.coverage.event_count != baseline_evidence.coverage.event_count
        || baseline.coverage.event_counts_by_type != baseline_evidence.coverage.event_counts_by_type
        || baseline.coverage.collector_sources != baseline_evidence.coverage.collector_sources
    {
        return Err(
            "Stored baseline scope or coverage does not match its source run. Recreate the baseline from that run."
                .to_string(),
        );
    }
    let baseline_scope = baseline.scope.clone();
    let current_scope = current_evidence.scope.clone();
    let scope_matches = baseline_scope.platform == current_scope.platform
        && baseline_scope.kind == current_scope.kind
        && baseline_scope.includes_descendants == current_scope.includes_descendants
        && baseline_scope.platform != "unknown"
        && baseline_scope.kind != "unknown";

    let mut coverage_changes = Vec::<CoverageChange>::new();
    if !scope_matches {
        coverage_changes.push(CoverageChange {
            kind: "scope_changed".to_string(),
            category: "observation_scope".to_string(),
            baseline_value: Some(format!(
                "platform={}, kind={}, includes_descendants={}",
                baseline_scope.platform, baseline_scope.kind, baseline_scope.includes_descendants
            )),
            current_value: Some(format!(
                "platform={}, kind={}, includes_descendants={}",
                current_scope.platform, current_scope.kind, current_scope.includes_descendants
            )),
            explanation: "The runs do not have matching, known observation scopes. Behavior-set comparisons were skipped rather than treating collection differences as behavior drift.".to_string(),
        });
    }

    let baseline_sources: BTreeSet<String> = baseline
        .coverage
        .collector_sources
        .iter()
        .cloned()
        .collect();
    let current_sources: BTreeSet<String> = current_evidence
        .coverage
        .collector_sources
        .iter()
        .cloned()
        .collect();
    for source in baseline_sources.difference(&current_sources) {
        coverage_changes.push(CoverageChange {
            kind: "source_not_observed".to_string(),
            category: "collector_provenance".to_string(),
            baseline_value: Some(source.clone()),
            current_value: None,
            explanation: "This source contributed stored events in the baseline but not in the current run. Provenance differences may reflect activity or collection differences and are not proof of absence.".to_string(),
        });
    }
    for source in current_sources.difference(&baseline_sources) {
        coverage_changes.push(CoverageChange {
            kind: "source_added".to_string(),
            category: "collector_provenance".to_string(),
            baseline_value: None,
            current_value: Some(source.clone()),
            explanation:
                "This source contributed stored events in the current run but not in the baseline."
                    .to_string(),
        });
    }

    let mut findings = Vec::<DriftFinding>::new();
    let mut compared_categories = Vec::<String>::new();
    let mut skipped_categories = Vec::<String>::new();
    let mut limitations = vec![
        "A 'not_observed' finding means no matching Passport observation was stored in the current run; it does not prove behavior stopped or is absent.".to_string(),
        "Event IDs refer to stored records in the baseline source run or current run. Empty evidence-ID lists mean no matching event record could be linked for that side.".to_string(),
    ];
    for note in baseline
        .coverage
        .limitations
        .iter()
        .chain(current_evidence.coverage.limitations.iter())
    {
        if !limitations.contains(note) {
            limitations.push(note.clone());
        }
    }

    if scope_matches && baseline_scope.kind == "selected_directory_watch" {
        let files_comparable = baseline_sources.contains("windows_filesystem_watch")
            && current_sources.contains("windows_filesystem_watch")
            && baseline_sources.contains("windows_filesystem_snapshot")
            && current_sources.contains("windows_filesystem_snapshot")
            && filesystem_coverage_complete(baseline_run)
            && filesystem_coverage_complete(current_run);
        compare_observation_category(
            &mut findings,
            &mut compared_categories,
            &mut skipped_categories,
            "files",
            &baseline_scope.platform,
            &baseline.passport.observations.files,
            &current_run.passport.observations.files,
            files_comparable,
            baseline_run,
            current_run,
        );
        if skipped_categories.iter().any(|item| item == "files") {
            limitations.push("Filesystem-path comparison was skipped because one or both runs lack complete initial-inventory/change-notification provenance, have unreadable or truncated inventory, dropped notifications, or a directory-tree change whose descendants could not be reconciled safely.".to_string());
        }
        skipped_categories.push("processes".to_string());
        skipped_categories.push("network_targets".to_string());
        skipped_categories.push("libraries".to_string());
    } else if scope_matches {
        compare_observation_category(
            &mut findings,
            &mut compared_categories,
            &mut skipped_categories,
            "processes",
            &baseline_scope.platform,
            &baseline.passport.observations.processes,
            &current_run.passport.observations.processes,
            has_process_provenance(&baseline.coverage.collector_sources)
                && has_process_provenance(&current_evidence.coverage.collector_sources)
                && (baseline_scope.kind != "selected_process_tree_watch"
                    || (process_watch_coverage_complete(baseline_run)
                        && process_watch_coverage_complete(current_run))),
            baseline_run,
            current_run,
        );
        if skipped_categories.iter().any(|item| item == "processes") {
            limitations.push("Process observations were skipped because one or both runs lack process-collector provenance or complete process-watch queue coverage.".to_string());
        }

        let network_comparable = baseline.scope.kind == "selected_process_tree_watch"
            && current_scope.kind == "selected_process_tree_watch"
            && baseline_sources.contains("windows_network_watch")
            && current_sources.contains("windows_network_watch")
            && network_watch_coverage_complete(baseline_run)
            && network_watch_coverage_complete(current_run);
        compare_observation_category(
            &mut findings,
            &mut compared_categories,
            &mut skipped_categories,
            "network_targets",
            &baseline_scope.platform,
            &baseline.passport.observations.network_targets,
            &current_run.passport.observations.network_targets,
            network_comparable,
            baseline_run,
            current_run,
        );
        if skipped_categories
            .iter()
            .any(|item| item == "network_targets")
        {
            limitations.push("Network-target comparisons were skipped because the stored collector provenance does not establish network observation coverage for both runs. A lack of stored network events is not proof that no network activity occurred.".to_string());
        }
        skipped_categories.push("files".to_string());

        let libraries_comparable = baseline_scope.kind == "selected_process_tree_snapshot"
            && current_scope.kind == "selected_process_tree_snapshot"
            && baseline_sources.contains("windows_module_snapshot")
            && current_sources.contains("windows_module_snapshot")
            && library_inventory_complete(baseline_run)
            && library_inventory_complete(current_run);
        compare_observation_category(
            &mut findings,
            &mut compared_categories,
            &mut skipped_categories,
            "libraries",
            &baseline_scope.platform,
            &baseline.passport.observations.libraries,
            &current_run.passport.observations.libraries,
            libraries_comparable,
            baseline_run,
            current_run,
        );
        if skipped_categories.iter().any(|item| item == "libraries") {
            limitations.push("Loaded-library comparison was skipped because one or both runs lack a complete point-in-time module inventory. Protected or exited processes and collector limits can leave gaps.".to_string());
        }
    } else {
        skipped_categories.push("processes".to_string());
        skipped_categories.push("network_targets".to_string());
        skipped_categories.push("files".to_string());
        skipped_categories.push("libraries".to_string());
        limitations.push("Observation comparisons were skipped because the baseline and current run have different or unknown observation scopes.".to_string());
    }

    let mut unique_limitations = BTreeSet::new();
    limitations.retain(|item| unique_limitations.insert(item.clone()));

    findings.sort_by(|left, right| {
        (&left.category, &left.kind, &left.observation).cmp(&(
            &right.category,
            &right.kind,
            &right.observation,
        ))
    });
    for (index, finding) in findings.iter_mut().enumerate() {
        finding.finding_id = format!("F-{:04}", index + 1);
    }
    compared_categories.sort();
    skipped_categories.sort();
    skipped_categories.dedup();
    coverage_changes.sort_by(|left, right| {
        (
            &left.category,
            &left.kind,
            &left.baseline_value,
            &left.current_value,
        )
            .cmp(&(
                &right.category,
                &right.kind,
                &right.baseline_value,
                &right.current_value,
            ))
    });

    Ok(BehaviorDriftReport {
        comparison_schema_version: "1.0".to_string(),
        generated_at_ms,
        baseline_name: baseline.name.clone(),
        baseline_source_run_id: baseline.source_run_id.clone(),
        current_run_id: current_run.run_id.clone(),
        application: current_run.application.clone(),
        comparable: scope_matches,
        baseline_scope,
        current_scope,
        baseline_collector_sources: baseline.coverage.collector_sources.clone(),
        current_collector_sources: current_evidence.coverage.collector_sources.clone(),
        baseline_event_count: baseline.coverage.event_count,
        current_event_count: current_evidence.coverage.event_count,
        baseline_event_counts_by_type: baseline.coverage.event_counts_by_type.clone(),
        current_event_counts_by_type: current_evidence.coverage.event_counts_by_type.clone(),
        compared_categories,
        skipped_categories,
        findings,
        coverage_changes,
        limitations,
    })
}

fn filesystem_coverage_complete(run: &StoredRun) -> bool {
    let mut inventory_summary_seen = false;
    let mut watch_summary_seen = false;
    for event in &run.events {
        if event.event_type != "file_observed" && event.event_type != "file_change" {
            continue;
        }
        let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&event.metadata_json) else {
            return false;
        };
        let operation = metadata
            .get("operation")
            .and_then(serde_json::Value::as_str);
        if event.source == "windows_filesystem_snapshot" && operation == Some("inventory_summary") {
            inventory_summary_seen = true;
            if metadata
                .get("initial_inventory_truncated")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
                || metadata
                    .get("initial_inventory_unreadable")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(1)
                    > 0
            {
                return false;
            }
        }
        if event.source == "windows_filesystem_watch" && operation == Some("watch_summary") {
            watch_summary_seen = true;
            if metadata
                .get("notification_queue_dropped")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1)
                > 0
                || metadata
                    .get("notification_error_present")
                    .and_then(serde_json::Value::as_bool)
                    != Some(false)
                || metadata
                    .get("filesystem_coverage_requires_review")
                    .and_then(serde_json::Value::as_bool)
                    != Some(false)
            {
                return false;
            }
        }
    }
    inventory_summary_seen && watch_summary_seen
}

fn same_scope(left: &EvidenceScope, right: &EvidenceScope) -> bool {
    left.platform == right.platform
        && left.kind == right.kind
        && left.root_pid == right.root_pid
        && left.includes_descendants == right.includes_descendants
}

fn passport_observations_match(left: &PassportObservations, right: &PassportObservations) -> bool {
    fn same_items(left: &[String], right: &[String]) -> bool {
        let left: BTreeSet<&str> = left.iter().map(String::as_str).collect();
        let right: BTreeSet<&str> = right.iter().map(String::as_str).collect();
        left == right
    }

    same_items(&left.processes, &right.processes)
        && same_items(&left.network_targets, &right.network_targets)
        && same_items(&left.files, &right.files)
        && same_items(&left.libraries, &right.libraries)
}

fn library_inventory_complete(run: &StoredRun) -> bool {
    let mut summaries = run.events.iter().filter(|event| {
        event.source == "windows_module_snapshot"
            && event.event_type == "library_inventory_status"
            && event.subject.as_deref() == Some("inventory_summary")
    });
    let Some(summary) = summaries.next() else {
        return false;
    };
    if summaries.next().is_some() {
        return false;
    }
    let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&summary.metadata_json) else {
        return false;
    };
    metadata
        .get("complete")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

fn has_process_provenance(sources: &[String]) -> bool {
    sources
        .iter()
        .any(|source| source == "windows_process" || source == "windows_process_watch")
}

fn process_watch_loss_counts(run: &StoredRun) -> Option<(u64, u64, u64, u64)> {
    let mut summaries = run.events.iter().filter(|event| {
        event.source == "windows_process_watch" && event.subject.as_deref() == Some("watch_summary")
    });
    let summary = summaries.next()?;
    if summaries.next().is_some() {
        return None;
    }

    let metadata = serde_json::from_str::<serde_json::Value>(&summary.metadata_json).ok()?;
    Some((
        metadata.get("dropped_start_events")?.as_u64()?,
        metadata.get("dropped_exit_events")?.as_u64()?,
        metadata.get("unpersisted_events_at_stop")?.as_u64()?,
        metadata.get("unclassified_events")?.as_u64()?,
    ))
}

fn process_watch_coverage_complete(run: &StoredRun) -> bool {
    process_watch_loss_counts(run) == Some((0, 0, 0, 0))
}

fn network_watch_coverage_complete(run: &StoredRun) -> bool {
    let mut summaries = run.events.iter().filter(|event| {
        event.source == "windows_network_watch"
            && event.event_type == "network_watch_summary"
            && event.subject.as_deref() == Some("watch_summary")
    });
    let Some(summary) = summaries.next() else {
        return false;
    };
    if summaries.next().is_some() {
        return false;
    }
    let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&summary.metadata_json) else {
        return false;
    };
    metadata
        .get("coverage_complete")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

fn compare_observation_category(
    findings: &mut Vec<DriftFinding>,
    compared_categories: &mut Vec<String>,
    skipped_categories: &mut Vec<String>,
    category: &str,
    platform: &str,
    baseline_items: &[String],
    current_items: &[String],
    coverage_available: bool,
    baseline_run: &StoredRun,
    current_run: &StoredRun,
) {
    if !coverage_available {
        skipped_categories.push(category.to_string());
        return;
    }
    compared_categories.push(category.to_string());

    let baseline_map = observation_map(category, platform, baseline_items);
    let current_map = observation_map(category, platform, current_items);
    let current_context_ids = category_context_event_ids(current_run, category);

    for (key, observation) in &current_map {
        if !baseline_map.contains_key(key) {
            let current_ids = matching_event_ids(current_run, category, observation, platform);
            let explanation = if current_ids.is_empty() {
                "Present in the current Runtime Passport but no matching event record could be linked. Inspect the source run before interpreting this difference.".to_string()
            } else {
                "Observed in the current Runtime Passport but not listed in the baseline Passport."
                    .to_string()
            };
            findings.push(DriftFinding {
                finding_id: String::new(),
                kind: "added".to_string(),
                category: category.to_string(),
                observation: observation.clone(),
                explanation,
                baseline_event_ids: matching_event_ids(
                    baseline_run,
                    category,
                    observation,
                    platform,
                ),
                current_event_ids: current_ids,
                current_context_event_ids: Vec::new(),
            });
        }
    }

    for (key, observation) in &baseline_map {
        if !current_map.contains_key(key) {
            let baseline_ids = matching_event_ids(baseline_run, category, observation, platform);
            let explanation = if baseline_ids.is_empty() {
                "Listed in the baseline Passport but no matching baseline event record could be linked. The current run did not list this observation; this does not prove it was removed.".to_string()
            } else {
                "Observed in the baseline Passport but not listed in the current Passport. This does not prove the behavior stopped or was removed.".to_string()
            };
            findings.push(DriftFinding {
                finding_id: String::new(),
                kind: "not_observed".to_string(),
                category: category.to_string(),
                observation: observation.clone(),
                explanation,
                baseline_event_ids: baseline_ids,
                current_event_ids: Vec::new(),
                current_context_event_ids: current_context_ids.clone(),
            });
        }
    }
}

fn observation_map(
    category: &str,
    platform: &str,
    items: &[String],
) -> std::collections::BTreeMap<String, String> {
    let mut ordered: Vec<&str> = items.iter().map(String::as_str).collect();
    ordered.sort_unstable();
    let mut observations = std::collections::BTreeMap::new();
    for item in ordered {
        observations
            .entry(comparison_key(category, platform, item))
            .or_insert_with(|| item.to_string());
    }
    observations
}

fn comparison_key(category: &str, platform: &str, value: &str) -> String {
    // Windows paths and process names are case-insensitive. Network endpoints
    // also normalize host casing. Keep exact comparison on other platforms.
    if platform == "windows"
        && (category == "processes"
            || category == "network_targets"
            || category == "files"
            || category == "libraries")
    {
        value.replace('/', "\\").to_lowercase()
    } else {
        value.to_string()
    }
}

fn category_context_event_ids(run: &StoredRun, category: &str) -> Vec<String> {
    let mut ids: Vec<String> = run
        .events
        .iter()
        .filter(|event| match category {
            "processes" => {
                event.event_type.starts_with("process_")
                    && event.subject.as_deref() != Some("watch_summary")
            }
            "network_targets" => {
                event.event_type == "network_connection" || event.event_type == "dns_lookup"
            }
            "files" => event.event_type == "file_change" || event.event_type == "file_observed",
            "libraries" => {
                event.event_type == "library_loaded"
                    || event.event_type == "library_inventory_status"
            }
            _ => false,
        })
        .map(|event| event.event_id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn matching_event_ids(
    run: &StoredRun,
    category: &str,
    observation: &str,
    platform: &str,
) -> Vec<String> {
    let expected_key = comparison_key(category, platform, observation);
    let mut ids: Vec<String> = run
        .events
        .iter()
        .filter(|event| {
            let value = match category {
                "processes" if event.event_type.starts_with("process_") => {
                    event.executable.as_deref()
                }
                "network_targets"
                    if event.event_type == "network_connection"
                        || event.event_type == "dns_lookup" =>
                {
                    event.target.as_deref()
                }
                "files"
                    if event.event_type == "file_change" || event.event_type == "file_observed" =>
                {
                    event.target.as_deref()
                }
                "libraries" if event.event_type == "library_loaded" => event.target.as_deref(),
                _ => None,
            };
            value
                .map(|value| comparison_key(category, platform, value) == expected_key)
                .unwrap_or(false)
        })
        .map(|event| event.event_id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod evidence_bundle_tests;
