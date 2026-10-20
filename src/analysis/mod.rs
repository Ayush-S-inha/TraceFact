use std::collections::BTreeSet;

use crate::model::{
    BehaviorDriftReport, CoverageChange, DriftFinding, EventType, EvidenceBundle, EvidenceCoverage,
    EvidenceEvent, EvidenceRunMetadata, EvidenceScope, PassportObservations, RuntimeEvent,
    RuntimePassport, RuntimePassportBaseline, RuntimeSnapshot,
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
    use std::collections::BTreeSet;

    if baseline.source_run_id != baseline_run.run_id {
        return Err(format!(
            "Baseline source run '{}' does not match loaded run '{}'.",
            baseline.source_run_id, baseline_run.run_id
        ));
    }
    if current_run.status != "completed" || current_run.ended_at_ms.is_none() {
        return Err(format!(
            "Run {} is not completed; only completed runs can be compared.",
            current_run.run_id
        ));
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
    let _baseline_evidence = evidence_bundle_from_run(baseline_run, generated_at_ms)?;
    let current_evidence = evidence_bundle_from_run(current_run, generated_at_ms)?;
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

    if scope_matches {
        compare_observation_category(
            &mut findings,
            &mut compared_categories,
            &mut skipped_categories,
            "processes",
            &baseline_scope.platform,
            &baseline.passport.observations.processes,
            &current_run.passport.observations.processes,
            has_process_provenance(&baseline.coverage.collector_sources)
                && has_process_provenance(&current_evidence.coverage.collector_sources),
            baseline_run,
            current_run,
        );
        if skipped_categories.iter().any(|item| item == "processes") {
            limitations.push("Process observations were skipped because both runs do not contain process-collector event provenance.".to_string());
        }

        let network_comparable = baseline.scope.kind == "selected_process_tree_watch"
            && current_scope.kind == "selected_process_tree_watch"
            && baseline_sources.contains("windows_network_watch")
            && current_sources.contains("windows_network_watch");
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
    } else {
        skipped_categories.push("processes".to_string());
        skipped_categories.push("network_targets".to_string());
        limitations.push("Process and network observation comparisons were skipped because the baseline and current run have different or unknown observation scopes.".to_string());
    }

    for category in ["files", "libraries"] {
        skipped_categories.push(category.to_string());
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

fn has_process_provenance(sources: &[String]) -> bool {
    sources
        .iter()
        .any(|source| source == "windows_process" || source == "windows_process_watch")
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
    // Windows process names are case-insensitive, as are DNS names and hexadecimal
    // letters in network endpoints. Keep exact comparison on other platforms.
    if platform == "windows" && (category == "processes" || category == "network_targets") {
        value.to_lowercase()
    } else {
        value.to_string()
    }
}

fn category_context_event_ids(run: &StoredRun, category: &str) -> Vec<String> {
    let mut ids: Vec<String> = run
        .events
        .iter()
        .filter(|event| match category {
            "processes" => event.event_type.starts_with("process_"),
            "network_targets" => {
                event.event_type == "network_connection" || event.event_type == "dns_lookup"
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
    fn baseline_normalizes_observations_and_clears_old_changes() {
        let mut run = sample_run("completed");
        run.passport.observations.processes = vec![
            "z.exe".to_string(),
            "a.exe".to_string(),
            "a.exe".to_string(),
        ];
        run.passport.changes.push(crate::model::BehaviorChange {
            kind: crate::model::ChangeKind::Added,
            category: "process".to_string(),
            subject: "old-finding.exe".to_string(),
            reason: "test finding".to_string(),
        });
        let baseline = super::baseline_from_run(&run, "test baseline", 300)
            .expect("completed run should become a baseline");

        assert_eq!(baseline.name, "test baseline");
        assert_eq!(baseline.source_run_id, run.run_id);
        assert_eq!(
            baseline.passport.observations.processes,
            vec!["a.exe".to_string(), "z.exe".to_string()]
        );
        assert!(baseline.passport.changes.is_empty());
        assert_eq!(baseline.coverage.event_count, 2);
        assert!(baseline
            .coverage
            .limitations
            .iter()
            .any(|item| item.contains("not implemented")));
    }

    #[test]
    fn baseline_rejects_incomplete_runs() {
        let run = sample_run("interrupted");
        let error = super::baseline_from_run(&run, "test baseline", 300)
            .expect_err("interrupted runs must not become baselines");
        assert!(error.contains("only completed runs"));
    }

    #[test]
    fn non_object_metadata_is_rejected_by_evidence_export() {
        let mut run = sample_run("completed");
        run.events[0].metadata_json = "42".to_string();
        let error = evidence_bundle_from_run(&run, 300).expect_err("non-object metadata must fail");
        assert!(error.contains("must be a JSON object"));
    }

    #[test]
    fn comparison_reports_added_and_not_observed_items_with_event_links() {
        let mut baseline_run = sample_run("completed");
        baseline_run.passport.observations.processes = vec!["demo.exe".into(), "old.exe".into()];
        baseline_run.passport.observations.network_targets = vec!["203.0.113.10:443".into()];
        baseline_run.events.push(StoredEvent {
            event_id: "old-process-event".to_string(),
            timestamp_ms: 130,
            event_type: "process_start".to_string(),
            pid: Some(43),
            executable: Some("old.exe".to_string()),
            subject: Some("process".to_string()),
            target: Some("old.exe".to_string()),
            metadata_json: r#"{"depth":1,"root_pid":42}"#.to_string(),
            source: "windows_process_watch".to_string(),
            sensitivity: "SystemMetadata".to_string(),
        });
        let baseline = super::baseline_from_run(&baseline_run, "stable", 300)
            .expect("completed run should become baseline");

        let mut current_run = baseline_run.clone();
        current_run.run_id = "watch-200-42".to_string();
        current_run.started_at_ms = 200;
        current_run.ended_at_ms = Some(400);
        current_run.passport.passport_id = "passport-watch-200-42".to_string();
        current_run.passport.observations.processes = vec!["demo.exe".into(), "new.exe".into()];
        current_run.passport.observations.network_targets = vec!["198.51.100.20:8443".into()];
        current_run
            .events
            .retain(|event| event.event_id != "old-process-event");
        let network_event = current_run
            .events
            .iter_mut()
            .find(|event| event.event_type == "network_connection")
            .expect("sample run has network event");
        network_event.event_id = "current-network-event".to_string();
        network_event.target = Some("198.51.100.20:8443".to_string());
        current_run.events.push(StoredEvent {
            event_id: "new-process-event".to_string(),
            timestamp_ms: 230,
            event_type: "process_start".to_string(),
            pid: Some(44),
            executable: Some("new.exe".to_string()),
            subject: Some("process".to_string()),
            target: Some("new.exe".to_string()),
            metadata_json: r#"{"depth":1,"root_pid":42}"#.to_string(),
            source: "windows_process_watch".to_string(),
            sensitivity: "SystemMetadata".to_string(),
        });

        let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
            .expect("comparable completed runs should compare");
        assert!(report.comparable);
        assert!(report
            .compared_categories
            .contains(&"processes".to_string()));
        assert!(report
            .compared_categories
            .contains(&"network_targets".to_string()));
        let added_process = report
            .findings
            .iter()
            .find(|finding| {
                finding.category == "processes"
                    && finding.kind == "added"
                    && finding.observation == "new.exe"
            })
            .expect("new process finding should exist");
        assert_eq!(added_process.current_event_ids, vec!["new-process-event"]);
        let not_observed_process = report
            .findings
            .iter()
            .find(|finding| {
                finding.category == "processes"
                    && finding.kind == "not_observed"
                    && finding.observation == "old.exe"
            })
            .expect("not-observed process finding should exist");
        assert_eq!(
            not_observed_process.baseline_event_ids,
            vec!["old-process-event"]
        );
        assert!(not_observed_process.current_event_ids.is_empty());
        assert!(!not_observed_process.current_context_event_ids.is_empty());
        assert!(not_observed_process.explanation.contains("does not prove"));
        assert!(report
            .findings
            .windows(2)
            .all(|pair| pair[0].finding_id.as_str() < pair[1].finding_id.as_str()));
    }

    #[test]
    fn scope_mismatch_skips_behavior_findings() {
        let baseline_run = sample_run("completed");
        let baseline = super::baseline_from_run(&baseline_run, "stable", 300)
            .expect("completed run should become baseline");
        let mut current_run = baseline_run.clone();
        current_run.run_id = "snap-200".to_string();
        current_run.passport.passport_id = "passport-snap-200".to_string();
        for event in &mut current_run.events {
            event.source = "windows_process".to_string();
        }
        current_run
            .events
            .retain(|event| event.event_type != "network_connection");
        current_run.passport.observations.network_targets.clear();

        let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
            .expect("scope mismatch should be reported, not misclassified as drift");
        assert!(!report.comparable);
        assert!(report.findings.is_empty());
        assert!(report
            .coverage_changes
            .iter()
            .any(|change| change.kind == "scope_changed"));
    }

    #[test]
    fn network_non_observations_are_skipped_without_provenance_in_both_runs() {
        let mut baseline_run = sample_run("completed");
        baseline_run.passport.observations.network_targets = vec!["203.0.113.10:443".into()];
        let baseline = super::baseline_from_run(&baseline_run, "stable", 300)
            .expect("completed run should become baseline");
        let mut current_run = sample_run("completed");
        current_run.run_id = "watch-200-42".to_string();
        current_run
            .events
            .retain(|event| event.event_type != "network_connection");
        current_run.passport.observations.network_targets.clear();

        let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
            .expect("comparison should complete while reporting limited coverage");
        assert!(report
            .skipped_categories
            .contains(&"network_targets".to_string()));
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.category == "network_targets"
                    && finding.kind == "not_observed")
        );
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("not proof")));
    }

    #[test]
    fn snapshot_network_limitations_do_not_refer_to_watch_runs() {
        let mut baseline_run = sample_run("completed");
        for event in &mut baseline_run.events {
            event.source = "windows_process".to_string();
        }
        baseline_run
            .events
            .retain(|event| event.event_type != "network_connection");
        baseline_run.passport.observations.network_targets.clear();
        let baseline = super::baseline_from_run(&baseline_run, "stable", 300)
            .expect("completed snapshot should become baseline");

        let mut current_run = baseline_run.clone();
        current_run.run_id = "snap-200".to_string();
        current_run.passport.passport_id = "passport-snap-200".to_string();
        current_run.started_at_ms = 200;
        current_run.ended_at_ms = Some(400);

        let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
            .expect("snapshot comparison should complete");
        assert!(report
            .skipped_categories
            .contains(&"network_targets".to_string()));
        assert!(report
            .limitations
            .iter()
            .any(|item| { item.contains("network observation coverage for both runs") }));
        let filesystem_library_limitations = report
            .limitations
            .iter()
            .filter(|item| {
                item.to_lowercase().contains("filesystem")
                    && item.to_lowercase().contains("loaded-library")
            })
            .count();
        assert_eq!(filesystem_library_limitations, 1);
        assert!(!report
            .limitations
            .iter()
            .any(|item| item.contains("both watch runs")));
    }

    #[test]
    fn windows_case_only_observation_changes_do_not_create_findings() {
        let mut baseline_run = sample_run("completed");
        baseline_run.passport.observations.processes = vec!["DEMO.EXE".into()];
        baseline_run.passport.observations.network_targets = vec!["2001:DB8::1:443".into()];
        let network_event = baseline_run
            .events
            .iter_mut()
            .find(|event| event.event_type == "network_connection")
            .expect("sample run has network event");
        network_event.target = Some("2001:DB8::1:443".into());
        let baseline = super::baseline_from_run(&baseline_run, "stable", 300)
            .expect("completed run should become baseline");

        let mut current_run = baseline_run.clone();
        current_run.run_id = "watch-case-variant".to_string();
        current_run.passport.observations.processes = vec!["demo.exe".into()];
        current_run.passport.observations.network_targets = vec!["2001:db8::1:443".into()];
        let network_event = current_run
            .events
            .iter_mut()
            .find(|event| event.event_type == "network_connection")
            .expect("sample run has network event");
        network_event.event_id = "network-case-variant".to_string();
        network_event.target = Some("2001:db8::1:443".into());

        let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
            .expect("case-only variations should compare");
        assert!(report.comparable);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn comparison_rejects_incomplete_runs_and_different_applications() {
        let baseline_run = sample_run("completed");
        let baseline = super::baseline_from_run(&baseline_run, "stable", 300)
            .expect("completed run should become baseline");

        let mut interrupted = sample_run("interrupted");
        interrupted.run_id = "watch-interrupted".to_string();
        interrupted.ended_at_ms = None;
        let error = super::compare_baseline_to_run(&baseline, &baseline_run, &interrupted, 500)
            .expect_err("interrupted runs must not be compared as final behavior");
        assert!(error.contains("only completed runs can be compared"));

        let mut other_application = sample_run("completed");
        other_application.run_id = "watch-other-app".to_string();
        other_application.application = "other.exe".to_string();
        let error =
            super::compare_baseline_to_run(&baseline, &baseline_run, &other_application, 500)
                .expect_err("different applications must not be compared");
        assert!(error.contains("does not match baseline application"));
    }

    #[test]
    fn reordered_observations_and_changed_timestamps_do_not_create_findings() {
        let baseline_run = sample_run("completed");
        let baseline = super::baseline_from_run(&baseline_run, "stable", 300)
            .expect("completed run should become baseline");
        let mut current_run = baseline_run.clone();
        current_run.run_id = "watch-300-42".to_string();
        current_run.started_at_ms += 10_000;
        current_run.ended_at_ms = Some(10_200);
        current_run.passport.generated_at_ms += 10_000;
        current_run.passport.observations.processes.reverse();
        current_run
            .events
            .iter_mut()
            .for_each(|event| event.timestamp_ms += 10_000);

        let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 20_000)
            .expect("equivalent observation sets should compare");
        assert!(report.comparable);
        assert!(report.findings.is_empty());
    }
}
