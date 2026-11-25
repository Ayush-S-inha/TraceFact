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
            StoredEvent {
                event_id: "process-watch-summary".to_string(),
                timestamp_ms: 200,
                event_type: "process_observed".to_string(),
                pid: Some(42),
                executable: Some("process-watch-summary".to_string()),
                subject: Some("watch_summary".to_string()),
                target: None,
                metadata_json: r#"{"operation":"watch_summary","root_pid":42,"dropped_start_events":0,"dropped_exit_events":0,"unpersisted_events_at_stop":0,"unclassified_events":0,"queue_capacity":4096}"#.to_string(),
                source: "windows_process_watch".to_string(),
                sensitivity: "SystemMetadata".to_string(),
            },
            StoredEvent {
                event_id: "network-watch-summary".to_string(),
                timestamp_ms: 200,
                event_type: "network_watch_summary".to_string(),
                pid: Some(42),
                executable: Some("demo.exe".to_string()),
                subject: Some("watch_summary".to_string()),
                target: None,
                metadata_json: r#"{"root_pid":42,"coverage_complete":true,"queue_dropped_events":0,"incomplete_tcp_events":0,"events_with_unverified_attribution":0,"stream_error_present":false}"#.to_string(),
                source: "windows_network_watch".to_string(),
                sensitivity: "SystemMetadata".to_string(),
            },
        ],
    }
}

fn sample_filesystem_run(run_id: &str, initial_files: &[&str]) -> StoredRun {
    let root = "C:/TraceFactTest";
    let mut run = sample_run("completed");
    run.run_id = run_id.to_string();
    run.application = format!("directory:{root}");
    run.started_at_ms = 1_000;
    run.ended_at_ms = Some(2_000);
    run.passport.passport_id = format!("passport-{run_id}");
    run.passport.application = run.application.clone();
    run.passport.observations.processes.clear();
    run.passport.observations.network_targets.clear();
    run.passport.observations.files = initial_files
        .iter()
        .map(|path| (*path).to_string())
        .collect();
    run.events.clear();

    run.events.push(StoredEvent {
        event_id: format!("{run_id}-inventory-summary"),
        timestamp_ms: 1_000,
        event_type: "file_observed".to_string(),
        pid: Some(0),
        executable: Some("filesystem-observer".to_string()),
        subject: Some("inventory_summary".to_string()),
        target: None,
        metadata_json: format!(r#"{{"operation":"inventory_summary","initial_inventory_truncated":false,"initial_inventory_unreadable":0,"watch_root":"{root}"}}"#),
        source: "windows_filesystem_snapshot".to_string(),
        sensitivity: "SystemMetadata".to_string(),
    });
    for (index, path) in initial_files.iter().enumerate() {
        run.events.push(StoredEvent {
            event_id: format!("{run_id}-present-{index}"),
            timestamp_ms: 1_010 + index as i64,
            event_type: "file_observed".to_string(),
            pid: Some(0),
            executable: Some("filesystem-observer".to_string()),
            subject: Some("present_at_start".to_string()),
            target: Some((*path).to_string()),
            metadata_json: format!(
                r#"{{"operation":"present_at_start","entry_kind":"file","watch_root":"{root}"}}"#
            ),
            source: "windows_filesystem_snapshot".to_string(),
            sensitivity: "PotentiallySensitive".to_string(),
        });
    }
    run.events.push(StoredEvent {
        event_id: format!("{run_id}-watch-summary"),
        timestamp_ms: 2_000,
        event_type: "file_change".to_string(),
        pid: Some(0),
        executable: Some("filesystem-observer".to_string()),
        subject: Some("watch_summary".to_string()),
        target: None,
        metadata_json: format!(r#"{{"operation":"watch_summary","notification_queue_dropped":0,"notification_error_present":false,"filesystem_coverage_requires_review":false,"initial_inventory_truncated":false,"initial_inventory_unreadable":0,"watch_root":"{root}"}}"#),
        source: "windows_filesystem_watch".to_string(),
        sensitivity: "SystemMetadata".to_string(),
    });
    run
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
    assert_eq!(bundle.coverage.event_count, 4);
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
        .any(|note| note.contains("loaded-library observation was not captured in this run")));
}

#[test]
fn process_queue_loss_is_reported_and_skips_process_comparison() {
    let mut baseline_run = sample_run("completed");
    let summary = baseline_run
        .events
        .iter_mut()
        .find(|event| event.subject.as_deref() == Some("watch_summary"))
        .expect("sample run has a process coverage summary");
    summary.metadata_json = r#"{"operation":"watch_summary","root_pid":42,"dropped_start_events":3,"dropped_exit_events":1,"unpersisted_events_at_stop":2,"unclassified_events":4,"queue_capacity":4096}"#.to_string();

    let bundle =
        evidence_bundle_from_run(&baseline_run, 300).expect("queue loss should remain exportable");
    let process_summary = bundle
        .events
        .iter()
        .find(|event| {
            event.source == "windows_process_watch"
                && event.subject.as_deref() == Some("watch_summary")
        })
        .expect("process-watch summary should be preserved in the evidence bundle");

    assert_eq!(process_summary.metadata["dropped_start_events"], 3);
    assert_eq!(process_summary.metadata["dropped_exit_events"], 1);
    assert_eq!(process_summary.metadata["unpersisted_events_at_stop"], 2);
    assert_eq!(process_summary.metadata["unclassified_events"], 4);
    assert!(bundle.coverage.limitations.iter().any(|note| {
        note.to_ascii_lowercase().contains("process")
            && note.to_ascii_lowercase().contains("skipped")
    }));

    let baseline = super::baseline_from_run(&baseline_run, "lossy", 300)
        .expect("completed run should remain a recordable baseline");
    let current_run = sample_run("completed");
    let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
        .expect("comparison should report incomplete process coverage");
    assert!(report.skipped_categories.contains(&"processes".to_string()));
    assert!(!report
        .compared_categories
        .contains(&"processes".to_string()));
}

#[test]
fn network_watch_loss_skips_network_comparison() {
    let mut baseline_run = sample_run("completed");
    let summary = baseline_run
        .events
        .iter_mut()
        .find(|event| event.event_type == "network_watch_summary")
        .expect("sample run has a network coverage summary");
    summary.metadata_json = r#"{"root_pid":42,"coverage_complete":false,"queue_dropped_events":4,"incomplete_tcp_events":0,"events_with_unverified_attribution":0,"stream_error_present":false}"#.to_string();

    let baseline = super::baseline_from_run(&baseline_run, "network-loss", 300)
        .expect("completed run should remain a recordable baseline");
    let current_run = sample_run("completed");
    let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
        .expect("comparison should report incomplete network coverage");
    assert!(report
        .skipped_categories
        .contains(&"network_targets".to_string()));
    assert!(!report
        .compared_categories
        .contains(&"network_targets".to_string()));
}

#[test]
fn legacy_process_watch_without_summary_skips_process_comparison() {
    let mut baseline_run = sample_run("completed");
    baseline_run
        .events
        .retain(|event| event.subject.as_deref() != Some("watch_summary"));
    let bundle =
        evidence_bundle_from_run(&baseline_run, 300).expect("legacy run should remain exportable");
    assert!(bundle
        .coverage
        .limitations
        .iter()
        .any(|note| { note.contains("no single valid queue-coverage summary") }));

    let baseline = super::baseline_from_run(&baseline_run, "legacy", 300)
        .expect("legacy completed run should remain a recordable baseline");
    let current_run = sample_run("completed");
    let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
        .expect("comparison should report unknown historical queue coverage");
    assert!(report.skipped_categories.contains(&"processes".to_string()));
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
    assert_eq!(baseline.coverage.event_count, 4);
    assert!(baseline
        .coverage
        .limitations
        .iter()
        .any(|item| item.contains("loaded-library observation was not captured in this run")));
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
    current_run.events.retain(|event| {
        event.event_type != "network_connection" && event.event_type != "network_watch_summary"
    });
    current_run.passport.observations.network_targets.clear();

    let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
        .expect("comparison should complete while reporting limited coverage");
    assert!(report
        .skipped_categories
        .contains(&"network_targets".to_string()));
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.category == "network_targets" && finding.kind == "not_observed"));
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
fn directory_watch_comparison_reports_path_additions_and_not_observed_paths() {
    let baseline_run = sample_filesystem_run("filesystem-baseline", &["old.txt"]);
    let baseline = super::baseline_from_run(&baseline_run, "directory baseline", 3_000)
        .expect("completed filesystem run should become a baseline");

    let mut current_run = sample_filesystem_run("filesystem-current", &["new.txt"]);
    current_run.events.push(StoredEvent {
        event_id: "current-remove-old".to_string(),
        timestamp_ms: 1_500,
        event_type: "file_change".to_string(),
        pid: Some(0),
        executable: Some("filesystem-observer".to_string()),
        subject: Some("removed".to_string()),
        target: Some("old.txt".to_string()),
        metadata_json: r#"{"operation":"removed","watch_root":"C:\\TraceFactTest"}"#.to_string(),
        source: "windows_filesystem_watch".to_string(),
        sensitivity: "PotentiallySensitive".to_string(),
    });
    current_run.events.push(StoredEvent {
        event_id: "current-create-new".to_string(),
        timestamp_ms: 1_600,
        event_type: "file_change".to_string(),
        pid: Some(0),
        executable: Some("filesystem-observer".to_string()),
        subject: Some("created".to_string()),
        target: Some("new.txt".to_string()),
        metadata_json:
            r#"{"operation":"created","entry_kind":"file","watch_root":"C:\\TraceFactTest"}"#
                .to_string(),
        source: "windows_filesystem_watch".to_string(),
        sensitivity: "PotentiallySensitive".to_string(),
    });

    let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 4_000)
        .expect("matching directory scopes should compare");
    assert!(report.comparable);
    assert!(report.compared_categories.contains(&"files".to_string()));
    assert!(report.skipped_categories.contains(&"processes".to_string()));
    assert!(report
        .skipped_categories
        .contains(&"network_targets".to_string()));

    let added = report
        .findings
        .iter()
        .find(|finding| {
            finding.category == "files"
                && finding.kind == "added"
                && finding.observation == "new.txt"
        })
        .expect("new file should be reported");
    assert!(added
        .current_event_ids
        .contains(&"current-create-new".to_string()));

    let not_observed = report
        .findings
        .iter()
        .find(|finding| {
            finding.category == "files"
                && finding.kind == "not_observed"
                && finding.observation == "old.txt"
        })
        .expect("removed old file should be not-observed in the current Passport");
    assert!(not_observed
        .baseline_event_ids
        .iter()
        .any(|id| id.contains("present-0")));
    assert!(not_observed.current_event_ids.is_empty());
    assert!(not_observed
        .current_context_event_ids
        .contains(&"current-remove-old".to_string()));
    assert!(not_observed.explanation.contains("does not prove"));
}

fn sample_module_snapshot_run(run_id: &str, libraries: &[&str], complete: bool) -> StoredRun {
    let mut run = sample_run("completed");
    run.run_id = run_id.to_string();
    run.started_at_ms = 1_000;
    run.ended_at_ms = Some(2_000);
    run.passport.passport_id = format!("passport-{run_id}");
    run.passport.observations.network_targets.clear();
    run.passport.observations.libraries =
        libraries.iter().map(|path| (*path).to_string()).collect();
    run.events.retain(|event| {
        event.event_type == "process_observed" && event.subject.as_deref() != Some("watch_summary")
    });
    run.events[0].source = "windows_process".to_string();

    for (index, path) in libraries.iter().enumerate() {
        run.events.push(StoredEvent {
            event_id: format!("{run_id}-module-{index}"),
            timestamp_ms: 1_100 + index as i64,
            event_type: "library_loaded".to_string(),
            pid: Some(42),
            executable: Some("demo.exe".to_string()),
            subject: Some("loaded_module".to_string()),
            target: Some((*path).to_string()),
            metadata_json:
                r#"{"root_pid":42,"observation_method":"windows_toolhelp_module_snapshot"}"#
                    .to_string(),
            source: "windows_module_snapshot".to_string(),
            sensitivity: "PotentiallySensitive".to_string(),
        });
    }
    run.events.push(StoredEvent {
        event_id: format!("{run_id}-module-summary"),
        timestamp_ms: 1_999,
        event_type: "library_inventory_status".to_string(),
        pid: Some(42),
        executable: Some("demo.exe".to_string()),
        subject: Some("inventory_summary".to_string()),
        target: None,
        metadata_json: format!(
            r#"{{"root_pid":42,"complete":{complete},"observed_modules":{}}}"#,
            libraries.len()
        ),
        source: "windows_module_snapshot".to_string(),
        sensitivity: "SystemMetadata".to_string(),
    });
    run
}

#[test]
fn complete_module_inventories_compare_with_event_links() {
    let baseline_run = sample_module_snapshot_run(
        "module-baseline",
        &[r#"C:\Windows\System32\kernel32.dll"#, r#"C:\App\old.dll"#],
        true,
    );
    let baseline = super::baseline_from_run(&baseline_run, "module stable", 3_000)
        .expect("complete module snapshot should become a baseline");
    let current_run = sample_module_snapshot_run(
        "module-current",
        &[r#"c:/windows/system32/KERNEL32.DLL"#, r#"C:\App\new.dll"#],
        true,
    );

    let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 4_000)
        .expect("complete module inventories should compare");
    assert!(report
        .compared_categories
        .contains(&"libraries".to_string()));
    let added = report
        .findings
        .iter()
        .find(|finding| {
            finding.category == "libraries"
                && finding.kind == "added"
                && finding.observation.ends_with("new.dll")
        })
        .expect("new module should be reported");
    assert!(added
        .current_event_ids
        .contains(&"module-current-module-1".to_string()));
    let not_observed = report
        .findings
        .iter()
        .find(|finding| {
            finding.category == "libraries"
                && finding.kind == "not_observed"
                && finding.observation.ends_with("old.dll")
        })
        .expect("baseline module should be marked not observed");
    assert!(not_observed
        .baseline_event_ids
        .contains(&"module-baseline-module-1".to_string()));
    assert!(not_observed.explanation.contains("does not prove"));
    assert!(not_observed
        .current_context_event_ids
        .contains(&"module-current-module-summary".to_string()));
}

#[test]
fn incomplete_module_inventory_is_not_compared() {
    let baseline_run = sample_module_snapshot_run("module-baseline", &[r#"C:\App\old.dll"#], true);
    let baseline = super::baseline_from_run(&baseline_run, "module stable", 3_000)
        .expect("complete module snapshot should become a baseline");
    let current_run = sample_module_snapshot_run("module-current", &[], false);

    let report = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 4_000)
        .expect("incomplete inventory should produce a limited report");
    assert!(report.skipped_categories.contains(&"libraries".to_string()));
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.category == "libraries"));
    assert!(report
        .limitations
        .iter()
        .any(|item| item.contains("complete point-in-time module inventory")));
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
    other_application.passport.application = other_application.application.clone();
    let error = super::compare_baseline_to_run(&baseline, &baseline_run, &other_application, 500)
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

#[test]
fn conflicting_root_pids_are_not_silently_resolved() {
    let mut run = sample_run("completed");
    run.events[1].metadata_json =
        r#"{"root_pid":43,"protocol":"tcp","operation":"connect"}"#.to_string();

    let bundle = evidence_bundle_from_run(&run, 300).expect("valid event metadata should export");

    assert_eq!(bundle.scope.root_pid, None);
    assert!(bundle
        .coverage
        .limitations
        .iter()
        .any(|note| { note.contains("multiple root process IDs") }));
}

#[test]
fn comparison_rejects_a_baseline_whose_coverage_was_changed() {
    let baseline_run = sample_run("completed");
    let mut baseline = super::baseline_from_run(&baseline_run, "stable", 300)
        .expect("completed run should become baseline");
    baseline.coverage.event_count += 1;

    let mut current_run = sample_run("completed");
    current_run.run_id = "watch-200-42".to_string();
    current_run.passport.passport_id = "passport-watch-200-42".to_string();

    let error = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
        .expect_err("baseline coverage must agree with its source run");
    assert!(error.contains("scope or coverage does not match"));
}

#[test]
fn comparison_rejects_a_baseline_source_that_is_no_longer_complete() {
    let mut baseline_run = sample_run("completed");
    let baseline = super::baseline_from_run(&baseline_run, "stable", 300)
        .expect("completed run should become baseline");
    baseline_run.status = "interrupted".to_string();

    let current_run = sample_run("completed");
    let error = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
        .expect_err("incomplete source run must not be used for comparison");
    assert!(error.contains("no longer a completed run"));
}

#[test]
fn comparison_rejects_baseline_observations_that_were_changed() {
    let baseline_run = sample_run("completed");
    let mut baseline = super::baseline_from_run(&baseline_run, "stable", 300)
        .expect("completed run should become baseline");
    baseline
        .passport
        .observations
        .processes
        .push("unrecorded.exe".to_string());

    let current_run = sample_run("completed");
    let error = super::compare_baseline_to_run(&baseline, &baseline_run, &current_run, 500)
        .expect_err("baseline observations must match the source run");
    assert!(error.contains("identity or observations do not match"));
}
