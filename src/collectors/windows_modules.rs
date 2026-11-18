use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

use crate::collectors::CollectorError;
use crate::model::{EventType, ProcessIdentity, RuntimeEvent, Sensitivity};

const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_BAD_LENGTH: u32 = 24;
const SNAPSHOT_ATTEMPTS: usize = 3;
const MAX_PROCESSES: usize = 2_048;
const MAX_MODULES_PER_PROCESS: usize = 4_096;
const MAX_MODULES_TOTAL: usize = 50_000;
const MAX_FAILURE_DETAILS: usize = 128;

static SNAPSHOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct SnapshotHandle(HANDLE);

impl SnapshotHandle {
    fn for_process(pid: u32) -> Result<Self, u32> {
        for attempt in 0..SNAPSHOT_ATTEMPTS {
            let handle =
                unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                return Ok(Self(handle));
            }

            let error = unsafe { GetLastError() };
            if error != ERROR_BAD_LENGTH || attempt + 1 == SNAPSHOT_ATTEMPTS {
                return Err(error);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        Err(ERROR_BAD_LENGTH)
    }
}

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct ModuleRecord {
    name: String,
    path: String,
    image_size_bytes: u32,
}

fn utf16_string(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

fn enumerate_modules(pid: u32) -> Result<(Vec<ModuleRecord>, bool), u32> {
    let snapshot = SnapshotHandle::for_process(pid)?;
    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

    if unsafe { Module32FirstW(snapshot.0, &mut entry) } == 0 {
        return Err(unsafe { GetLastError() });
    }

    let mut modules = Vec::new();
    loop {
        let name = utf16_string(&entry.szModule);
        let path = utf16_string(&entry.szExePath);
        if !path.is_empty() || !name.is_empty() {
            modules.push(ModuleRecord {
                name,
                path,
                image_size_bytes: entry.modBaseSize,
            });
        }

        if modules.len() >= MAX_MODULES_PER_PROCESS {
            if unsafe { Module32NextW(snapshot.0, &mut entry) } != 0 {
                return Ok((modules, true));
            }
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_FILES {
                return Ok((modules, false));
            }
            return Err(error);
        }

        if unsafe { Module32NextW(snapshot.0, &mut entry) } != 0 {
            continue;
        }

        let error = unsafe { GetLastError() };
        if error == ERROR_NO_MORE_FILES {
            return Ok((modules, false));
        }
        return Err(error);
    }
}

/// Collects module paths for the selected process tree. Each process is
/// snapshotted separately, so the tree-wide result is not atomic.
pub fn collect_for_processes(
    process_events: &[RuntimeEvent],
    root_pid: u32,
) -> Result<Vec<RuntimeEvent>, CollectorError> {
    let selected: Vec<&RuntimeEvent> = process_events
        .iter()
        .filter(|event| event.source == "windows_process" && event.process.pid != 0)
        .collect();

    if selected.is_empty() {
        return Err(CollectorError::new(
            "windows_module_snapshot",
            "The process-tree collector supplied no process records.",
        ));
    }

    let root_event = selected
        .iter()
        .find(|event| event.process.pid == root_pid)
        .copied()
        .ok_or_else(|| {
            CollectorError::new(
                "windows_module_snapshot",
                format!("The selected process tree does not contain root PID {root_pid}."),
            )
        })?;
    let timestamp_ms = now_ms();
    let snapshot_sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let capture_id = format!("{timestamp_ms}-{snapshot_sequence}");
    let mut output = Vec::new();
    let mut attempted_processes = 0usize;
    let mut completed_processes = 0usize;
    let mut failed_processes = 0usize;
    let mut observed_modules = 0usize;
    let mut modules_without_paths = 0usize;
    let mut truncated = false;
    let mut failure_details = Vec::new();

    let process_count = selected.len().min(MAX_PROCESSES);
    for (process_index, process_event) in selected.iter().take(process_count).enumerate() {
        if observed_modules >= MAX_MODULES_TOTAL {
            truncated = true;
            break;
        }

        attempted_processes += 1;
        let pid = process_event.process.pid;
        match enumerate_modules(pid) {
            Ok((modules, process_truncated)) => {
                completed_processes += 1;
                truncated |= process_truncated;
                let remaining = MAX_MODULES_TOTAL.saturating_sub(observed_modules);
                let module_count = modules.len();
                if module_count > remaining {
                    truncated = true;
                }

                for (index, module) in modules.into_iter().take(remaining).enumerate() {
                    let target = if module.path.is_empty() {
                        modules_without_paths += 1;
                        if module.name.is_empty() {
                            continue;
                        }
                        module.name.clone()
                    } else {
                        module.path.clone()
                    };

                    observed_modules += 1;
                    output.push(RuntimeEvent {
                        id: format!("winmod-{capture_id}-{process_index}-{pid}-{index}"),
                        timestamp_ms,
                        event_type: EventType::LibraryLoaded,
                        process: ProcessIdentity {
                            pid,
                            executable: process_event.process.executable.clone(),
                            command_line: None,
                            parent_pid: process_event.process.parent_pid,
                        },
                        subject: "loaded_module".to_string(),
                        target: Some(target),
                        metadata: serde_json::json!({
                            "module_name": module.name,
                            "image_size_bytes": module.image_size_bytes,
                            "root_pid": root_pid,
                            "process_depth": process_event.metadata.get("depth").and_then(serde_json::Value::as_u64),
                            "observation_method": "windows_toolhelp_module_snapshot",
                            "observation_scope": "sequential_per_process_snapshot"
                        }),
                        source: "windows_module_snapshot".to_string(),
                        sensitivity: Sensitivity::PotentiallySensitive,
                    });
                }

                if observed_modules >= MAX_MODULES_TOTAL {
                    if module_count > remaining
                        || process_truncated
                        || process_index + 1 < process_count
                    {
                        truncated = true;
                    }
                    break;
                }
            }
            Err(win32_error) => {
                failed_processes += 1;
                if failure_details.len() < MAX_FAILURE_DETAILS {
                    failure_details.push(serde_json::json!({
                        "pid": pid,
                        "win32_error": win32_error
                    }));
                }
            }
        }
    }

    let process_limit_reached = selected.len() > MAX_PROCESSES;
    let processes_skipped = selected.len().saturating_sub(attempted_processes);
    truncated |= process_limit_reached;
    let complete = failed_processes == 0
        && !truncated
        && modules_without_paths == 0
        && attempted_processes == selected.len();

    output.push(RuntimeEvent {
        id: format!("winmod-summary-{capture_id}-{root_pid}"),
        timestamp_ms,
        event_type: EventType::LibraryInventoryStatus,
        process: ProcessIdentity {
            pid: root_event.process.pid,
            executable: root_event.process.executable.clone(),
            command_line: None,
            parent_pid: root_event.process.parent_pid,
        },
        subject: "inventory_summary".to_string(),
        target: None,
        metadata: serde_json::json!({
            "root_pid": root_pid,
            "discovered_processes": selected.len(),
            "attempted_processes": attempted_processes,
            "processes_skipped": processes_skipped,
            "processes_skipped_by_process_limit": selected.len().saturating_sub(process_count),
            "processes_not_attempted_after_module_limit": process_count.saturating_sub(attempted_processes),
            "maximum_processes": MAX_PROCESSES,
            "maximum_modules_per_process": MAX_MODULES_PER_PROCESS,
            "maximum_modules_total": MAX_MODULES_TOTAL,
            "completed_processes": completed_processes,
            "failed_processes": failed_processes,
            "observed_modules": observed_modules,
            "modules_without_paths": modules_without_paths,
            "truncated": truncated,
            "process_limit_reached": process_limit_reached,
            "complete": complete,
            "failure_details_truncated": failed_processes > failure_details.len(),
            "failure_details": failure_details
        }),
        source: "windows_module_snapshot".to_string(),
        sensitivity: Sensitivity::SystemMetadata,
    });

    Ok(output)
}

fn timestamp_ms(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(timestamp_ms)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{collect_for_processes, timestamp_ms, utf16_string};
    use crate::model::{EventType, ProcessIdentity, RuntimeEvent, Sensitivity};
    use std::time::Duration;

    #[test]
    fn module_name_stops_at_the_utf16_terminator() {
        assert_eq!(
            utf16_string(&[b'a' as u16, b'b' as u16, 0, b'c' as u16]),
            "ab"
        );
    }

    #[test]
    fn timestamp_conversion_saturates_instead_of_wrapping() {
        assert_eq!(timestamp_ms(Duration::from_secs(u64::MAX)), i64::MAX);
    }

    #[test]
    fn collection_rejects_a_process_list_without_the_requested_root() {
        let event = RuntimeEvent {
            id: "process-7".to_string(),
            timestamp_ms: 1,
            event_type: EventType::ProcessObserved,
            process: ProcessIdentity {
                pid: 7,
                executable: "example.exe".to_string(),
                command_line: None,
                parent_pid: None,
            },
            subject: "process".to_string(),
            target: Some("example.exe".to_string()),
            metadata: serde_json::json!({"depth": 0}),
            source: "windows_process".to_string(),
            sensitivity: Sensitivity::SystemMetadata,
        };

        let error = collect_for_processes(&[event], 99)
            .expect_err("a missing root must not fall back to an unrelated process");
        assert!(error.to_string().contains("root PID 99"));
    }
}
