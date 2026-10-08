use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use wmi::WMIConnection;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use crate::collectors::{Collector, CollectorError};
use crate::model::{EventType, ProcessIdentity, RuntimeEvent, Sensitivity};

const ERROR_NO_MORE_FILES: u32 = 18;

#[derive(Debug, Clone)]
pub(crate) struct ProcessRecord {
    pid: u32,
    parent_pid: u32,
    name: String,
    thread_count: u32,
}

#[derive(Debug, Clone)]
struct SelectedProcess {
    pid: u32,
    parent_pid: u32,
    name: String,
    thread_count: u32,
    depth: u32,
}

struct SnapshotHandle(HANDLE);

impl SnapshotHandle {
    fn new() -> Result<Self, CollectorError> {
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(windows_error(
                "windows_process",
                "CreateToolhelp32Snapshot failed",
            ));
        }
        Ok(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub struct WindowsProcessCollector {
    root_pid: u32,
    sequence: u64,
}

impl WindowsProcessCollector {
    pub fn new(root_pid: u32) -> Self {
        Self {
            root_pid,
            sequence: 0,
        }
    }

    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    pub fn collect_once(&mut self) -> Result<Vec<RuntimeEvent>, CollectorError> {
        let timestamp_ms = Self::now_ms();
        let processes = Self::enumerate_processes()?;
        let selected = Self::select_process_tree(&processes, self.root_pid)?;
        let mut events = Vec::with_capacity(selected.len());

        for process in selected {
            self.sequence = self.sequence.wrapping_add(1);
            let relationship = if process.pid == self.root_pid {
                "root"
            } else {
                "child"
            };

            let executable = process.name.clone();
            events.push(RuntimeEvent {
                id: format!("winproc-{timestamp_ms}-{}-{}", self.root_pid, process.pid),
                timestamp_ms,
                event_type: EventType::ProcessObserved,
                process: ProcessIdentity {
                    pid: process.pid,
                    executable: executable.clone(),
                    command_line: None,
                    parent_pid: Some(process.parent_pid).filter(|pid| *pid != 0),
                },
                subject: "process".to_string(),
                target: Some(executable),
                metadata: serde_json::json!({
                    "root_pid": self.root_pid,
                    "parent_pid": process.parent_pid,
                    "depth": process.depth,
                    "relationship": relationship,
                    "thread_count": process.thread_count
                }),
                source: self.name().to_string(),
                sensitivity: Sensitivity::SystemMetadata,
            });
        }

        Ok(events)
    }

    pub(crate) fn enumerate_processes() -> Result<Vec<ProcessRecord>, CollectorError> {
        let snapshot = SnapshotHandle::new()?;
        unsafe { Self::read_process_snapshot(snapshot.raw()) }
    }

    unsafe fn read_process_snapshot(
        snapshot: HANDLE,
    ) -> Result<Vec<ProcessRecord>, CollectorError> {
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry) == 0 {
            return Err(windows_error("windows_process", "Process32FirstW failed"));
        }

        let mut processes = Vec::new();

        loop {
            processes.push(ProcessRecord {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                name: utf16_string(&entry.szExeFile),
                thread_count: entry.cntThreads,
            });

            if Process32NextW(snapshot, &mut entry) != 0 {
                continue;
            }

            let error = GetLastError();
            if error == ERROR_NO_MORE_FILES {
                break;
            }

            return Err(CollectorError::new(
                "windows_process",
                format!("Process32NextW failed with Windows error {error}."),
            ));
        }

        Ok(processes)
    }

    fn select_process_tree(
        processes: &[ProcessRecord],
        root_pid: u32,
    ) -> Result<Vec<SelectedProcess>, CollectorError> {
        let process_by_pid: BTreeMap<u32, &ProcessRecord> = processes
            .iter()
            .map(|process| (process.pid, process))
            .collect();

        if !process_by_pid.contains_key(&root_pid) {
            return Err(CollectorError::new(
                "windows_process",
                format!("Process with PID {root_pid} was not found."),
            ));
        }

        let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for process in process_by_pid.values() {
            children
                .entry(process.parent_pid)
                .or_default()
                .push(process.pid);
        }

        for child_pids in children.values_mut() {
            child_pids.sort_unstable();
        }

        let mut queue = VecDeque::new();
        queue.push_back((root_pid, 0));
        let mut selected_pids = BTreeSet::new();
        let mut selected = Vec::new();

        while let Some((pid, depth)) = queue.pop_front() {
            if !selected_pids.insert(pid) {
                continue;
            }

            if let Some(process) = process_by_pid.get(&pid) {
                selected.push(SelectedProcess {
                    pid: process.pid,
                    parent_pid: process.parent_pid,
                    name: process.name.clone(),
                    thread_count: process.thread_count,
                    depth,
                });
            }

            if let Some(child_pids) = children.get(&pid) {
                for child_pid in child_pids {
                    queue.push_back((*child_pid, depth + 1));
                }
            }
        }

        selected.sort_by_key(|process| (process.depth, process.pid));

        if selected.is_empty() {
            return Err(CollectorError::new(
                "windows_process",
                format!("Process with PID {root_pid} was not found."),
            ));
        }

        Ok(selected)
    }

    pub(crate) fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }
}

impl Collector for WindowsProcessCollector {
    fn name(&self) -> &'static str {
        "windows_process"
    }

    fn collect(&mut self) -> Result<Vec<RuntimeEvent>, CollectorError> {
        self.collect_once()
    }
}

#[derive(Debug)]
pub enum ProcessWatchEvent {
    Start(ProcessStartTrace),
    Exit(ProcessStopTrace),
    Ready(WatchSource),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WatchSource {
    Starts,
    Exits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "Win32_ProcessStartTrace")]
#[serde(rename_all = "PascalCase")]
pub struct ProcessStartTrace {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "Win32_ProcessStopTrace")]
#[serde(rename_all = "PascalCase")]
pub struct ProcessStopTrace {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub process_name: String,
    pub exit_status: u32,
}

pub struct WindowsProcessEventWatcher {
    receiver: Receiver<ProcessWatchEvent>,
}

impl WindowsProcessEventWatcher {
    pub fn start() -> Self {
        let (sender, receiver) = mpsc::channel();
        spawn_start_watcher(sender.clone());
        spawn_exit_watcher(sender);
        Self { receiver }
    }

    pub fn receiver(&self) -> &Receiver<ProcessWatchEvent> {
        &self.receiver
    }
}

fn spawn_start_watcher(sender: Sender<ProcessWatchEvent>) {
    thread::spawn(move || {
        let connection = match WMIConnection::new() {
            Ok(connection) => connection,
            Err(error) => {
                let _ = sender.send(ProcessWatchEvent::Error(format!(
                    "Could not connect to WMI for process start events: {error}"
                )));
                return;
            }
        };

        let events = match connection.notification::<ProcessStartTrace>() {
            Ok(events) => events,
            Err(error) => {
                let _ = sender.send(ProcessWatchEvent::Error(format!(
                    "Could not subscribe to Windows process start events: {error}"
                )));
                return;
            }
        };

        if sender
            .send(ProcessWatchEvent::Ready(WatchSource::Starts))
            .is_err()
        {
            return;
        }

        for result in events {
            match result {
                Ok(event) => {
                    if sender.send(ProcessWatchEvent::Start(event)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.send(ProcessWatchEvent::Error(format!(
                        "Windows process start event stream failed: {error}"
                    )));
                    break;
                }
            }
        }
    });
}

fn spawn_exit_watcher(sender: Sender<ProcessWatchEvent>) {
    thread::spawn(move || {
        let connection = match WMIConnection::new() {
            Ok(connection) => connection,
            Err(error) => {
                let _ = sender.send(ProcessWatchEvent::Error(format!(
                    "Could not connect to WMI for process exit events: {error}"
                )));
                return;
            }
        };

        let events = match connection.notification::<ProcessStopTrace>() {
            Ok(events) => events,
            Err(error) => {
                let _ = sender.send(ProcessWatchEvent::Error(format!(
                    "Could not subscribe to Windows process exit events: {error}"
                )));
                return;
            }
        };

        if sender
            .send(ProcessWatchEvent::Ready(WatchSource::Exits))
            .is_err()
        {
            return;
        }

        for result in events {
            match result {
                Ok(event) => {
                    if sender.send(ProcessWatchEvent::Exit(event)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.send(ProcessWatchEvent::Error(format!(
                        "Windows process exit event stream failed: {error}"
                    )));
                    break;
                }
            }
        }
    });
}

fn process_event_metadata(
    root_pid: u32,
    parent_pid: u32,
    depth: u32,
    relationship: &str,
) -> serde_json::Value {
    serde_json::json!({
        "root_pid": root_pid,
        "parent_pid": parent_pid,
        "depth": depth,
        "relationship": relationship
    })
}

pub fn build_process_lifecycle_event(
    run_id: &str,
    sequence: u64,
    root_pid: u32,
    timestamp_ms: i64,
    start: &ProcessStartTrace,
    depth: u32,
) -> RuntimeEvent {
    RuntimeEvent {
        id: format!("{run_id}-event-{sequence}"),
        timestamp_ms,
        event_type: EventType::ProcessStart,
        process: ProcessIdentity {
            pid: start.process_id,
            executable: start.process_name.clone(),
            command_line: None,
            parent_pid: Some(start.parent_process_id).filter(|pid| *pid != 0),
        },
        subject: "process".to_string(),
        target: Some(start.process_name.clone()),
        metadata: process_event_metadata(root_pid, start.parent_process_id, depth, "child"),
        source: "windows_process_watch".to_string(),
        sensitivity: Sensitivity::SystemMetadata,
    }
}

pub fn build_process_exit_event(
    run_id: &str,
    sequence: u64,
    root_pid: u32,
    timestamp_ms: i64,
    exit: &ProcessStopTrace,
    depth: u32,
    relationship: &str,
) -> RuntimeEvent {
    let mut metadata =
        process_event_metadata(root_pid, exit.parent_process_id, depth, relationship);
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "exit_status".to_string(),
            serde_json::json!(exit.exit_status),
        );
    }

    RuntimeEvent {
        id: format!("{run_id}-event-{sequence}"),
        timestamp_ms,
        event_type: EventType::ProcessExit,
        process: ProcessIdentity {
            pid: exit.process_id,
            executable: exit.process_name.clone(),
            command_line: None,
            parent_pid: Some(exit.parent_process_id).filter(|pid| *pid != 0),
        },
        subject: "process".to_string(),
        target: Some(exit.process_name.clone()),
        metadata,
        source: "windows_process_watch".to_string(),
        sensitivity: Sensitivity::SystemMetadata,
    }
}

pub(crate) fn classify_process_depth(
    processes: &[ProcessRecord],
    root_pid: u32,
    target_pid: u32,
) -> Option<u32> {
    let by_pid: BTreeMap<u32, &ProcessRecord> = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();

    let mut current = target_pid;
    let mut depth = 0_u32;
    let mut seen = BTreeSet::new();

    loop {
        if !seen.insert(current) {
            return None;
        }
        if current == root_pid {
            return Some(depth);
        }
        let process = by_pid.get(&current)?;
        if process.parent_pid == 0 || process.parent_pid == current {
            return None;
        }
        current = process.parent_pid;
        depth = depth.saturating_add(1);
    }
}

pub fn snapshot_process_tree(
    root_pid: u32,
    run_id: &str,
) -> Result<Vec<RuntimeEvent>, CollectorError> {
    let processes = WindowsProcessCollector::enumerate_processes()?;
    let selected = WindowsProcessCollector::select_process_tree(&processes, root_pid)?;
    let timestamp_ms = WindowsProcessCollector::now_ms();
    let mut events = Vec::with_capacity(selected.len());

    for process in selected {
        let relationship = if process.pid == root_pid {
            "root"
        } else {
            "child"
        };
        let executable = process.name.clone();
        events.push(RuntimeEvent {
            id: format!("{run_id}-bootstrap-{}", process.pid),
            timestamp_ms,
            event_type: EventType::ProcessObserved,
            process: ProcessIdentity {
                pid: process.pid,
                executable: executable.clone(),
                command_line: None,
                parent_pid: Some(process.parent_pid).filter(|pid| *pid != 0),
            },
            subject: "process".to_string(),
            target: Some(executable),
            metadata: serde_json::json!({
                "root_pid": root_pid,
                "parent_pid": process.parent_pid,
                "depth": process.depth,
                "relationship": relationship,
                "thread_count": process.thread_count,
                "observation": "bootstrap"
            }),
            source: "windows_process_watch".to_string(),
            sensitivity: Sensitivity::SystemMetadata,
        });
    }

    Ok(events)
}

pub fn wait_for_watchers(
    receiver: &Receiver<ProcessWatchEvent>,
    timeout: Duration,
) -> Result<Vec<ProcessWatchEvent>, CollectorError> {
    let deadline = std::time::Instant::now() + timeout;
    let mut ready = BTreeSet::new();
    let mut queued_events = Vec::new();

    while ready.len() < 2 {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(CollectorError::new(
                "windows_process_watch",
                "Timed out waiting for Windows process event watchers to initialize.",
            ));
        }

        match receiver.recv_timeout(remaining) {
            Ok(ProcessWatchEvent::Ready(source)) => {
                ready.insert(source);
            }
            Ok(ProcessWatchEvent::Start(event)) => {
                queued_events.push(ProcessWatchEvent::Start(event));
            }
            Ok(ProcessWatchEvent::Exit(event)) => {
                queued_events.push(ProcessWatchEvent::Exit(event));
            }
            Ok(ProcessWatchEvent::Error(message)) => {
                return Err(CollectorError::new("windows_process_watch", message));
            }
            Err(_) => {
                return Err(CollectorError::new(
                    "windows_process_watch",
                    "Timed out waiting for Windows process event watchers to initialize.",
                ));
            }
        }
    }

    Ok(queued_events)
}

fn windows_error(collector: &'static str, message: &str) -> CollectorError {
    let error = unsafe { GetLastError() };
    CollectorError::new(collector, format!("{message}. Windows error {error}."))
}

fn utf16_string(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_string_stops_at_null() {
        assert_eq!(
            utf16_string(&[b'A' as u16, b'B' as u16, 0, b'C' as u16]),
            "AB"
        );
    }

    #[test]
    fn selects_root_and_descendants() {
        let processes = vec![
            ProcessRecord {
                pid: 10,
                parent_pid: 1,
                name: "root.exe".into(),
                thread_count: 4,
            },
            ProcessRecord {
                pid: 11,
                parent_pid: 10,
                name: "child.exe".into(),
                thread_count: 2,
            },
            ProcessRecord {
                pid: 12,
                parent_pid: 11,
                name: "grandchild.exe".into(),
                thread_count: 1,
            },
            ProcessRecord {
                pid: 20,
                parent_pid: 999,
                name: "other.exe".into(),
                thread_count: 1,
            },
        ];

        let selected = WindowsProcessCollector::select_process_tree(&processes, 10).unwrap();

        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].pid, 10);
        assert_eq!(selected[0].depth, 0);
        assert_eq!(selected[1].pid, 11);
        assert_eq!(selected[1].depth, 1);
        assert_eq!(selected[2].pid, 12);
        assert_eq!(selected[2].depth, 2);
    }

    #[test]
    fn classify_depth_follows_parent_chain() {
        let processes = vec![
            ProcessRecord {
                pid: 10,
                parent_pid: 1,
                name: "root.exe".into(),
                thread_count: 4,
            },
            ProcessRecord {
                pid: 11,
                parent_pid: 10,
                name: "child.exe".into(),
                thread_count: 2,
            },
            ProcessRecord {
                pid: 12,
                parent_pid: 11,
                name: "grandchild.exe".into(),
                thread_count: 1,
            },
        ];

        assert_eq!(classify_process_depth(&processes, 10, 10), Some(0));
        assert_eq!(classify_process_depth(&processes, 10, 11), Some(1));
        assert_eq!(classify_process_depth(&processes, 10, 12), Some(2));
        assert_eq!(classify_process_depth(&processes, 10, 99), None);
    }

    #[test]
    fn lifecycle_event_ids_are_run_scoped() {
        let start = ProcessStartTrace {
            process_id: 11,
            parent_process_id: 10,
            process_name: "child.exe".into(),
        };

        let first = build_process_lifecycle_event("watch-a", 1, 10, 100, &start, 1);
        let second = build_process_lifecycle_event("watch-b", 1, 10, 100, &start, 1);

        assert_ne!(first.id, second.id);
        assert!(matches!(first.event_type, EventType::ProcessStart));
    }

    #[test]
    fn missing_root_is_an_error() {
        let processes = vec![ProcessRecord {
            pid: 10,
            parent_pid: 1,
            name: "root.exe".into(),
            thread_count: 1,
        }];

        let result = WindowsProcessCollector::select_process_tree(&processes, 99);
        assert!(result.is_err());
    }
}
