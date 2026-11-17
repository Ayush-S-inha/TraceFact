use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
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
pub const PROCESS_EVENT_QUEUE_CAPACITY: usize = 4096;

#[derive(Debug, Clone)]
pub(crate) struct ProcessRecord {
    pid: u32,
    parent_pid: u32,
    name: String,
    thread_count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessTreeMember {
    pub parent_pid: Option<u32>,
    pub name: String,
    pub depth: u32,
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
}

#[derive(Debug)]
pub enum ProcessWatchControl {
    Ready(WatchSource),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WatchSource {
    Starts,
    Exits,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessEventDropCounts {
    pub start_events: usize,
    pub exit_events: usize,
}

#[derive(Default)]
struct ProcessEventQueueState {
    stopped: bool,
    dropped: ProcessEventDropCounts,
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
    control_receiver: Receiver<ProcessWatchControl>,
    queue_state: Arc<Mutex<ProcessEventQueueState>>,
}

impl WindowsProcessEventWatcher {
    pub fn start() -> Self {
        let (sender, receiver) = mpsc::sync_channel(PROCESS_EVENT_QUEUE_CAPACITY);
        let (control_sender, control_receiver) = mpsc::channel();
        let queue_state = Arc::new(Mutex::new(ProcessEventQueueState::default()));
        spawn_start_watcher(
            sender.clone(),
            control_sender.clone(),
            Arc::clone(&queue_state),
        );
        spawn_exit_watcher(sender, control_sender, Arc::clone(&queue_state));
        Self {
            receiver,
            control_receiver,
            queue_state,
        }
    }

    pub fn receiver(&self) -> &Receiver<ProcessWatchEvent> {
        &self.receiver
    }

    pub fn control_receiver(&self) -> &Receiver<ProcessWatchControl> {
        &self.control_receiver
    }

    pub fn stop_event_collection(&self) -> ProcessEventDropCounts {
        let mut state = self
            .queue_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.stopped = true;
        state.dropped
    }
}

fn try_send_process_event(
    sender: &SyncSender<ProcessWatchEvent>,
    queue_state: &Mutex<ProcessEventQueueState>,
    event: ProcessWatchEvent,
) -> bool {
    let mut state = queue_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if state.stopped {
        return false;
    }

    match sender.try_send(event) {
        Ok(()) => true,
        Err(TrySendError::Full(event)) => {
            match event {
                ProcessWatchEvent::Start(_) => {
                    state.dropped.start_events = state.dropped.start_events.saturating_add(1);
                }
                ProcessWatchEvent::Exit(_) => {
                    state.dropped.exit_events = state.dropped.exit_events.saturating_add(1);
                }
            }
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn spawn_start_watcher(
    sender: SyncSender<ProcessWatchEvent>,
    control_sender: mpsc::Sender<ProcessWatchControl>,
    queue_state: Arc<Mutex<ProcessEventQueueState>>,
) {
    thread::spawn(move || {
        let connection = match WMIConnection::new() {
            Ok(connection) => connection,
            Err(error) => {
                let _ = control_sender.send(ProcessWatchControl::Error(format!(
                    "Could not connect to WMI for process start events: {error}"
                )));
                return;
            }
        };

        let events = match connection.notification::<ProcessStartTrace>() {
            Ok(events) => events,
            Err(error) => {
                let _ = control_sender.send(ProcessWatchControl::Error(format!(
                    "Could not subscribe to Windows process start events: {error}"
                )));
                return;
            }
        };

        if control_sender
            .send(ProcessWatchControl::Ready(WatchSource::Starts))
            .is_err()
        {
            return;
        }

        for result in events {
            match result {
                Ok(event) => {
                    if !try_send_process_event(
                        &sender,
                        &queue_state,
                        ProcessWatchEvent::Start(event),
                    ) {
                        break;
                    }
                }
                Err(error) => {
                    let _ = control_sender.send(ProcessWatchControl::Error(format!(
                        "Windows process start event stream failed: {error}"
                    )));
                    break;
                }
            }
        }
    });
}

fn spawn_exit_watcher(
    sender: SyncSender<ProcessWatchEvent>,
    control_sender: mpsc::Sender<ProcessWatchControl>,
    queue_state: Arc<Mutex<ProcessEventQueueState>>,
) {
    thread::spawn(move || {
        let connection = match WMIConnection::new() {
            Ok(connection) => connection,
            Err(error) => {
                let _ = control_sender.send(ProcessWatchControl::Error(format!(
                    "Could not connect to WMI for process exit events: {error}"
                )));
                return;
            }
        };

        let events = match connection.notification::<ProcessStopTrace>() {
            Ok(events) => events,
            Err(error) => {
                let _ = control_sender.send(ProcessWatchControl::Error(format!(
                    "Could not subscribe to Windows process exit events: {error}"
                )));
                return;
            }
        };

        if control_sender
            .send(ProcessWatchControl::Ready(WatchSource::Exits))
            .is_err()
        {
            return;
        }

        for result in events {
            match result {
                Ok(event) => {
                    if !try_send_process_event(
                        &sender,
                        &queue_state,
                        ProcessWatchEvent::Exit(event),
                    ) {
                        break;
                    }
                }
                Err(error) => {
                    let _ = control_sender.send(ProcessWatchControl::Error(format!(
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

pub fn build_process_watch_summary_event(
    run_id: &str,
    sequence: u64,
    root_pid: u32,
    timestamp_ms: i64,
    dropped: ProcessEventDropCounts,
    unpersisted_events_at_stop: usize,
) -> RuntimeEvent {
    RuntimeEvent {
        id: format!("{run_id}-event-{sequence}"),
        timestamp_ms,
        event_type: EventType::ProcessObserved,
        process: ProcessIdentity {
            pid: root_pid,
            executable: "process-watch-summary".to_string(),
            command_line: None,
            parent_pid: None,
        },
        subject: "watch_summary".to_string(),
        target: None,
        metadata: serde_json::json!({
            "operation": "watch_summary",
            "root_pid": root_pid,
            "dropped_start_events": dropped.start_events,
            "dropped_exit_events": dropped.exit_events,
            "unpersisted_events_at_stop": unpersisted_events_at_stop,
            "queue_capacity": PROCESS_EVENT_QUEUE_CAPACITY
        }),
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

pub(crate) fn identify_process_in_tree(
    root_pid: u32,
    target_pid: u32,
) -> Result<Option<ProcessTreeMember>, CollectorError> {
    let processes = WindowsProcessCollector::enumerate_processes()?;
    let Some(depth) = classify_process_depth(&processes, root_pid, target_pid) else {
        return Ok(None);
    };
    let Some(process) = processes.iter().find(|process| process.pid == target_pid) else {
        return Ok(None);
    };

    Ok(Some(ProcessTreeMember {
        parent_pid: Some(process.parent_pid).filter(|pid| *pid != 0),
        name: process.name.clone(),
        depth,
    }))
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
    watcher: &WindowsProcessEventWatcher,
    timeout: Duration,
) -> Result<(), CollectorError> {
    let deadline = std::time::Instant::now() + timeout;
    let mut ready = BTreeSet::new();

    while ready.len() < 2 {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(CollectorError::new(
                "windows_process_watch",
                "Timed out waiting for Windows process event watchers to initialize.",
            ));
        }

        match watcher.control_receiver().recv_timeout(remaining) {
            Ok(ProcessWatchControl::Ready(source)) => {
                ready.insert(source);
            }
            Ok(ProcessWatchControl::Error(message)) => {
                return Err(CollectorError::new("windows_process_watch", message));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(CollectorError::new(
                    "windows_process_watch",
                    "Timed out waiting for Windows process event watchers to initialize.",
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(CollectorError::new(
                    "windows_process_watch",
                    "Process watcher control channel disconnected during startup.",
                ));
            }
        }
    }

    Ok(())
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
    fn missing_root_is_an_error() {    #[test]
    fn bounded_queue_counts_start_and_exit_drops_separately() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let queue_state = Mutex::new(ProcessEventQueueState::default());
        let start = ProcessWatchEvent::Start(ProcessStartTrace {
            process_id: 8101,
            parent_process_id: 8100,
            process_name: "worker.exe".to_string(),
        });
        let exit = ProcessWatchEvent::Exit(ProcessStopTrace {
            process_id: 8102,
            parent_process_id: 8100,
            process_name: "child.exe".to_string(),
            exit_status: 0,
        });

        assert!(try_send_process_event(&sender, &queue_state, start));
        assert!(try_send_process_event(&sender, &queue_state, exit));
        assert_eq!(receiver.try_iter().count(), 1);

        let state = queue_state.lock().unwrap();
        assert_eq!(state.dropped.start_events, 0);
        assert_eq!(state.dropped.exit_events, 1);
    }

    #[test]
    fn stopped_queue_rejects_late_events() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let queue_state = Mutex::new(ProcessEventQueueState::default());
        queue_state.lock().unwrap().stopped = true;
        let event = ProcessWatchEvent::Start(ProcessStartTrace {
            process_id: 8103,
            parent_process_id: 8100,
            process_name: "late.exe".to_string(),
        });

        assert!(!try_send_process_event(&sender, &queue_state, event));
        assert_eq!(receiver.try_iter().count(), 0);
        assert_eq!(
            queue_state.lock().unwrap().dropped,
            ProcessEventDropCounts::default()
        );
    }

    #[test]
    fn watch_summary_records_queue_loss() {
        let event = build_process_watch_summary_event(
            "watch-8100-run",
            7,
            8100,
            900,
            ProcessEventDropCounts {
                start_events: 3,
                exit_events: 2,
            },
            4,
        );

        assert_eq!(event.subject, "watch_summary");
        assert_eq!(event.metadata["dropped_start_events"], 3);
        assert_eq!(event.metadata["dropped_exit_events"], 2);
        assert_eq!(event.metadata["unpersisted_events_at_stop"], 4);
    }


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
