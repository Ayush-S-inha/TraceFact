use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecursiveMode, Watcher};

use crate::collectors::CollectorError;

/// Bound callback backlog so a busy directory cannot grow memory without limit.
pub const FILESYSTEM_QUEUE_CAPACITY: usize = 2_048;
/// Initial inventory is capped; exceeding it is recorded as incomplete coverage.
pub const MAX_INITIAL_INVENTORY_ENTRIES: usize = 10_000;

#[derive(Debug)]
pub enum FileSystemWatchMessage {
    Event(Event),
}

#[derive(Debug, Clone)]
pub struct FileSystemObservation {
    pub operation: &'static str,
    pub path: String,
    pub related_path: Option<String>,
    pub entry_kind: &'static str,
}

#[derive(Debug, Clone)]
pub struct InventoryEntry {
    pub relative_path: String,
    pub entry_kind: &'static str,
}

#[derive(Debug, Default)]
pub struct InitialInventory {
    pub entries: Vec<InventoryEntry>,
    pub truncated: bool,
    pub unreadable_entries: u64,
}

pub struct WindowsFileSystemEventWatcher {
    // Dropping RecommendedWatcher stops the native filesystem notification backend.
    watcher: Option<notify::RecommendedWatcher>,
    receiver: Option<Receiver<FileSystemWatchMessage>>,
    dropped_events: Arc<AtomicUsize>,
    first_error: Arc<Mutex<Option<String>>>,
}

impl WindowsFileSystemEventWatcher {
    pub fn start(root: &Path) -> Result<Self, CollectorError> {
        let (sender, receiver) = mpsc::sync_channel(FILESYSTEM_QUEUE_CAPACITY);
        let dropped_events = Arc::new(AtomicUsize::new(0));
        let first_error = Arc::new(Mutex::new(None::<String>));

        let callback_sender: SyncSender<FileSystemWatchMessage> = sender;
        let callback_dropped = Arc::clone(&dropped_events);
        let callback_error = Arc::clone(&first_error);

        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<Event>| match result {
                Ok(event) => match callback_sender.try_send(FileSystemWatchMessage::Event(event)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        callback_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => {}
                },
                Err(error) => {
                    let mut stored = callback_error
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if stored.is_none() {
                        *stored = Some(error.to_string());
                    }
                }
            })
            .map_err(|error| {
                CollectorError::new(
                    "windows_filesystem",
                    format!("Could not create filesystem notification watcher: {error}"),
                )
            })?;

        watcher
            .watch(root, RecursiveMode::Recursive)
            .map_err(|error| {
                CollectorError::new(
                    "windows_filesystem",
                    format!(
                        "Could not watch selected directory {} recursively: {error}",
                        root.display()
                    ),
                )
            })?;

        Ok(Self {
            watcher: Some(watcher),
            receiver: Some(receiver),
            dropped_events,
            first_error,
        })
    }

    pub fn take_receiver(&mut self) -> Option<Receiver<FileSystemWatchMessage>> {
        self.receiver.take()
    }

    pub fn dropped_events(&self) -> usize {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub fn first_error(&self) -> Option<String> {
        self.first_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn stop(&mut self) {
        // The backend is owned by this handle. Dropping it stops future native watches.
        drop(self.watcher.take());
    }
}

impl Drop for WindowsFileSystemEventWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Collect a bounded initial directory inventory without following symlinks.
/// File contents are never opened or read.
pub fn initial_inventory(root: &Path) -> InitialInventory {
    let mut inventory = InitialInventory::default();
    walk_directory(root, root, &mut inventory);
    inventory
        .entries
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    inventory
        .entries
        .dedup_by(|left, right| left.relative_path == right.relative_path);
    inventory
}

fn walk_directory(root: &Path, directory: &Path, inventory: &mut InitialInventory) {
    if inventory.truncated {
        return;
    }

    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => {
            inventory.unreadable_entries = inventory.unreadable_entries.saturating_add(1);
            return;
        }
    };

    for entry in entries {
        if inventory.entries.len() >= MAX_INITIAL_INVENTORY_ENTRIES {
            inventory.truncated = true;
            return;
        }

        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                inventory.unreadable_entries = inventory.unreadable_entries.saturating_add(1);
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                inventory.unreadable_entries = inventory.unreadable_entries.saturating_add(1);
                continue;
            }
        };

        let entry_kind = if file_type.is_dir() {
            "directory"
        } else if file_type.is_file() {
            "file"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };

        if let Some(relative_path) = relative_path(root, &path) {
            inventory.entries.push(InventoryEntry {
                relative_path,
                entry_kind,
            });
        }

        // Never follow symlinks. This keeps the watcher inventory within the selected root.
        if file_type.is_dir() {
            walk_directory(root, &path, inventory);
            if inventory.truncated {
                return;
            }
        }
    }
}

/// Convert notify events to path-level observations. Access/read notifications are deliberately
/// ignored: this feature records directory changes, not file reads or process-level file access.
pub fn observations_from_event(event: &Event, root: &Path) -> Vec<FileSystemObservation> {
    match &event.kind {
        EventKind::Create(_) => path_observations("created", &event.paths, root),
        EventKind::Remove(_) => path_observations("removed", &event.paths, root),
        EventKind::Modify(ModifyKind::Name(mode)) => {
            if event.paths.len() >= 2 {
                let old_path = relative_path(root, &event.paths[0]);
                let new_path = event
                    .paths
                    .last()
                    .and_then(|path| relative_path(root, path));
                match (old_path, new_path) {
                    (Some(old_path), Some(new_path)) => vec![
                        make_observation(
                            "renamed_from",
                            old_path.clone(),
                            Some(new_path.clone()),
                            root,
                        ),
                        make_observation("renamed_to", new_path, Some(old_path), root),
                    ],
                    (Some(path), None) => vec![make_observation("renamed_from", path, None, root)],
                    (None, Some(path)) => vec![make_observation("renamed_to", path, None, root)],
                    (None, None) => Vec::new(),
                }
            } else {
                let operation = match mode {
                    RenameMode::From => "renamed_from",
                    RenameMode::To => "renamed_to",
                    _ => "renamed",
                };
                path_observations(operation, &event.paths, root)
            }
        }
        EventKind::Modify(_) => path_observations("modified", &event.paths, root),
        // Access, Any, Other, and other event classes are intentionally not represented as
        // filesystem changes because their semantics are not sufficiently specific here.
        _ => Vec::new(),
    }
}

fn path_observations(
    operation: &'static str,
    paths: &[PathBuf],
    root: &Path,
) -> Vec<FileSystemObservation> {
    paths
        .iter()
        .filter_map(|path| {
            relative_path(root, path).map(|path| make_observation(operation, path, None, root))
        })
        .collect()
}

fn make_observation(
    operation: &'static str,
    path: String,
    related_path: Option<String>,
    root: &Path,
) -> FileSystemObservation {
    let entry_kind = classify_entry_kind(root, &path);
    FileSystemObservation {
        operation,
        path,
        related_path,
        entry_kind,
    }
}

fn classify_entry_kind(root: &Path, relative_path: &str) -> &'static str {
    match fs::symlink_metadata(root.join(relative_path)) {
        Ok(metadata) if metadata.file_type().is_symlink() => "symlink",
        Ok(metadata) if metadata.is_dir() => "directory",
        Ok(metadata) if metadata.is_file() => "file",
        Ok(_) => "other",
        Err(_) => "unknown",
    }
}

fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let value = relative.to_string_lossy().replace('\\', "/");
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{initial_inventory, observations_from_event, MAX_INITIAL_INVENTORY_ENTRIES};
    use notify::event::{CreateKind, ModifyKind, RenameMode};
    use notify::{Event, EventKind};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("tracefact-fs-test-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn initial_inventory_is_relative_sorted_and_does_not_read_contents() {
        let root = temp_directory();
        fs::create_dir_all(root.join("nested")).expect("create nested directory");
        fs::write(root.join("z.txt"), b"not collected").expect("create file");
        fs::write(root.join("nested").join("a.txt"), b"not collected").expect("create nested file");

        let inventory = initial_inventory(&root);
        let paths: Vec<_> = inventory
            .entries
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        assert_eq!(paths, vec!["nested", "nested/a.txt", "z.txt"]);
        assert!(inventory
            .entries
            .iter()
            .all(|entry| !PathBuf::from(&entry.relative_path).is_absolute()));

        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn create_event_is_reduced_to_a_relative_path_without_contents() {
        let root = temp_directory();
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("created.txt"), b"content must not be collected").expect("create file");

        let event =
            Event::new(EventKind::Create(CreateKind::File)).add_path(root.join("created.txt"));
        let observations = observations_from_event(&event, &root);

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].operation, "created");
        assert_eq!(observations[0].path, "created.txt");
        assert_eq!(observations[0].entry_kind, "file");

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn paired_rename_event_preserves_old_and_new_relative_paths() {
        let root = temp_directory();
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("new.txt"), b"contents are not collected")
            .expect("create destination file");

        let event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(root.join("old.txt"))
            .add_path(root.join("new.txt"));
        let observations = observations_from_event(&event, &root);

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].operation, "renamed_from");
        assert_eq!(observations[0].path, "old.txt");
        assert_eq!(observations[0].related_path.as_deref(), Some("new.txt"));
        assert_eq!(observations[1].operation, "renamed_to");
        assert_eq!(observations[1].path, "new.txt");
        assert_eq!(observations[1].related_path.as_deref(), Some("old.txt"));

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn separate_rename_notifications_do_not_claim_an_unverified_pair() {
        let root = temp_directory();
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("new.txt"), b"contents are not collected")
            .expect("create destination file");

        let from_event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::From)))
            .add_path(root.join("old.txt"));
        let to_event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::To)))
            .add_path(root.join("new.txt"));

        let from = observations_from_event(&from_event, &root);
        let to = observations_from_event(&to_event, &root);

        assert_eq!(from.len(), 1);
        assert_eq!(from[0].operation, "renamed_from");
        assert_eq!(from[0].path, "old.txt");
        assert_eq!(from[0].related_path, None);
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].operation, "renamed_to");
        assert_eq!(to[0].path, "new.txt");
        assert_eq!(to[0].related_path, None);

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn relative_path_rejects_paths_outside_selected_root() {
        let root = temp_directory();
        assert_eq!(
            super::relative_path(&root, &root.join("inside.txt")),
            Some("inside.txt".to_string())
        );
        assert_eq!(
            super::relative_path(
                &root,
                &root
                    .parent()
                    .expect("temp dir has parent")
                    .join("outside.txt")
            ),
            None
        );
    }

    #[test]
    fn initial_inventory_is_bounded() {
        assert!(MAX_INITIAL_INVENTORY_ENTRIES > 0);
    }
}
