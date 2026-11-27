//! Atomic, bounded event batches for runtime collectors.
//!
//! A successful flush commits every event in the batch in one SQLite
//! transaction. A failed flush leaves the in-memory batch intact so the
//! caller can account for pending events or retry deliberately.

use rusqlite::Connection;

use crate::model::RuntimeEvent;

use super::{cleanup_storage_pressure, insert_event, with_storage_space_recovery, StorageError};

/// Default upper bound for one in-memory event batch.
pub const DEFAULT_EVENT_BATCH_SIZE: usize = 128;

/// Write a group of events for one run in a single SQLite transaction.
///
/// An empty slice is a no-op. The existing storage-full recovery path is
/// retained, and a failed insert rolls back the entire batch.
pub fn append_events(
    connection: &mut Connection,
    run_id: &str,
    events: &[RuntimeEvent],
) -> Result<(), StorageError> {
    if events.is_empty() {
        return Ok(());
    }

    with_storage_space_recovery(connection, |connection, retry_after_full| {
        if retry_after_full {
            cleanup_storage_pressure(connection, run_id)?;
        }

        let transaction = connection.transaction()?;
        for event in events {
            insert_event(&transaction, run_id, event)?;
        }
        transaction.commit()?;
        Ok(())
    })
}

/// A bounded queue of events waiting for an atomic SQLite commit.
#[derive(Debug)]
pub struct EventBatch {
    events: Vec<RuntimeEvent>,
    max_events: usize,
}

impl EventBatch {
    /// Create a batch with a fixed maximum number of events.
    pub fn new(max_events: usize) -> Result<Self, StorageError> {
        if max_events == 0 {
            return Err(StorageError::InvalidValue(
                "event batch capacity must be greater than zero".to_string(),
            ));
        }

        Ok(Self {
            events: Vec::with_capacity(max_events),
            max_events,
        })
    }

    /// Add an event unless the configured capacity has been reached.
    pub fn push(&mut self, event: RuntimeEvent) -> Result<(), StorageError> {
        if self.events.len() >= self.max_events {
            return Err(StorageError::InvalidValue(format!(
                "event batch is full at {} events",
                self.max_events
            )));
        }

        self.events.push(event);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.events.len() == self.max_events
    }

    /// Commit the pending events and return them only after the commit succeeds.
    /// On error, the batch remains available for accounting or a deliberate retry.
    pub fn flush(
        &mut self,
        connection: &mut Connection,
        run_id: &str,
    ) -> Result<Vec<RuntimeEvent>, StorageError> {
        if self.events.is_empty() {
            return Ok(Vec::new());
        }

        append_events(connection, run_id, &self.events)?;
        Ok(std::mem::take(&mut self.events))
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{
        EventType, ProcessIdentity, RuntimeEvent, RuntimePassport, RuntimeSnapshot, Sensitivity,
    };
    use crate::storage::{begin_run, get_run, initialize};

    use super::{append_events, EventBatch, DEFAULT_EVENT_BATCH_SIZE};

    fn start_run(connection: &mut rusqlite::Connection, run_id: &str) {
        let snapshot = RuntimeSnapshot {
            schema_version: "0.1".to_string(),
            snapshot_id: run_id.to_string(),
            application: "batch-test.exe".to_string(),
            started_at_ms: 100,
            ended_at_ms: None,
            events: Vec::new(),
        };
        let passport = RuntimePassport {
            schema_version: "0.1".to_string(),
            passport_id: format!("passport-{run_id}"),
            generated_at_ms: 100,
            application: "batch-test.exe".to_string(),
            observations: Default::default(),
            changes: Vec::new(),
        };
        begin_run(connection, &snapshot, &passport).expect("run should begin");
    }

    fn event(id: &str, timestamp_ms: i64) -> RuntimeEvent {
        RuntimeEvent {
            id: id.to_string(),
            timestamp_ms,
            event_type: EventType::ProcessObserved,
            process: ProcessIdentity {
                pid: 42,
                executable: "batch-test.exe".to_string(),
                command_line: None,
                parent_pid: Some(1),
            },
            subject: "process".to_string(),
            target: Some("batch-test.exe".to_string()),
            metadata: serde_json::json!({"depth": 0}),
            source: "batch-test".to_string(),
            sensitivity: Sensitivity::SystemMetadata,
        }
    }

    #[test]
    fn append_events_commits_the_batch_in_timestamp_order() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        start_run(&mut connection, "batch-order");

        append_events(
            &mut connection,
            "batch-order",
            &[event("first", 101), event("second", 102)],
        )
        .expect("batch should commit");

        let run = get_run(&connection, "batch-order")
            .expect("run should be readable")
            .expect("run should exist");
        assert_eq!(run.events.len(), 2);
        assert_eq!(run.events[0].event_id, "first");
        assert_eq!(run.events[1].event_id, "second");
    }

    #[test]
    fn append_events_rolls_back_the_whole_batch_on_duplicate_id() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        start_run(&mut connection, "batch-rollback");

        let result = append_events(
            &mut connection,
            "batch-rollback",
            &[event("duplicate", 101), event("duplicate", 102)],
        );
        assert!(result.is_err());

        let run = get_run(&connection, "batch-rollback")
            .expect("run should remain readable")
            .expect("run should still exist");
        assert!(run.events.is_empty());
    }

    #[test]
    fn empty_batch_is_a_no_op() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        start_run(&mut connection, "batch-empty");

        append_events(&mut connection, "batch-empty", &[]).expect("empty batch should succeed");

        let run = get_run(&connection, "batch-empty")
            .expect("run should be readable")
            .expect("run should exist");
        assert!(run.events.is_empty());
    }

    #[test]
    fn bounded_batch_retains_events_after_a_failed_flush() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        start_run(&mut connection, "batch-pending");

        let mut batch = EventBatch::new(2).expect("batch capacity should be valid");
        batch
            .push(event("duplicate", 101))
            .expect("first event should queue");
        batch
            .push(event("duplicate", 102))
            .expect("second event should queue");
        assert!(batch.is_full());

        assert!(batch.flush(&mut connection, "batch-pending").is_err());
        assert_eq!(batch.len(), 2);

        let run = get_run(&connection, "batch-pending")
            .expect("run should remain readable")
            .expect("run should exist");
        assert!(run.events.is_empty());
    }

    #[test]
    fn batch_capacity_must_be_positive_and_cannot_be_exceeded() {
        assert!(EventBatch::new(0).is_err());
        let mut batch = EventBatch::new(1).expect("capacity should be valid");
        assert_eq!(DEFAULT_EVENT_BATCH_SIZE, 128);
        batch.push(event("one", 101)).expect("event should queue");
        assert!(batch.push(event("two", 102)).is_err());
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn successful_flush_returns_committed_events_and_clears_the_batch() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        start_run(&mut connection, "batch-flush");

        let mut batch = EventBatch::new(2).expect("capacity should be valid");
        batch.push(event("one", 101)).expect("event should queue");
        batch.push(event("two", 102)).expect("event should queue");

        let committed = batch
            .flush(&mut connection, "batch-flush")
            .expect("batch should commit");
        assert_eq!(committed.len(), 2);
        assert!(batch.is_empty());

        let run = get_run(&connection, "batch-flush")
            .expect("run should be readable")
            .expect("run should exist");
        assert_eq!(run.events.len(), 2);
    }
}
