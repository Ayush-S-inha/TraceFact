use std::env;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::model::{RuntimeEvent, RuntimePassport, RuntimeSnapshot};

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Json(serde_json::Error),
    InvalidValue(String),
}

impl Display for StorageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "storage I/O error: {error}"),
            Self::Sql(error) => write!(formatter, "storage database error: {error}"),
            Self::Json(error) => write!(formatter, "storage serialization error: {error}"),
            Self::InvalidValue(message) => write!(formatter, "storage value error: {message}"),
        }
    }
}

impl Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sql(error)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub run_id: String,
    pub application: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub event_count: i64,
}

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub event_id: String,
    pub timestamp_ms: i64,
    pub event_type: String,
    pub pid: Option<u32>,
    pub executable: Option<String>,
    pub subject: Option<String>,
    pub target: Option<String>,
    pub metadata_json: String,
    pub source: String,
    pub sensitivity: String,
}

#[derive(Debug, Clone)]
pub struct StoredRun {
    pub run_id: String,
    pub application: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub schema_version: String,
    pub passport: RuntimePassport,
    pub events: Vec<StoredEvent>,
}

pub fn default_database_path() -> Result<PathBuf, StorageError> {
    #[cfg(windows)]
    {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| env::temp_dir());
        return Ok(base.join("TraceFact").join("tracefact.db"));
    }

    #[cfg(target_os = "macos")]
    {
        let base = home_dir()?.join("Library").join("Application Support");
        return Ok(base.join("TraceFact").join("tracefact.db"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                home_dir()
                    .unwrap_or_else(|_| env::temp_dir())
                    .join(".local")
                    .join("share")
            });
        return Ok(base.join("TraceFact").join("tracefact.db"));
    }

    #[allow(unreachable_code)]
    Ok(env::temp_dir().join("TraceFact").join("tracefact.db"))
}

pub fn open_default() -> Result<(Connection, PathBuf), StorageError> {
    let path = default_database_path()?;
    let parent = path.parent().ok_or_else(|| {
        StorageError::InvalidValue("default database path has no parent directory".to_string())
    })?;
    std::fs::create_dir_all(parent)?;
    let connection = initialize(path.to_string_lossy().as_ref())?;
    Ok((connection, path))
}

pub fn initialize(path: &str) -> Result<Connection, StorageError> {
    let connection = Connection::open(path)?;
    connection.execute_batch(include_str!("../../schema/tracefact.sql"))?;
    Ok(connection)
}

pub fn begin_run(
    connection: &mut Connection,
    snapshot: &RuntimeSnapshot,
    passport: &RuntimePassport,
) -> Result<(), StorageError> {
    let transaction = connection.transaction()?;

    transaction.execute(
        "INSERT INTO runs (run_id, application, started_at_ms, ended_at_ms, schema_version)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &snapshot.snapshot_id,
            &snapshot.application,
            snapshot.started_at_ms,
            snapshot.ended_at_ms,
            &snapshot.schema_version,
        ],
    )?;

    let passport_json = serde_json::to_string(passport)?;
    transaction.execute(
        "INSERT INTO passports (passport_id, run_id, generated_at_ms, passport_json)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            &passport.passport_id,
            &snapshot.snapshot_id,
            passport.generated_at_ms,
            passport_json,
        ],
    )?;

    transaction.commit()?;
    Ok(())
}

pub fn append_event(
    connection: &mut Connection,
    run_id: &str,
    event: &RuntimeEvent,
) -> Result<(), StorageError> {
    let transaction = connection.transaction()?;
    insert_event(&transaction, run_id, event)?;
    transaction.commit()?;
    Ok(())
}

pub fn finish_run(
    connection: &mut Connection,
    run_id: &str,
    ended_at_ms: i64,
    passport: &RuntimePassport,
) -> Result<(), StorageError> {
    let transaction = connection.transaction()?;

    let updated = transaction.execute(
        "UPDATE runs SET ended_at_ms = ?1 WHERE run_id = ?2",
        params![ended_at_ms, run_id],
    )?;

    if updated != 1 {
        return Err(StorageError::InvalidValue(format!(
            "run {run_id} was not found while finishing the run"
        )));
    }

    let passport_json = serde_json::to_string(passport)?;
    let updated = transaction.execute(
        "UPDATE passports
            SET generated_at_ms = ?1, passport_json = ?2
          WHERE passport_id = ?3 AND run_id = ?4",
        params![
            passport.generated_at_ms,
            passport_json,
            &passport.passport_id,
            run_id,
        ],
    )?;

    if updated != 1 {
        return Err(StorageError::InvalidValue(format!(
            "passport {} was not found while finishing run {run_id}",
            passport.passport_id
        )));
    }

    transaction.commit()?;
    Ok(())
}

pub fn save_snapshot_and_passport(
    connection: &mut Connection,
    snapshot: &RuntimeSnapshot,
    passport: &RuntimePassport,
) -> Result<(), StorageError> {
    let transaction = connection.transaction()?;

    transaction.execute(
        "INSERT INTO runs (run_id, application, started_at_ms, ended_at_ms, schema_version)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &snapshot.snapshot_id,
            &snapshot.application,
            snapshot.started_at_ms,
            snapshot.ended_at_ms,
            &snapshot.schema_version,
        ],
    )?;

    for event in &snapshot.events {
        insert_event(&transaction, &snapshot.snapshot_id, event)?;
    }

    let passport_json = serde_json::to_string(passport)?;
    transaction.execute(
        "INSERT INTO passports (passport_id, run_id, generated_at_ms, passport_json)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            &passport.passport_id,
            &snapshot.snapshot_id,
            passport.generated_at_ms,
            passport_json,
        ],
    )?;

    transaction.commit()?;
    Ok(())
}

fn insert_event(
    connection: &rusqlite::Transaction<'_>,
    run_id: &str,
    event: &RuntimeEvent,
) -> Result<(), StorageError> {
    let event_type = enum_text(&event.event_type, "event_type")?;
    let sensitivity = enum_text(&event.sensitivity, "sensitivity")?;
    let metadata_json = serde_json::to_string(&event.metadata)?;

    connection.execute(
        "INSERT INTO events (
            event_id,
            run_id,
            timestamp_ms,
            event_type,
            pid,
            executable,
            subject,
            target,
            metadata_json,
            source,
            sensitivity
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            &event.id,
            run_id,
            event.timestamp_ms,
            event_type,
            event.process.pid,
            &event.process.executable,
            &event.subject,
            &event.target,
            metadata_json,
            &event.source,
            sensitivity,
        ],
    )?;

    Ok(())
}

pub fn get_run(connection: &Connection, run_id: &str) -> Result<Option<StoredRun>, StorageError> {
    let run = connection
        .query_row(
            "SELECT run_id, application, started_at_ms, ended_at_ms, schema_version FROM runs WHERE run_id = ?1",
            params![run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;

    let Some((run_id, application, started_at_ms, ended_at_ms, schema_version)) = run else {
        return Ok(None);
    };

    let passport_json: String = connection.query_row(
        "SELECT passport_json FROM passports WHERE run_id = ?1 ORDER BY generated_at_ms DESC LIMIT 1",
        params![run_id],
        |row| row.get(0),
    )?;
    let passport: RuntimePassport = serde_json::from_str(&passport_json)?;

    let mut statement = connection.prepare(
        "SELECT event_id, timestamp_ms, event_type, pid, executable, subject, target, metadata_json, source, sensitivity FROM events WHERE run_id = ?1 ORDER BY timestamp_ms ASC, event_id ASC",
    )?;

    let rows = statement.query_map(params![run_id], |row| {
        Ok(StoredEvent {
            event_id: row.get(0)?,
            timestamp_ms: row.get(1)?,
            event_type: row.get(2)?,
            pid: row.get(3)?,
            executable: row.get(4)?,
            subject: row.get(5)?,
            target: row.get(6)?,
            metadata_json: row.get(7)?,
            source: row.get(8)?,
            sensitivity: row.get(9)?,
        })
    })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }

    Ok(Some(StoredRun {
        run_id,
        application,
        started_at_ms,
        ended_at_ms,
        schema_version,
        passport,
        events,
    }))
}

pub fn latest_run_id(connection: &Connection) -> Result<Option<String>, StorageError> {
    connection
        .query_row(
            "SELECT run_id FROM runs ORDER BY started_at_ms DESC, run_id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(StorageError::from)
}

pub fn list_runs(connection: &Connection, limit: u32) -> Result<Vec<RunSummary>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT r.run_id,
                r.application,
                r.started_at_ms,
                r.ended_at_ms,
                COUNT(e.event_id) AS event_count
           FROM runs r
           LEFT JOIN events e ON e.run_id = r.run_id
          GROUP BY r.run_id, r.application, r.started_at_ms, r.ended_at_ms
          ORDER BY r.started_at_ms DESC
          LIMIT ?1",
    )?;

    let rows = statement.query_map(params![limit], |row| {
        Ok(RunSummary {
            run_id: row.get(0)?,
            application: row.get(1)?,
            started_at_ms: row.get(2)?,
            ended_at_ms: row.get(3)?,
            event_count: row.get(4)?,
        })
    })?;

    let mut summaries = Vec::new();
    for row in rows {
        summaries.push(row?);
    }
    Ok(summaries)
}

fn enum_text<T: Serialize>(value: &T, field: &str) -> Result<String, StorageError> {
    let value = serde_json::to_value(value)?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::InvalidValue(format!("{field} did not serialize as a string")))
}

#[cfg(any(target_os = "macos", all(unix, not(target_os = "macos"))))]
fn home_dir() -> Result<PathBuf, StorageError> {
    env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .ok_or_else(|| StorageError::InvalidValue("home directory is not available".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EventType, ProcessIdentity, RuntimeEvent, Sensitivity};

    #[test]
    fn save_and_list_round_trip() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        let event = RuntimeEvent {
            id: "event-1".to_string(),
            timestamp_ms: 100,
            event_type: EventType::ProcessObserved,
            process: ProcessIdentity {
                pid: 42,
                executable: "demo.exe".to_string(),
                command_line: None,
                parent_pid: Some(7),
            },
            subject: "process".to_string(),
            target: Some("demo.exe".to_string()),
            metadata: serde_json::json!({"depth": 0}),
            source: "test".to_string(),
            sensitivity: Sensitivity::SystemMetadata,
        };

        let snapshot = RuntimeSnapshot {
            schema_version: "0.1".to_string(),
            snapshot_id: "snap-test".to_string(),
            application: "demo.exe".to_string(),
            started_at_ms: 100,
            ended_at_ms: Some(100),
            events: vec![event],
        };

        let passport = RuntimePassport {
            schema_version: "0.1".to_string(),
            passport_id: "passport-snap-test".to_string(),
            generated_at_ms: 101,
            application: "demo.exe".to_string(),
            observations: Default::default(),
            changes: vec![],
        };

        save_snapshot_and_passport(&mut connection, &snapshot, &passport)
            .expect("snapshot should be saved");

        let runs = list_runs(&connection, 10).expect("runs should be readable");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, "snap-test");
        assert_eq!(runs[0].application, "demo.exe");
        assert_eq!(runs[0].event_count, 1);
    }
    #[test]
    fn get_run_returns_passport_and_events() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        let event = RuntimeEvent {
            id: "event-inspect".to_string(),
            timestamp_ms: 200,
            event_type: EventType::ProcessObserved,
            process: ProcessIdentity {
                pid: 99,
                executable: "inspect.exe".to_string(),
                command_line: None,
                parent_pid: Some(1),
            },
            subject: "process".to_string(),
            target: Some("inspect.exe".to_string()),
            metadata: serde_json::json!({"depth": 0}),
            source: "test".to_string(),
            sensitivity: Sensitivity::SystemMetadata,
        };
        let snapshot = RuntimeSnapshot {
            schema_version: "0.1".to_string(),
            snapshot_id: "snap-inspect".to_string(),
            application: "inspect.exe".to_string(),
            started_at_ms: 200,
            ended_at_ms: Some(201),
            events: vec![event],
        };
        let passport = RuntimePassport {
            schema_version: "0.1".to_string(),
            passport_id: "passport-snap-inspect".to_string(),
            generated_at_ms: 202,
            application: "inspect.exe".to_string(),
            observations: Default::default(),
            changes: vec![],
        };
        save_snapshot_and_passport(&mut connection, &snapshot, &passport)
            .expect("snapshot should be saved");

        let stored = get_run(&connection, "snap-inspect")
            .expect("run should be readable")
            .expect("run should exist");

        assert_eq!(stored.run_id, "snap-inspect");
        assert_eq!(stored.passport.passport_id, "passport-snap-inspect");
        assert_eq!(stored.events.len(), 1);
        assert_eq!(stored.events[0].event_id, "event-inspect");
    }

    #[test]
    fn continuous_run_lifecycle_round_trip() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        let snapshot = RuntimeSnapshot {
            schema_version: "0.1".into(),
            snapshot_id: "watch-test".into(),
            application: "demo.exe".into(),
            started_at_ms: 1000,
            ended_at_ms: None,
            events: vec![],
        };
        let passport = RuntimePassport {
            schema_version: "0.1".into(),
            passport_id: "passport-watch-test".into(),
            generated_at_ms: 1000,
            application: "demo.exe".into(),
            observations: Default::default(),
            changes: vec![],
        };

        begin_run(&mut connection, &snapshot, &passport).expect("run should begin");

        let event = RuntimeEvent {
            id: "watch-event-1".into(),
            timestamp_ms: 1001,
            event_type: EventType::ProcessStart,
            process: ProcessIdentity {
                pid: 42,
                executable: "child.exe".into(),
                command_line: None,
                parent_pid: Some(10),
            },
            subject: "process".into(),
            target: Some("child.exe".into()),
            metadata: serde_json::json!({"depth": 1}),
            source: "test".into(),
            sensitivity: Sensitivity::SystemMetadata,
        };

        append_event(&mut connection, "watch-test", &event).expect("event should be appended");

        let completed_passport = RuntimePassport {
            schema_version: "0.1".into(),
            passport_id: "passport-watch-test".into(),
            generated_at_ms: 2000,
            application: "demo.exe".into(),
            observations: crate::model::PassportObservations {
                processes: vec!["child.exe".into()],
                network_targets: vec![],
                files: vec![],
                libraries: vec![],
            },
            changes: vec![],
        };

        finish_run(&mut connection, "watch-test", 2000, &completed_passport)
            .expect("run should finish");

        let stored = get_run(&connection, "watch-test")
            .expect("run should be readable")
            .expect("run should exist");

        assert_eq!(stored.ended_at_ms, Some(2000));
        assert_eq!(stored.events.len(), 1);
        assert_eq!(stored.events[0].event_id, "watch-event-1");
        assert_eq!(stored.passport.generated_at_ms, 2000);
        assert_eq!(stored.passport.observations.processes, vec!["child.exe"]);
    }

    #[test]
    fn latest_run_id_returns_most_recent_run() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        for (run_id, started_at_ms) in [("snap-old", 100_i64), ("snap-new", 200_i64)] {
            let snapshot = RuntimeSnapshot {
                schema_version: "0.1".to_string(),
                snapshot_id: run_id.to_string(),
                application: "demo.exe".to_string(),
                started_at_ms,
                ended_at_ms: Some(started_at_ms),
                events: vec![],
            };
            let passport = RuntimePassport {
                schema_version: "0.1".to_string(),
                passport_id: format!("passport-{run_id}"),
                generated_at_ms: started_at_ms,
                application: "demo.exe".to_string(),
                observations: Default::default(),
                changes: vec![],
            };
            save_snapshot_and_passport(&mut connection, &snapshot, &passport)
                .expect("snapshot should be saved");
        }

        assert_eq!(
            latest_run_id(&connection).expect("latest run should be readable"),
            Some("snap-new".to_string())
        );
    }
}
