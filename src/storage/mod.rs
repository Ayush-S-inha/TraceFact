use std::env;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::model::{
    EvidenceCoverage, EvidenceScope, RuntimeEvent, RuntimePassport, RuntimePassportBaseline,
    RuntimeSnapshot,
};

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Json(serde_json::Error),
    InvalidValue(String),
    // The first write hit SQLITE_FULL and its one recovery attempt also failed.
    StorageFullRecovery(String),
}

impl Display for StorageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "storage I/O error: {error}"),
            Self::Sql(error) => write!(formatter, "storage database error: {error}"),
            Self::Json(error) => write!(formatter, "storage serialization error: {error}"),
            Self::InvalidValue(message) => write!(formatter, "storage value error: {message}"),
            Self::StorageFullRecovery(message) => {
                write!(formatter, "storage-full recovery error: {message}")
            }
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
    pub status: String,
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
    pub status: String,
    pub schema_version: String,
    pub passport: RuntimePassport,
    pub events: Vec<StoredEvent>,
}

#[derive(Debug, Clone)]
pub struct BaselineSummary {
    pub name: String,
    pub application: String,
    pub created_at_ms: i64,
    pub source_run_id: String,
    pub event_count: u64,
    pub collector_sources: Vec<String>,
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
    ensure_storage_reserve(&path);
    let connection = initialize(path.to_string_lossy().as_ref())?;
    Ok((connection, path))
}

const CURRENT_SCHEMA_VERSION: i64 = 2;
const DEFAULT_MAX_RUNS: u64 = 500;
const DEFAULT_MAX_DATABASE_MB: u64 = 1024;
const SQLITE_MAX_PAGE_COUNT: i64 = 4_294_967_294;
const STORAGE_RESERVE_BYTES: usize = 1024 * 1024;
const STORAGE_RESERVE_MARKER: &[u8] = b"TRACEFACT_STORAGE_RESERVE_V1\n";

#[derive(Debug, Clone)]
pub struct StorageStatus {
    pub database_bytes: u64,
    pub database_limit_bytes: Option<u64>,
    pub emergency_reserve_bytes: u64,
    pub run_count: u64,
    pub protected_run_count: u64,
    pub max_runs: u64,
}

fn configured_limit(name: &str, default: u64) -> Result<u64, StorageError> {
    let Some(value) = env::var_os(name) else {
        return Ok(default);
    };
    value
        .to_string_lossy()
        .parse::<u64>()
        .map_err(|_| StorageError::InvalidValue(format!("{name} must be a non-negative integer")))
}

fn configured_max_runs() -> Result<u64, StorageError> {
    configured_limit("TRACEFACT_MAX_RUNS", DEFAULT_MAX_RUNS)
}

fn configured_max_database_mb() -> Result<u64, StorageError> {
    configured_limit("TRACEFACT_MAX_DATABASE_MB", DEFAULT_MAX_DATABASE_MB)
}

fn configure_database_limit(connection: &Connection) -> Result<(), StorageError> {
    let limit_mb = configured_max_database_mb()?;
    let max_pages = if limit_mb == 0 {
        SQLITE_MAX_PAGE_COUNT
    } else {
        let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let page_size = u64::try_from(page_size).unwrap_or(4096);
        let max_bytes = limit_mb.checked_mul(1024 * 1024).ok_or_else(|| {
            StorageError::InvalidValue("database size limit is too large".to_string())
        })?;
        i64::try_from((max_bytes / page_size).max(1)).map_err(|_| {
            StorageError::InvalidValue(
                "database size limit exceeds SQLite's page limit".to_string(),
            )
        })?
    };
    connection.pragma_update(None, "max_page_count", max_pages)?;
    Ok(())
}

fn reserve_path(database_path: &Path) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push(".reserve");
    PathBuf::from(path)
}

// Keep a preallocated file outside SQLite so a full volume can still finalize a run.
fn ensure_storage_reserve(database_path: &Path) {
    let path = reserve_path(database_path);
    let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(&path) else {
        return;
    };
    let write_result = (|| -> std::io::Result<()> {
        file.write_all(STORAGE_RESERVE_MARKER)?;
        let block = [0_u8; 64 * 1024];
        for _ in 0..(STORAGE_RESERVE_BYTES / block.len()) {
            file.write_all(&block)?;
        }
        file.sync_all()
    })();
    if write_result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
}

fn release_storage_reserve(database_path: &Path) -> bool {
    let path = reserve_path(database_path);
    let Ok(mut file) = File::open(&path) else {
        return false;
    };
    let mut marker = vec![0_u8; STORAGE_RESERVE_MARKER.len()];
    if file.read_exact(&mut marker).is_err() || marker.as_slice() != STORAGE_RESERVE_MARKER {
        return false;
    }
    drop(file);
    fs::remove_file(path).is_ok()
}

fn connection_path(connection: &Connection) -> Option<PathBuf> {
    let raw = connection.path()?;
    if raw.is_empty() || raw == ":memory:" || raw.starts_with("file:") {
        return None;
    }
    Some(PathBuf::from(raw))
}

fn is_storage_full(error: &StorageError) -> bool {
    match error {
        StorageError::Sql(rusqlite::Error::SqliteFailure(code, _)) => {
            code.extended_code & 0xff == 13
        }
        StorageError::StorageFullRecovery(_) => true,
        _ => false,
    }
}

fn with_storage_space_recovery<F>(
    connection: &mut Connection,
    mut operation: F,
) -> Result<(), StorageError>
where
    F: FnMut(&mut Connection, bool) -> Result<(), StorageError>,
{
    match operation(connection, false) {
        Ok(()) => Ok(()),
        Err(error) if is_storage_full(&error) => {
            let path = connection_path(connection);
            if let Some(path) = &path {
                release_storage_reserve(path);
            }
            match operation(connection, true) {
                Ok(()) => {
                    if let Some(path) = &path {
                        ensure_storage_reserve(path);
                    }
                    Ok(())
                }
                Err(retry_error) => Err(StorageError::StorageFullRecovery(format!(
                    "retry after releasing the emergency reserve failed: {retry_error}; original error: {error}"
                ))),
            }
        }
        Err(error) => Err(error),
    }
}

fn prune_runs(
    transaction: &rusqlite::Transaction<'_>,
    max_runs: u64,
    current_run_id: &str,
    additional_runs: u64,
) -> Result<usize, StorageError> {
    if max_runs == 0 {
        return Ok(0);
    }
    let max_runs = i64::try_from(max_runs).map_err(|_| {
        StorageError::InvalidValue("TRACEFACT_MAX_RUNS exceeds the supported range".to_string())
    })?;
    let run_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))?;
    let projected_count =
        run_count.saturating_add(i64::try_from(additional_runs).unwrap_or(i64::MAX));
    let excess = projected_count.saturating_sub(max_runs);
    if excess == 0 {
        return Ok(0);
    }

    Ok(transaction.execute(
        "DELETE FROM runs
          WHERE run_id IN (
              SELECT r.run_id
                FROM runs r
               WHERE r.status <> 'running'
                 AND r.run_id <> ?1
                 AND NOT EXISTS (
                     SELECT 1 FROM baselines b WHERE b.source_run_id = r.run_id
                 )
                 AND r.run_id NOT IN (
                     SELECT latest.run_id
                       FROM runs latest
                      WHERE latest.status = 'completed'
                        AND latest.ended_at_ms IS NOT NULL
                      ORDER BY latest.started_at_ms DESC, latest.run_id DESC
                      LIMIT 1
                 )
                 AND r.run_id NOT IN (
                     SELECT latest.run_id
                       FROM runs latest
                      ORDER BY latest.started_at_ms DESC, latest.run_id DESC
                      LIMIT 1
                 )
               ORDER BY r.started_at_ms ASC, r.run_id ASC
               LIMIT ?2
          )",
        params![current_run_id, excess],
    )?)
}

fn cleanup_storage_pressure(
    connection: &mut Connection,
    protected_run_id: &str,
) -> Result<(), StorageError> {
    cleanup_storage_pressure_with_limit(connection, protected_run_id, configured_max_runs()?)
}

fn cleanup_storage_pressure_with_limit(
    connection: &mut Connection,
    protected_run_id: &str,
    max_runs: u64,
) -> Result<(), StorageError> {
    if max_runs == 0 {
        return Ok(());
    }

    loop {
        let transaction = connection.transaction()?;
        let run_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))?;
        let retention_target = u64::try_from(run_count).unwrap_or(0);
        let deleted = prune_runs(&transaction, retention_target, protected_run_id, 1)?;
        transaction.commit()?;
        if deleted == 0 {
            break;
        }
    }
    Ok(())
}

fn add_file_size(total: &mut u64, path: &Path) {
    if let Ok(metadata) = fs::metadata(path) {
        *total = total.saturating_add(metadata.len());
    }
}

pub fn storage_status(
    connection: &Connection,
    database_path: &Path,
) -> Result<StorageStatus, StorageError> {
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let max_pages: i64 = connection.pragma_query_value(None, "max_page_count", |row| row.get(0))?;
    let max_database_mb = configured_max_database_mb()?;
    let mut database_bytes = 0_u64;
    add_file_size(&mut database_bytes, database_path);
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        add_file_size(&mut database_bytes, Path::new(&sidecar));
    }
    let reserve = reserve_path(database_path);
    let emergency_reserve_bytes = fs::metadata(reserve).map_or(0, |metadata| metadata.len());
    let run_count: i64 = connection.query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))?;
    let protected_run_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runs r
          WHERE r.status = 'running'
             OR EXISTS (SELECT 1 FROM baselines b WHERE b.source_run_id = r.run_id)
             OR r.run_id IN (
                 SELECT latest.run_id FROM runs latest
                  WHERE latest.status = 'completed' AND latest.ended_at_ms IS NOT NULL
                  ORDER BY latest.started_at_ms DESC, latest.run_id DESC LIMIT 1
             )
             OR r.run_id IN (
                 SELECT latest.run_id FROM runs latest
                  ORDER BY latest.started_at_ms DESC, latest.run_id DESC LIMIT 1
             )",
        [],
        |row| row.get(0),
    )?;

    Ok(StorageStatus {
        database_bytes,
        database_limit_bytes: (max_database_mb > 0).then(|| {
            u64::try_from(page_size)
                .unwrap_or(4096)
                .saturating_mul(u64::try_from(max_pages).unwrap_or(0))
        }),
        emergency_reserve_bytes,
        run_count: u64::try_from(run_count).unwrap_or(0),
        protected_run_count: u64::try_from(protected_run_count).unwrap_or(0),
        max_runs: configured_max_runs()?,
    })
}

pub fn initialize(path: &str) -> Result<Connection, StorageError> {
    let mut connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    // Enable referential integrity before beginning migrations.
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    apply_migrations(&mut connection)?;
    configure_database_limit(&connection)?;
    Ok(connection)
}

/// Applies ordered schema migrations using SQLite's PRAGMA user_version.
/// Each migration and the corresponding version update are committed atomically.
fn apply_migrations(connection: &mut Connection) -> Result<(), StorageError> {
    let mut current_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if current_version > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::InvalidValue(format!(
            "database schema version {current_version} is newer than this TraceFact build supports (maximum {CURRENT_SCHEMA_VERSION})"
        )));
    }

    if current_version < 1 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(include_str!("../../schema/migrations/0001_initial.sql"))?;
        // Earlier TraceFact builds did not consistently track the SQLite schema version.
        // This migration also upgrades the legacy runs table when it lacks status.
        migrate_run_status(&transaction)?;
        transaction.execute_batch("PRAGMA user_version = 1;")?;
        transaction.commit()?;
        current_version = 1;
    }

    if current_version < 2 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(include_str!(
            "../../schema/migrations/0002_named_baselines.sql"
        ))?;
        transaction.execute_batch("PRAGMA user_version = 2;")?;
        transaction.commit()?;
    }

    Ok(())
}

/// Adds lifecycle status to databases created by earlier TraceFact versions.
/// Legacy rows are classified from their end timestamp rather than being
/// mislabeled as healthy completed runs.
fn migrate_run_status(connection: &Connection) -> Result<(), StorageError> {
    let mut statement = connection.prepare("PRAGMA table_info(runs)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_status = false;
    for column in columns {
        if column? == "status" {
            has_status = true;
            break;
        }
    }
    drop(statement);

    if !has_status {
        connection.execute_batch(
            "ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'interrupted'
             CHECK (status IN ('running', 'completed', 'interrupted', 'failed'));
             UPDATE runs SET status = CASE
                 WHEN ended_at_ms IS NULL THEN 'interrupted'
                 ELSE 'completed'
             END;",
        )?;
    }

    Ok(())
}

pub fn begin_run(
    connection: &mut Connection,
    snapshot: &RuntimeSnapshot,
    passport: &RuntimePassport,
) -> Result<(), StorageError> {
    begin_run_with_events(connection, snapshot, passport, &[])
}

/// Creates a run, its initial passport, and bootstrap events in one transaction.
/// A failed bootstrap therefore cannot leave a partially initialized run behind.
pub fn begin_run_with_events(
    connection: &mut Connection,
    snapshot: &RuntimeSnapshot,
    passport: &RuntimePassport,
    initial_events: &[RuntimeEvent],
) -> Result<(), StorageError> {
    with_storage_space_recovery(connection, |connection, retry_after_full| {
        if retry_after_full {
            cleanup_storage_pressure(connection, &snapshot.snapshot_id)?;
        }
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO runs (run_id, application, started_at_ms, ended_at_ms, schema_version, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &snapshot.snapshot_id,
                &snapshot.application,
                snapshot.started_at_ms,
                snapshot.ended_at_ms,
                &snapshot.schema_version,
                if snapshot.ended_at_ms.is_some() {
                    "completed"
                } else {
                    "running"
                },
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

        for event in initial_events {
            insert_event(&transaction, &snapshot.snapshot_id, event)?;
        }
        prune_runs(
            &transaction,
            configured_max_runs()?,
            &snapshot.snapshot_id,
            0,
        )?;
        transaction.commit()?;
        Ok(())
    })
}

pub fn append_event(
    connection: &mut Connection,
    run_id: &str,
    event: &RuntimeEvent,
) -> Result<(), StorageError> {
    with_storage_space_recovery(connection, |connection, retry_after_full| {
        if retry_after_full {
            cleanup_storage_pressure(connection, run_id)?;
        }
        let transaction = connection.transaction()?;
        insert_event(&transaction, run_id, event)?;
        transaction.commit()?;
        Ok(())
    })
}

pub fn finish_run(
    connection: &mut Connection,
    run_id: &str,
    ended_at_ms: i64,
    passport: &RuntimePassport,
) -> Result<(), StorageError> {
    finish_run_with_status(connection, run_id, ended_at_ms, passport, "completed")
}

pub fn finish_run_with_status(
    connection: &mut Connection,
    run_id: &str,
    ended_at_ms: i64,
    passport: &RuntimePassport,
    status: &str,
) -> Result<(), StorageError> {
    if !matches!(status, "completed" | "interrupted" | "failed") {
        return Err(StorageError::InvalidValue(format!(
            "unsupported terminal run status: {status}"
        )));
    }

    let result = with_storage_space_recovery(connection, |connection, retry_after_full| {
        if retry_after_full {
            cleanup_storage_pressure(connection, run_id)?;
        }
        let transaction = connection.transaction()?;
        let updated = transaction.execute(
            "UPDATE runs SET ended_at_ms = ?1, status = ?2 WHERE run_id = ?3",
            params![ended_at_ms, status, run_id],
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
    });

    if let Err(error) = result {
        if is_storage_full(&error) {
            if let Err(fallback_error) =
                mark_run_failed_without_passport(connection, run_id, ended_at_ms)
            {
                return Err(StorageError::InvalidValue(format!(
                    "storage ran out of space while finalizing run {run_id}; the final Passport was not saved, and the status-only fallback also failed, so the run may remain running: {fallback_error}; original error: {error}"
                )));
            }
            if let Some(path) = connection_path(connection) {
                ensure_storage_reserve(&path);
            }
            return Err(StorageError::InvalidValue(format!(
                "storage ran out of space while finalizing run {run_id}; the run was marked failed, but its final Runtime Passport was not updated: {error}"
            )));
        }
        return Err(error);
    }
    if let Some(path) = connection_path(connection) {
        ensure_storage_reserve(&path);
    }
    Ok(())
}

fn mark_run_failed_without_passport(
    connection: &mut Connection,
    run_id: &str,
    ended_at_ms: i64,
) -> Result<(), StorageError> {
    let transaction = connection.transaction()?;
    let updated = transaction.execute(
        "UPDATE runs SET ended_at_ms = ?1, status = 'failed' WHERE run_id = ?2",
        params![ended_at_ms, run_id],
    )?;
    if updated != 1 {
        return Err(StorageError::InvalidValue(format!(
            "run {run_id} could not be marked failed after storage exhaustion"
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
    with_storage_space_recovery(connection, |connection, retry_after_full| {
        if retry_after_full {
            cleanup_storage_pressure(connection, &snapshot.snapshot_id)?;
        }
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO runs (run_id, application, started_at_ms, ended_at_ms, schema_version, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &snapshot.snapshot_id,
                &snapshot.application,
                snapshot.started_at_ms,
                snapshot.ended_at_ms,
                &snapshot.schema_version,
                if snapshot.ended_at_ms.is_some() {
                    "completed"
                } else {
                    "running"
                },
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
        prune_runs(
            &transaction,
            configured_max_runs()?,
            &snapshot.snapshot_id,
            0,
        )?;
        transaction.commit()?;
        Ok(())
    })
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

/// Reads run metadata, its Passport, and its events from one SQLite snapshot.
pub fn get_run(connection: &Connection, run_id: &str) -> Result<Option<StoredRun>, StorageError> {
    let transaction = connection.unchecked_transaction()?;
    let run = transaction
        .query_row(
            "SELECT run_id, application, started_at_ms, ended_at_ms, schema_version, status FROM runs WHERE run_id = ?1",
            params![run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;

    let Some((run_id, application, started_at_ms, ended_at_ms, schema_version, status)) = run
    else {
        transaction.commit()?;
        return Ok(None);
    };

    let passport_json: String = transaction.query_row(
        "SELECT passport_json FROM passports WHERE run_id = ?1 ORDER BY generated_at_ms DESC LIMIT 1",
        params![run_id],
        |row| row.get(0),
    )?;
    let passport: RuntimePassport = serde_json::from_str(&passport_json)?;

    let mut statement = transaction.prepare(
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
    drop(statement);
    transaction.commit()?;

    Ok(Some(StoredRun {
        run_id,
        application,
        started_at_ms,
        ended_at_ms,
        status,
        schema_version,
        passport,
        events,
    }))
}

/// Validates the user-facing baseline name before storage or export.
pub fn validate_baseline_name(name: &str) -> Result<(), StorageError> {
    let length = name.chars().count();
    if name.trim().is_empty() {
        return Err(StorageError::InvalidValue(
            "baseline name must not be empty".to_string(),
        ));
    }
    if name.trim() != name {
        return Err(StorageError::InvalidValue(
            "baseline name must not start or end with whitespace".to_string(),
        ));
    }
    if length > 120 {
        return Err(StorageError::InvalidValue(
            "baseline name must be 120 characters or fewer".to_string(),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(StorageError::InvalidValue(
            "baseline name must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn baseline_name_key(name: &str) -> String {
    // SQLite's built-in NOCASE collation folds ASCII only. Store a Unicode-lowercase
    // key so case variants in non-ASCII names are also treated as the same baseline.
    name.to_lowercase()
}

pub fn save_baseline(
    connection: &mut Connection,
    baseline: &RuntimePassportBaseline,
) -> Result<(), StorageError> {
    validate_baseline_name(&baseline.name)?;
    if baseline.baseline_schema_version != "1.0" {
        return Err(StorageError::InvalidValue(format!(
            "unsupported baseline schema version '{}'",
            baseline.baseline_schema_version
        )));
    }

    let name_key = baseline_name_key(&baseline.name);
    with_storage_space_recovery(connection, |connection, retry_after_full| {
        if retry_after_full {
            cleanup_storage_pressure(connection, &baseline.source_run_id)?;
        }
        let transaction = connection.transaction()?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM baselines WHERE name_key = ?1)",
            params![&name_key],
            |row| row.get(0),
        )?;
        if exists {
            return Err(StorageError::InvalidValue(format!(
                "baseline '{}' already exists; existing baselines are not overwritten",
                baseline.name
            )));
        }

        transaction.execute(
            "INSERT INTO baselines (
                name, name_key, created_at_ms, application, source_run_id, baseline_schema_version,
                passport_json, scope_json, coverage_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &baseline.name,
                &name_key,
                baseline.created_at_ms,
                &baseline.application,
                &baseline.source_run_id,
                &baseline.baseline_schema_version,
                serde_json::to_string(&baseline.passport)?,
                serde_json::to_string(&baseline.scope)?,
                serde_json::to_string(&baseline.coverage)?,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    })
}

pub fn get_baseline(
    connection: &Connection,
    name: &str,
) -> Result<Option<RuntimePassportBaseline>, StorageError> {
    let stored = connection
        .query_row(
            "SELECT name, created_at_ms, application, source_run_id, baseline_schema_version,
                    passport_json, scope_json, coverage_json
               FROM baselines WHERE name_key = ?1",
            params![baseline_name_key(name)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()?;

    let Some((
        name,
        created_at_ms,
        application,
        source_run_id,
        baseline_schema_version,
        passport_json,
        scope_json,
        coverage_json,
    )) = stored
    else {
        return Ok(None);
    };

    Ok(Some(RuntimePassportBaseline {
        baseline_schema_version,
        name,
        created_at_ms,
        source_run_id,
        application,
        passport: serde_json::from_str(&passport_json)?,
        scope: serde_json::from_str::<EvidenceScope>(&scope_json)?,
        coverage: serde_json::from_str::<EvidenceCoverage>(&coverage_json)?,
    }))
}

pub fn list_baselines(
    connection: &Connection,
    limit: u32,
) -> Result<Vec<BaselineSummary>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT name, application, created_at_ms, source_run_id, coverage_json
           FROM baselines
          ORDER BY created_at_ms DESC, name COLLATE NOCASE ASC
          LIMIT ?1",
    )?;
    let rows = statement.query_map(params![limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;

    let mut baselines = Vec::new();
    for row in rows {
        let (name, application, created_at_ms, source_run_id, coverage_json) = row?;
        let coverage: EvidenceCoverage = serde_json::from_str(&coverage_json)?;
        baselines.push(BaselineSummary {
            name,
            application,
            created_at_ms,
            source_run_id,
            event_count: coverage.event_count,
            collector_sources: coverage.collector_sources,
        });
    }
    Ok(baselines)
}

pub fn latest_completed_run_id(connection: &Connection) -> Result<Option<String>, StorageError> {
    connection
        .query_row(
            "SELECT run_id FROM runs
              WHERE status = 'completed' AND ended_at_ms IS NOT NULL
              ORDER BY started_at_ms DESC, run_id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(StorageError::from)
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
                r.status,
                COUNT(e.event_id) AS event_count
           FROM runs r
           LEFT JOIN events e ON e.run_id = r.run_id
          GROUP BY r.run_id, r.application, r.started_at_ms, r.ended_at_ms, r.status
          ORDER BY r.started_at_ms DESC
          LIMIT ?1",
    )?;

    let rows = statement.query_map(params![limit], |row| {
        Ok(RunSummary {
            run_id: row.get(0)?,
            application: row.get(1)?,
            started_at_ms: row.get(2)?,
            ended_at_ms: row.get(3)?,
            status: row.get(4)?,
            event_count: row.get(5)?,
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
    fn retention_prunes_old_runs_and_preserves_latest_and_baseline_runs() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        connection.execute_batch(
            "INSERT INTO runs VALUES
                ('old-run', 'app.exe', 100, 150, '0.1', 'completed'),
                ('baseline-run', 'app.exe', 200, 250, '0.1', 'completed'),
                ('latest-completed', 'app.exe', 300, 350, '0.1', 'completed'),
                ('latest-run', 'app.exe', 400, 450, '0.1', 'interrupted');
             INSERT INTO events VALUES
                ('old-event', 'old-run', 120, 'process_observed', 42, 'app.exe', 'process', 'app.exe', '{}', 'test', 'SystemMetadata');
             INSERT INTO passports VALUES
                ('old-passport', 'old-run', 150, '{}');
             INSERT INTO baselines VALUES
                ('stable', 'stable', 260, 'app.exe', 'baseline-run', '1.0', '{}', '{}', '{}');",
        ).expect("test records should be inserted");

        let transaction = connection.transaction().expect("transaction should start");
        let deleted = prune_runs(&transaction, 2, "new-run", 1).expect("retention should succeed");
        transaction.commit().expect("retention should commit");

        assert_eq!(deleted, 1);
        for (run_id, expected) in [
            ("old-run", false),
            ("baseline-run", true),
            ("latest-completed", true),
            ("latest-run", true),
        ] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = ?1)",
                    [run_id],
                    |row| row.get(0),
                )
                .expect("run existence should be readable");
            assert_eq!(exists, expected, "unexpected retention result for {run_id}");
        }
        let orphan_events: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id = 'old-event'",
                [],
                |row| row.get(0),
            )
            .expect("event count should be readable");
        let orphan_passports: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM passports WHERE passport_id = 'old-passport'",
                [],
                |row| row.get(0),
            )
            .expect("passport count should be readable");
        assert_eq!(orphan_events, 0);
        assert_eq!(orphan_passports, 0);
    }

    #[test]
    fn retention_preserves_active_run_while_pruning_old_history() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        connection
            .execute_batch(
                "INSERT INTO runs VALUES
                ('old-run', 'app.exe', 100, 150, '0.1', 'completed'),
                ('latest-run', 'app.exe', 200, 250, '0.1', 'completed'),
                ('active-run', 'app.exe', 300, NULL, '0.1', 'running');",
            )
            .expect("test records should be inserted");

        let transaction = connection.transaction().expect("transaction should start");
        let deleted = prune_runs(&transaction, 1, "new-run", 1).expect("retention should succeed");
        transaction.commit().expect("retention should commit");

        assert_eq!(deleted, 1);
        let remaining: i64 = connection
            .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
            .expect("run count should be readable");
        assert_eq!(remaining, 2);
        let active_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = 'active-run')",
                [],
                |row| row.get(0),
            )
            .expect("active run should remain readable");
        assert!(active_exists);
    }

    #[test]
    fn retention_allows_protected_runs_to_exceed_the_configured_target() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        connection.execute_batch(
            "INSERT INTO runs VALUES
                ('old-run', 'app.exe', 50, 75, '0.1', 'completed'),
                ('pinned-one', 'app.exe', 100, 150, '0.1', 'completed'),
                ('pinned-two', 'app.exe', 200, 250, '0.1', 'completed'),
                ('active-run', 'app.exe', 300, NULL, '0.1', 'running');
             INSERT INTO baselines VALUES
                ('stable-one', 'stable-one', 160, 'app.exe', 'pinned-one', '1.0', '{}', '{}', '{}'),
                ('stable-two', 'stable-two', 260, 'app.exe', 'pinned-two', '1.0', '{}', '{}', '{}');",
        ).expect("protected runs should be inserted");

        let transaction = connection.transaction().expect("transaction should start");
        let deleted = prune_runs(&transaction, 1, "new-run", 1).expect("retention should succeed");
        transaction.commit().expect("retention should commit");

        assert_eq!(deleted, 1);
        let old_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = 'old-run')",
                [],
                |row| row.get(0),
            )
            .expect("old run status should be readable");
        let pinned_one_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = 'pinned-one')",
                [],
                |row| row.get(0),
            )
            .expect("first baseline source should be readable");
        let pinned_two_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = 'pinned-two')",
                [],
                |row| row.get(0),
            )
            .expect("second baseline source should be readable");
        let active_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = 'active-run')",
                [],
                |row| row.get(0),
            )
            .expect("active run status should be readable");
        assert!(!old_exists);
        assert!(pinned_one_exists);
        assert!(pinned_two_exists);
        assert!(active_exists);
    }

    #[test]
    fn storage_pressure_cleanup_preserves_baselines_and_latest_runs() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        connection
            .execute_batch(
                "INSERT INTO runs VALUES
                ('old-run', 'app.exe', 100, 150, '0.1', 'completed'),
                ('baseline-run', 'app.exe', 200, 250, '0.1', 'completed'),
                ('latest-completed', 'app.exe', 300, 350, '0.1', 'completed'),
                ('active-run', 'app.exe', 400, NULL, '0.1', 'running');
             INSERT INTO baselines VALUES
                ('stable', 'stable', 260, 'app.exe', 'baseline-run', '1.0', '{}', '{}', '{}');",
            )
            .expect("test records should be inserted");

        cleanup_storage_pressure_with_limit(&mut connection, "active-run", 500)
            .expect("storage-pressure cleanup should succeed");

        for (run_id, expected) in [
            ("old-run", false),
            ("baseline-run", true),
            ("latest-completed", true),
            ("active-run", true),
        ] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = ?1)",
                    [run_id],
                    |row| row.get(0),
                )
                .expect("run existence should be readable");
            assert_eq!(exists, expected, "unexpected pressure cleanup for {run_id}");
        }
    }

    #[test]
    fn zero_run_limit_disables_emergency_history_cleanup() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        connection
            .execute_batch(
                "INSERT INTO runs VALUES
                    ('old-run', 'app.exe', 100, 150, '0.1', 'completed'),
                    ('latest-run', 'app.exe', 200, 250, '0.1', 'completed');",
            )
            .expect("test runs should be inserted");

        cleanup_storage_pressure_with_limit(&mut connection, "latest-run", 0)
            .expect("disabled emergency cleanup should be a no-op");
        assert!(connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = 'old-run')",
                [],
                |row| row.get::<_, bool>(0),
            )
            .expect("old run should remain readable"));
    }

    #[test]
    fn emergency_reserve_is_owned_and_can_be_released() {
        let database_path = std::env::temp_dir().join(format!(
            "tracefact-reserve-test-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        ));
        let reserve = reserve_path(&database_path);

        ensure_storage_reserve(&database_path);
        let size = fs::metadata(&reserve)
            .expect("reserve file should exist")
            .len();
        assert!(size >= (STORAGE_RESERVE_BYTES + STORAGE_RESERVE_MARKER.len()) as u64);
        assert!(release_storage_reserve(&database_path));
        assert!(!reserve.exists());
    }

    #[test]
    fn failed_storage_retry_keeps_the_storage_full_error_class() {
        let mut connection = Connection::open_in_memory().expect("database should open");
        connection
            .execute_batch("CREATE TABLE pressure (payload BLOB NOT NULL);")
            .expect("pressure table should be created");
        let page_count: i64 = connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .expect("page count should be readable");
        connection
            .pragma_update(None, "max_page_count", page_count)
            .expect("page limit should be set to the current size");

        let error = with_storage_space_recovery(&mut connection, |connection, retry| {
            if retry {
                return Err(StorageError::InvalidValue("retry blocked".to_string()));
            }
            connection.execute(
                "INSERT INTO pressure (payload) VALUES (?1)",
                params![vec![0_u8; 32 * 1024]],
            )?;
            Ok(())
        })
        .expect_err("the retry should report its error");

        assert!(is_storage_full(&error));
        assert!(error.to_string().contains("retry blocked"));
    }

    #[test]
    fn emergency_finalization_marks_run_failed_without_replacing_old_passport() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        connection.execute(
            "INSERT INTO runs VALUES ('reserve-fallback', 'app.exe', 100, NULL, '0.1', 'running')",
            [],
        ).expect("run should be inserted");
        connection.execute(
            "INSERT INTO passports VALUES ('reserve-fallback-passport', 'reserve-fallback', 100, '{\"state\":\"initial\"}')",
            [],
        ).expect("initial passport should be inserted");

        mark_run_failed_without_passport(&mut connection, "reserve-fallback", 200)
            .expect("run should be marked failed");
        let status: String = connection
            .query_row(
                "SELECT status FROM runs WHERE run_id = 'reserve-fallback'",
                [],
                |row| row.get(0),
            )
            .expect("status should be readable");
        let passport_json: String = connection
            .query_row(
                "SELECT passport_json FROM passports WHERE run_id = 'reserve-fallback'",
                [],
                |row| row.get(0),
            )
            .expect("passport should be readable");
        assert_eq!(status, "failed");
        assert_eq!(passport_json, r#"{"state":"initial"}"#);
    }

    #[test]
    fn initialize_applies_versioned_schema_migration() {
        let mut connection = Connection::open_in_memory().expect("database should open");
        apply_migrations(&mut connection).expect("schema migration should succeed");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version should be readable");
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        let baseline_table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'baselines'",
                [],
                |row| row.get(0),
            )
            .expect("baseline table should exist");
        assert_eq!(baseline_table_count, 1);

        // Migration is idempotent after the version has advanced.
        apply_migrations(&mut connection).expect("migration should be safe to rerun");
        let version_again: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version should remain readable");
        assert_eq!(version_again, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn versioned_migration_upgrades_legacy_runs_table() {
        let mut connection = Connection::open_in_memory().expect("database should open");
        connection
            .execute_batch(
                "CREATE TABLE runs (
                 run_id TEXT PRIMARY KEY,
                 application TEXT NOT NULL,
                 started_at_ms INTEGER NOT NULL,
                 ended_at_ms INTEGER,
                 schema_version TEXT NOT NULL
             );
             INSERT INTO runs VALUES ('legacy-complete', 'demo.exe', 1, 2, '0.1');
             INSERT INTO runs VALUES ('legacy-open', 'demo.exe', 3, NULL, '0.1');",
            )
            .expect("legacy schema should be created");

        apply_migrations(&mut connection).expect("legacy database should migrate");
        let complete: String = connection
            .query_row(
                "SELECT status FROM runs WHERE run_id = 'legacy-complete'",
                [],
                |row| row.get(0),
            )
            .expect("legacy completed status should be readable");
        let open: String = connection
            .query_row(
                "SELECT status FROM runs WHERE run_id = 'legacy-open'",
                [],
                |row| row.get(0),
            )
            .expect("legacy open status should be readable");
        assert_eq!(complete, "completed");
        assert_eq!(open, "interrupted");

        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version should be readable");
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn newer_schema_version_is_rejected() {
        let mut connection = Connection::open_in_memory().expect("database should open");
        connection
            .execute_batch("PRAGMA user_version = 999;")
            .unwrap();
        let error = apply_migrations(&mut connection).expect_err("newer schema must be rejected");
        assert!(error
            .to_string()
            .contains("newer than this TraceFact build supports"));
    }

    #[test]
    fn legacy_run_status_migration_marks_open_runs_interrupted() {
        let connection = Connection::open_in_memory().expect("database should initialize");
        connection
            .execute_batch(
                "CREATE TABLE runs (
                 run_id TEXT PRIMARY KEY,
                 application TEXT NOT NULL,
                 started_at_ms INTEGER NOT NULL,
                 ended_at_ms INTEGER,
                 schema_version TEXT NOT NULL
             );
             INSERT INTO runs VALUES ('old-complete', 'demo.exe', 1, 2, '0.1');
             INSERT INTO runs VALUES ('old-open', 'demo.exe', 3, NULL, '0.1');",
            )
            .expect("legacy schema should be created");

        migrate_run_status(&connection).expect("status migration should succeed");
        let completed: String = connection
            .query_row(
                "SELECT status FROM runs WHERE run_id = 'old-complete'",
                [],
                |row| row.get(0),
            )
            .expect("completed legacy status should be readable");
        let interrupted: String = connection
            .query_row(
                "SELECT status FROM runs WHERE run_id = 'old-open'",
                [],
                |row| row.get(0),
            )
            .expect("open legacy status should be readable");

        assert_eq!(completed, "completed");
        assert_eq!(interrupted, "interrupted");
        migrate_run_status(&connection).expect("running the migration again should be safe");
    }

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
        assert_eq!(runs[0].status, "completed");
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
    fn missing_run_lookup_closes_its_read_transaction() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        assert!(get_run(&connection, "missing-run")
            .expect("missing run lookup should succeed")
            .is_none());

        let transaction = connection
            .transaction()
            .expect("a new transaction should start after the lookup");
        transaction
            .execute(
                "INSERT INTO runs VALUES ('after-missing-lookup', 'app.exe', 100, 150, '0.1', 'completed')",
                [],
            )
            .expect("run should be inserted after lookup");
        transaction.commit().expect("transaction should commit");
    }

    #[test]
    fn begin_run_with_events_saves_bootstrap_events_atomically() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        let snapshot = RuntimeSnapshot {
            schema_version: "0.1".into(),
            snapshot_id: "watch-bootstrap-test".into(),
            application: "demo.exe".into(),
            started_at_ms: 1000,
            ended_at_ms: None,
            events: vec![],
        };
        let passport = RuntimePassport {
            schema_version: "0.1".into(),
            passport_id: "passport-watch-bootstrap-test".into(),
            generated_at_ms: 1000,
            application: "demo.exe".into(),
            observations: Default::default(),
            changes: vec![],
        };
        let event = RuntimeEvent {
            id: "watch-bootstrap-event-1".into(),
            timestamp_ms: 1000,
            event_type: EventType::ProcessObserved,
            process: ProcessIdentity {
                pid: 42,
                executable: "demo.exe".into(),
                command_line: None,
                parent_pid: Some(1),
            },
            subject: "process".into(),
            target: Some("demo.exe".into()),
            metadata: serde_json::json!({"observation": "bootstrap"}),
            source: "test".into(),
            sensitivity: Sensitivity::SystemMetadata,
        };

        begin_run_with_events(&mut connection, &snapshot, &passport, &[event])
            .expect("run and bootstrap event should be saved");

        let stored = get_run(&connection, "watch-bootstrap-test")
            .expect("run should be readable")
            .expect("run should exist");
        assert_eq!(stored.events.len(), 1);
        assert_eq!(stored.events[0].event_id, "watch-bootstrap-event-1");
        assert_eq!(stored.ended_at_ms, None);
    }

    #[test]
    fn begin_run_with_events_rolls_back_if_bootstrap_event_fails() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        let snapshot = RuntimeSnapshot {
            schema_version: "0.1".into(),
            snapshot_id: "watch-bootstrap-rollback-test".into(),
            application: "demo.exe".into(),
            started_at_ms: 1000,
            ended_at_ms: None,
            events: vec![],
        };
        let passport = RuntimePassport {
            schema_version: "0.1".into(),
            passport_id: "passport-watch-bootstrap-rollback-test".into(),
            generated_at_ms: 1000,
            application: "demo.exe".into(),
            observations: Default::default(),
            changes: vec![],
        };
        let event = RuntimeEvent {
            id: "duplicate-bootstrap-event".into(),
            timestamp_ms: 1000,
            event_type: EventType::ProcessObserved,
            process: ProcessIdentity {
                pid: 42,
                executable: "demo.exe".into(),
                command_line: None,
                parent_pid: Some(1),
            },
            subject: "process".into(),
            target: Some("demo.exe".into()),
            metadata: serde_json::json!({"observation": "bootstrap"}),
            source: "test".into(),
            sensitivity: Sensitivity::SystemMetadata,
        };

        let result = begin_run_with_events(
            &mut connection,
            &snapshot,
            &passport,
            &[event.clone(), event],
        );
        assert!(result.is_err());
        assert!(get_run(&connection, "watch-bootstrap-rollback-test")
            .expect("database should remain readable")
            .is_none());
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
        assert_eq!(stored.status, "completed");
        assert_eq!(stored.events.len(), 1);
        assert_eq!(stored.events[0].event_id, "watch-event-1");
        assert_eq!(stored.passport.generated_at_ms, 2000);
        assert_eq!(stored.passport.observations.processes, vec!["child.exe"]);
    }

    #[test]
    fn finish_run_with_status_preserves_failure_state() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        let snapshot = RuntimeSnapshot {
            schema_version: "0.1".into(),
            snapshot_id: "watch-failed-test".into(),
            application: "demo.exe".into(),
            started_at_ms: 1000,
            ended_at_ms: None,
            events: vec![],
        };
        let initial_passport = RuntimePassport {
            schema_version: "0.1".into(),
            passport_id: "passport-watch-failed-test".into(),
            generated_at_ms: 1000,
            application: "demo.exe".into(),
            observations: Default::default(),
            changes: vec![],
        };
        begin_run(&mut connection, &snapshot, &initial_passport).expect("run should be created");

        let final_passport = RuntimePassport {
            generated_at_ms: 1500,
            ..initial_passport
        };
        finish_run_with_status(
            &mut connection,
            "watch-failed-test",
            1500,
            &final_passport,
            "failed",
        )
        .expect("failed run should be finalized");

        let stored = get_run(&connection, "watch-failed-test")
            .expect("run should be readable")
            .expect("run should exist");
        assert_eq!(stored.status, "failed");
        assert_eq!(stored.ended_at_ms, Some(1500));
    }

    #[test]
    fn version_one_database_receives_named_baseline_migration() {
        let mut connection = Connection::open_in_memory().expect("database should open");
        connection
            .execute_batch(include_str!("../../schema/migrations/0001_initial.sql"))
            .expect("version one schema should be created");
        connection
            .execute_batch(
                "INSERT INTO runs VALUES ('pre-baseline-run', 'app.exe', 100, 200, '0.1', 'completed');
                 INSERT INTO events VALUES ('pre-baseline-event', 'pre-baseline-run', 150, 'process_observed', 42, 'app.exe', 'process', 'app.exe', '{}', 'test-collector', 'SystemMetadata');
                 INSERT INTO passports VALUES ('pre-baseline-passport', 'pre-baseline-run', 200, '{\"schema_version\":\"0.1\",\"passport_id\":\"pre-baseline-passport\",\"generated_at_ms\":200,\"application\":\"app.exe\",\"observations\":{\"processes\":[],\"network_targets\":[],\"files\":[],\"libraries\":[]},\"changes\":[]}');
                 PRAGMA user_version = 1;",
            )
            .expect("version one data should be created");

        apply_migrations(&mut connection).expect("version two migration should succeed");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version should be readable");
        assert_eq!(version, 2);
        let baseline_table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'baselines'",
                [],
                |row| row.get(0),
            )
            .expect("baseline table should be readable");
        assert_eq!(baseline_table_count, 1);
        let preserved_runs: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM runs WHERE run_id = 'pre-baseline-run'",
                [],
                |row| row.get(0),
            )
            .expect("existing run should remain available");
        let preserved_events: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id = 'pre-baseline-event'",
                [],
                |row| row.get(0),
            )
            .expect("existing event should remain available");
        let preserved_passports: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM passports WHERE passport_id = 'pre-baseline-passport'",
                [],
                |row| row.get(0),
            )
            .expect("existing Passport should remain available");
        assert_eq!(preserved_runs, 1);
        assert_eq!(preserved_events, 1);
        assert_eq!(preserved_passports, 1);
    }

    #[test]
    fn named_baseline_round_trips_and_rejects_duplicate_names() {
        let mut connection = initialize(":memory:").expect("database should initialize");
        connection.execute(
            "INSERT INTO runs (run_id, application, started_at_ms, ended_at_ms, schema_version, status)
             VALUES ('source-run', 'demo.exe', 100, 200, '0.1', 'completed')",
            [],
        ).expect("source run should exist");
        let baseline = RuntimePassportBaseline {
            baseline_schema_version: "1.0".to_string(),
            name: "desktop-app".to_string(),
            created_at_ms: 300,
            source_run_id: "source-run".to_string(),
            application: "demo.exe".to_string(),
            passport: RuntimePassport {
                schema_version: "0.1".to_string(),
                passport_id: "passport-source-run".to_string(),
                generated_at_ms: 200,
                application: "demo.exe".to_string(),
                observations: Default::default(),
                changes: vec![],
            },
            scope: EvidenceScope {
                platform: "windows".to_string(),
                kind: "selected_process_tree_watch".to_string(),
                root_pid: Some(42),
                includes_descendants: true,
            },
            coverage: EvidenceCoverage {
                event_count: 2,
                event_counts_by_type: std::collections::BTreeMap::from([(
                    "process_observed".to_string(),
                    2,
                )]),
                collector_sources: vec!["windows_process_watch".to_string()],
                limitations: vec!["Not all runtime behavior is observable.".to_string()],
            },
        };

        save_baseline(&mut connection, &baseline).expect("baseline should save");
        let stored = get_baseline(&connection, "DESKTOP-APP")
            .expect("baseline should be read")
            .expect("baseline should exist case-insensitively");
        assert_eq!(stored.name, "desktop-app");
        assert_eq!(stored.source_run_id, "source-run");
        assert_eq!(stored.coverage.event_count, 2);

        let mut case_variant = baseline.clone();
        case_variant.name = "DESKTOP-APP".to_string();
        let error = save_baseline(&mut connection, &case_variant)
            .expect_err("case-insensitive duplicate baseline must not overwrite");
        assert!(error.to_string().contains("already exists"));

        let summaries = list_baselines(&connection, 20).expect("baselines should list");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "desktop-app");
        assert_eq!(summaries[0].event_count, 2);

        // SQLite NOCASE does not fold non-ASCII letters; the stored key must.
        let mut unicode_baseline = baseline.clone();
        unicode_baseline.name = "CAF\u{00C9} desktop".to_string();
        save_baseline(&mut connection, &unicode_baseline)
            .expect("Unicode baseline name should save");
        let retrieved = get_baseline(&connection, "caf\u{00E9} desktop")
            .expect("Unicode baseline lookup should work")
            .expect("Unicode baseline should be found ignoring case");
        assert_eq!(retrieved.name, "CAF\u{00C9} desktop");

        unicode_baseline.name = "caf\u{00E9} desktop".to_string();
        let error = save_baseline(&mut connection, &unicode_baseline)
            .expect_err("Unicode case variants must not create duplicates");
        assert!(error.to_string().contains("already exists"));
    }

    #[test]
    fn baseline_names_are_validated() {
        assert!(validate_baseline_name("stable baseline").is_ok());
        assert!(validate_baseline_name("").is_err());
        assert!(validate_baseline_name(" leading").is_err());
        assert!(validate_baseline_name("trailing ").is_err());
        assert!(validate_baseline_name(&"x".repeat(121)).is_err());
    }

    #[test]
    fn latest_completed_run_skips_a_newer_running_run() {
        let connection = initialize(":memory:").expect("database should initialize");
        connection.execute_batch(
            "INSERT INTO runs VALUES ('completed-old', 'app.exe', 100, 150, '0.1', 'completed');
             INSERT INTO runs VALUES ('running-new', 'app.exe', 200, NULL, '0.1', 'running');",
        ).expect("test runs should be inserted");

        assert_eq!(
            latest_completed_run_id(&connection).expect("latest completed run should be found"),
            Some("completed-old".to_string())
        );
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
