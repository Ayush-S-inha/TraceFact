pub mod demo;
#[cfg(windows)]
pub mod windows_process;

use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::model::{RuntimeEvent, RuntimeSnapshot};

#[derive(Debug, Clone)]
pub struct CollectorError {
    pub collector: &'static str,
    pub message: String,
}

impl CollectorError {
    pub fn new(collector: &'static str, message: impl Into<String>) -> Self {
        Self {
            collector,
            message: message.into(),
        }
    }
}

impl Display for CollectorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.collector, self.message)
    }
}

impl Error for CollectorError {}

pub trait Collector {
    fn name(&self) -> &'static str;
    fn collect(&mut self) -> Result<Vec<RuntimeEvent>, CollectorError>;
}

pub fn snapshot<C: Collector>(
    collector: &mut C,
    application: String,
    started_at_ms: i64,
) -> Result<RuntimeSnapshot, CollectorError> {
    let events = collector.collect()?;
    Ok(RuntimeSnapshot {
        schema_version: "0.1".to_string(),
        snapshot_id: format!("snap-{started_at_ms}"),
        application,
        started_at_ms,
        ended_at_ms: Some(started_at_ms),
        events,
    })
}
