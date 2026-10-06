pub mod demo;

use crate::model::{RuntimeEvent, RuntimeSnapshot};

pub trait Collector {
    fn name(&self) -> &'static str;
    fn collect(&mut self) -> Vec<RuntimeEvent>;
}

pub fn snapshot<C: Collector>(
    collector: &mut C,
    application: String,
    started_at_ms: i64,
) -> RuntimeSnapshot {
    let events = collector.collect();
    RuntimeSnapshot {
        schema_version: "0.1".to_string(),
        snapshot_id: format!("snap-{}", started_at_ms),
        application,
        started_at_ms,
        ended_at_ms: Some(started_at_ms),
        events,
    }
}
