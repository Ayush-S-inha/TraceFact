use crate::collectors::Collector;
use crate::model::{
    EventType, PassportObservations, ProcessIdentity, RuntimeEvent, RuntimePassport, Sensitivity,
};

pub struct DemoCollector;

impl Collector for DemoCollector {
    fn name(&self) -> &'static str {
        "demo"
    }

    fn collect(&mut self) -> Vec<RuntimeEvent> {
        let process = ProcessIdentity {
            pid: 4812,
            executable: "checkout-service".into(),
            command_line: Some("./checkout-service".into()),
            parent_pid: None,
        };

        vec![
            RuntimeEvent {
                id: "evt-001".into(),
                timestamp_ms: 1_000,
                event_type: EventType::ProcessStart,
                process: process.clone(),
                subject: "process".into(),
                target: Some("checkout-service".into()),
                metadata: serde_json::json!({}),
                source: "demo".into(),
                sensitivity: Sensitivity::PublicMetadata,
            },
            RuntimeEvent {
                id: "evt-002".into(),
                timestamp_ms: 1_020,
                event_type: EventType::NetworkConnection,
                process: process.clone(),
                subject: "tcp".into(),
                target: Some("api.example.com:443".into()),
                metadata: serde_json::json!({"protocol":"tcp","port":443}),
                source: "demo".into(),
                sensitivity: Sensitivity::PublicMetadata,
            },
            RuntimeEvent {
                id: "evt-003".into(),
                timestamp_ms: 1_050,
                event_type: EventType::FileAccess,
                process: process,
                subject: "file_read".into(),
                target: Some("/app/config/payment.json".into()),
                metadata: serde_json::json!({}),
                source: "demo".into(),
                sensitivity: Sensitivity::PotentiallySensitive,
            },
        ]
    }
}

pub fn build_demo_passport() -> RuntimePassport {
    RuntimePassport {
        schema_version: "0.1".into(),
        passport_id: "demo-passport".into(),
        generated_at_ms: 1_050,
        application: "checkout-service".into(),
        observations: PassportObservations {
            processes: vec!["checkout-service".into()],
            network_targets: vec!["api.example.com:443".into()],
            files: vec!["/app/config/payment.json".into()],
            libraries: vec![],
        },
        changes: vec![],
    }
}
