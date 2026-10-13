use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, UNIX_EPOCH};

use windows_erg::etw::{DecodedEvent, EventTrace, SystemProvider, TcpEvent, TcpOperation};

use crate::collectors::CollectorError;

const CLASSIC_TCPIP_PROVIDER_GUID: &str = "9A280AC0-C8E0-11D1-84E2-00C04FB998A2";
const TRACE_CHANNEL_CAPACITY: usize = 10_000;
const APP_CHANNEL_CAPACITY: usize = 512;
const EMPTY_BATCH_SLEEP: Duration = Duration::from_millis(40);
const MAX_EVENT_SHAPES: usize = 24;
const MAX_RAW_SAMPLES: usize = 6;
const MAX_TCP_SAMPLES: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct NetworkTraceDiagnostics {
    pub raw_events_seen: u64,
    pub tcp_events_decoded: u64,
    pub other_events_decoded: u64,
    pub unsupported_tcp_operations: u64,
    pub incomplete_tcp_events: u64,
    pub observations_enqueued: u64,
    pub event_shapes: BTreeMap<String, u64>,
    pub additional_shape_event_count: u64,
    /// Terminal ETW errors are retained here even when the bounded message queue is full.
    pub stream_error: Option<String>,
    pub raw_event_samples: Vec<String>,
    pub tcp_event_samples: Vec<String>,
}

impl NetworkTraceDiagnostics {
    fn record_shape(&mut self, event: &windows_erg::etw::TraceEvent) {
        let shape = format!(
            "id={} version={} opcode={} provider={:?}",
            event.id, event.version, event.opcode, event.provider_guid
        );
        if let Some(count) = self.event_shapes.get_mut(&shape) {
            *count = count.saturating_add(1);
        } else if self.event_shapes.len() < MAX_EVENT_SHAPES {
            self.event_shapes.insert(shape, 1);
        } else {
            self.additional_shape_event_count = self.additional_shape_event_count.saturating_add(1);
        }
    }

    fn record_raw_sample(&mut self, sample: String) {
        if self.raw_event_samples.len() < MAX_RAW_SAMPLES {
            self.raw_event_samples.push(sample);
        }
    }

    fn record_tcp_sample(&mut self, sample: String) {
        if self.tcp_event_samples.len() < MAX_TCP_SAMPLES {
            self.tcp_event_samples.push(sample);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkOperation {
    Connect,
    Accept,
    Disconnect,
    Reconnect,
}

impl NetworkOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Accept => "accept",
            Self::Disconnect => "disconnect",
            Self::Reconnect => "reconnect",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkObservation {
    pub timestamp_ms: i64,
    pub process_id: u32,
    pub operation: NetworkOperation,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}

#[derive(Debug)]
pub enum NetworkWatchMessage {
    Event(NetworkObservation),
    Error(String),
}

pub struct WindowsNetworkEventWatcher {
    stop_requested: Arc<AtomicBool>,
    receiver: Receiver<NetworkWatchMessage>,
    worker: Option<JoinHandle<()>>,
    dropped_events: Arc<AtomicUsize>,
    diagnostics: Arc<Mutex<NetworkTraceDiagnostics>>,
}

impl WindowsNetworkEventWatcher {
    pub fn start() -> Result<Self, CollectorError> {
        let trace = EventTrace::builder("TraceFactNetworkObserver")
            .system_provider(SystemProvider::Network)
            .channel_capacity(TRACE_CHANNEL_CAPACITY)
            .start()
            .map_err(|error| {
                CollectorError::new(
                    "windows_network",
                    format!(
                        "Could not start Windows TCP/IP tracing. Run TraceFact from an Administrator PowerShell and check whether another kernel tracing session is active. Details: {error}"
                    ),
                )
            })?;

        let (sender, receiver) = mpsc::sync_channel(APP_CHANNEL_CAPACITY);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop_requested);
        let dropped_events = Arc::new(AtomicUsize::new(0));
        let worker_dropped = Arc::clone(&dropped_events);
        let diagnostics = Arc::new(Mutex::new(NetworkTraceDiagnostics::default()));
        let worker_diagnostics = Arc::clone(&diagnostics);

        let worker = thread::Builder::new()
            .name("tracefact-windows-network".to_string())
            .spawn(move || {
                run_trace(
                    trace,
                    sender,
                    worker_stop,
                    worker_dropped,
                    worker_diagnostics,
                )
            })
            .map_err(|error| {
                CollectorError::new(
                    "windows_network",
                    format!("Could not create the network observer thread: {error}"),
                )
            })?;

        Ok(Self {
            stop_requested,
            receiver,
            worker: Some(worker),
            dropped_events,
            diagnostics,
        })
    }

    pub fn receiver(&self) -> &Receiver<NetworkWatchMessage> {
        &self.receiver
    }

    pub fn dropped_events(&self) -> usize {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub fn diagnostics(&self) -> NetworkTraceDiagnostics {
        self.diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn stop(&mut self) -> Result<(), CollectorError> {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| {
                CollectorError::new("windows_network", "The network observer thread panicked.")
            })?;
        }
        Ok(())
    }
}

impl Drop for WindowsNetworkEventWatcher {
    fn drop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn raw_event_sample(event_shape: &str, payload_bytes: usize) -> String {
    format!("{event_shape} payload_bytes={payload_bytes} decoded_as=non_tcp")
}

fn classic_tcp_sample(event_shape: &str, operation: NetworkOperation) -> String {
    format!(
        "{event_shape} operation={} endpoint_data=redacted",
        operation.as_str()
    )
}

fn decoded_tcp_sample(
    event_shape: &str,
    operation: &str,
    payload_pid_present: bool,
    source_ip_present: bool,
    source_port_present: bool,
    destination_ip_present: bool,
    destination_port_present: bool,
) -> String {
    format!(
        "{event_shape} operation={operation} payload_pid_present={payload_pid_present} source_ip_present={source_ip_present} source_port_present={source_port_present} destination_ip_present={destination_ip_present} destination_port_present={destination_port_present}"
    )
}

fn run_trace(
    mut trace: EventTrace,
    sender: SyncSender<NetworkWatchMessage>,
    stop_requested: Arc<AtomicBool>,
    dropped_events: Arc<AtomicUsize>,
    shared_diagnostics: Arc<Mutex<NetworkTraceDiagnostics>>,
) {
    let mut batch = Vec::with_capacity(256);
    let mut diagnostics = NetworkTraceDiagnostics::default();
    let mut last_publish = Instant::now();

    while !stop_requested.load(Ordering::Relaxed) {
        let count = match trace.next_batch(&mut batch) {
            Ok(count) => count,
            Err(error) => {
                let message = format!("Windows TCP/IP event stream failed: {error}");
                diagnostics.stream_error = Some(message.clone());
                // Preserve the terminal error outside the bounded queue as well.
                // If the queue is full, the main thread can still report this after shutdown.
                publish_diagnostics(&shared_diagnostics, &diagnostics);
                match sender.try_send(NetworkWatchMessage::Error(message)) {
                    Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
                }
                break;
            }
        };

        if count == 0 {
            if last_publish.elapsed() >= Duration::from_secs(1) {
                publish_diagnostics(&shared_diagnostics, &diagnostics);
                last_publish = Instant::now();
            }
            thread::sleep(EMPTY_BATCH_SLEEP);
            continue;
        }

        diagnostics.raw_events_seen = diagnostics.raw_events_seen.saturating_add(count as u64);

        for event in batch.iter().take(count) {
            diagnostics.record_shape(event);

            match decode_classic_tcpip_event(event) {
                ClassicTcpIpDecode::Observation(observation) => {
                    diagnostics.tcp_events_decoded =
                        diagnostics.tcp_events_decoded.saturating_add(1);
                    // Diagnostics are system-wide at the ETW source. Keep samples
                    // schema-only so unrelated process IDs and endpoints are not exposed.
                    let tcp_sample = classic_tcp_sample(&event_shape(event), observation.operation);
                    match sender.try_send(NetworkWatchMessage::Event(observation)) {
                        Ok(()) => {
                            diagnostics.observations_enqueued =
                                diagnostics.observations_enqueued.saturating_add(1);
                            diagnostics.record_tcp_sample(format!("{tcp_sample} enqueued=yes"));
                        }
                        Err(TrySendError::Full(_)) => {
                            dropped_events.fetch_add(1, Ordering::Relaxed);
                            diagnostics
                                .record_tcp_sample(format!("{tcp_sample} enqueued=no queue=full"));
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            publish_diagnostics(&shared_diagnostics, &diagnostics);
                            return;
                        }
                    }
                    continue;
                }
                ClassicTcpIpDecode::IgnoredOperation => {
                    diagnostics.unsupported_tcp_operations =
                        diagnostics.unsupported_tcp_operations.saturating_add(1);
                    continue;
                }
                ClassicTcpIpDecode::Incomplete(reason) => {
                    diagnostics.incomplete_tcp_events =
                        diagnostics.incomplete_tcp_events.saturating_add(1);
                    diagnostics.record_tcp_sample(format!(
                        "{} payload_bytes={} rejected={reason}",
                        event_shape(event),
                        event.data.len()
                    ));
                    continue;
                }
                ClassicTcpIpDecode::NotClassicTcpIp => {}
            }

            let decoded = event.decode();
            let DecodedEvent::Tcp(tcp) = decoded else {
                diagnostics.other_events_decoded =
                    diagnostics.other_events_decoded.saturating_add(1);
                diagnostics
                    .record_raw_sample(raw_event_sample(&event_shape(event), event.data.len()));
                continue;
            };

            diagnostics.tcp_events_decoded = diagnostics.tcp_events_decoded.saturating_add(1);
            // Report field availability without putting process IDs, IP addresses,
            // or port values from unrelated system traffic into diagnostics.
            let tcp_sample = decoded_tcp_sample(
                &event_shape(event),
                &format!("{:?}", tcp.operation),
                tcp.process_id.is_some(),
                tcp.source_ip.is_some(),
                tcp.source_port.is_some(),
                tcp.destination_ip.is_some(),
                tcp.destination_port.is_some(),
            );

            if supported_operation(tcp.operation).is_none() {
                diagnostics.unsupported_tcp_operations =
                    diagnostics.unsupported_tcp_operations.saturating_add(1);
                diagnostics
                    .record_tcp_sample(format!("{tcp_sample} rejected=unsupported_operation"));
                continue;
            }

            let Some(observation) = observation_from_tcp_event(&tcp, event.timestamp) else {
                diagnostics.incomplete_tcp_events =
                    diagnostics.incomplete_tcp_events.saturating_add(1);
                diagnostics.record_tcp_sample(format!(
                    "{tcp_sample} rejected=incomplete_fields_or_timestamp"
                ));
                continue;
            };

            match sender.try_send(NetworkWatchMessage::Event(observation)) {
                Ok(()) => {
                    diagnostics.observations_enqueued =
                        diagnostics.observations_enqueued.saturating_add(1);
                    diagnostics.record_tcp_sample(format!("{tcp_sample} enqueued=yes"));
                }
                Err(TrySendError::Full(_)) => {
                    dropped_events.fetch_add(1, Ordering::Relaxed);
                    diagnostics.record_tcp_sample(format!("{tcp_sample} enqueued=no queue=full"));
                }
                Err(TrySendError::Disconnected(_)) => {
                    publish_diagnostics(&shared_diagnostics, &diagnostics);
                    return;
                }
            }
        }

        if last_publish.elapsed() >= Duration::from_secs(1) {
            publish_diagnostics(&shared_diagnostics, &diagnostics);
            last_publish = Instant::now();
        }
    }

    let _ = trace.stop();
    publish_diagnostics(&shared_diagnostics, &diagnostics);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassicTcpIpPayloadLayout {
    Ipv4Group1,
    Ipv4Group2,
    Ipv6Group3,
    Ipv6Group4,
}

impl ClassicTcpIpPayloadLayout {
    fn minimum_size(self) -> usize {
        match self {
            Self::Ipv4Group1 => 28,
            Self::Ipv4Group2 => 44,
            Self::Ipv6Group3 => 52,
            Self::Ipv6Group4 => 68,
        }
    }

    fn endpoint_offsets(self) -> (usize, usize, usize, usize) {
        match self {
            Self::Ipv4Group1 | Self::Ipv4Group2 => (8, 12, 16, 18),
            Self::Ipv6Group3 | Self::Ipv6Group4 => (8, 24, 40, 42),
        }
    }

    fn is_ipv6(self) -> bool {
        matches!(self, Self::Ipv6Group3 | Self::Ipv6Group4)
    }
}

enum ClassicTcpIpDecode {
    NotClassicTcpIp,
    IgnoredOperation,
    Incomplete(String),
    Observation(NetworkObservation),
}

/// Decode the classic NT Kernel Logger TcpIp events. They use Event ID 0 and
/// place the event type in the opcode, so TraceEvent::decode() does not decode
/// their binary MOF payload into a TcpEvent.
fn decode_classic_tcpip_event(event: &windows_erg::etw::TraceEvent) -> ClassicTcpIpDecode {
    let provider_guid = format!("{:?}", event.provider_guid);
    if event.id != 0 || !provider_guid.eq_ignore_ascii_case(CLASSIC_TCPIP_PROVIDER_GUID) {
        return ClassicTcpIpDecode::NotClassicTcpIp;
    }

    decode_classic_tcpip_payload(event.opcode, event.version, &event.data, event.timestamp)
}

fn decode_classic_tcpip_payload(
    opcode: u8,
    version: u8,
    data: &[u8],
    timestamp: std::time::SystemTime,
) -> ClassicTcpIpDecode {
    if version != 2 {
        return ClassicTcpIpDecode::Incomplete(format!("unsupported_classic_version_{version}"));
    }

    let (operation, layout) = match opcode {
        12 => (
            NetworkOperation::Connect,
            ClassicTcpIpPayloadLayout::Ipv4Group2,
        ),
        15 => (
            NetworkOperation::Accept,
            ClassicTcpIpPayloadLayout::Ipv4Group2,
        ),
        13 => (
            NetworkOperation::Disconnect,
            ClassicTcpIpPayloadLayout::Ipv4Group1,
        ),
        16 => (
            NetworkOperation::Reconnect,
            ClassicTcpIpPayloadLayout::Ipv4Group1,
        ),
        28 => (
            NetworkOperation::Connect,
            ClassicTcpIpPayloadLayout::Ipv6Group4,
        ),
        31 => (
            NetworkOperation::Accept,
            ClassicTcpIpPayloadLayout::Ipv6Group4,
        ),
        29 => (
            NetworkOperation::Disconnect,
            ClassicTcpIpPayloadLayout::Ipv6Group3,
        ),
        32 => (
            NetworkOperation::Reconnect,
            ClassicTcpIpPayloadLayout::Ipv6Group3,
        ),
        // Classic TcpIp Send, Receive, Retransmit, Copy and Fail events are
        // deliberately excluded because this collector records connections.
        _ => return ClassicTcpIpDecode::IgnoredOperation,
    };

    let minimum_size = layout.minimum_size();
    if data.len() < minimum_size {
        return ClassicTcpIpDecode::Incomplete(format!(
            "payload_too_short_expected_{minimum_size}_got_{}",
            data.len()
        ));
    }

    let Some(process_id) = read_u32_le(data, 0) else {
        return ClassicTcpIpDecode::Incomplete("missing_payload_process_id".to_string());
    };
    if process_id == 0 || process_id == u32::MAX {
        return ClassicTcpIpDecode::Incomplete("invalid_payload_process_id".to_string());
    }

    let (destination_offset, source_offset, destination_port_offset, source_port_offset) =
        layout.endpoint_offsets();
    let source_ip = if layout.is_ipv6() {
        let Some(address) = read_ipv6(data, source_offset) else {
            return ClassicTcpIpDecode::Incomplete("missing_source_ipv6".to_string());
        };
        IpAddr::V6(address)
    } else {
        let Some(address) = read_ipv4(data, source_offset) else {
            return ClassicTcpIpDecode::Incomplete("missing_source_ipv4".to_string());
        };
        IpAddr::V4(address)
    };
    let destination_ip = if layout.is_ipv6() {
        let Some(address) = read_ipv6(data, destination_offset) else {
            return ClassicTcpIpDecode::Incomplete("missing_destination_ipv6".to_string());
        };
        IpAddr::V6(address)
    } else {
        let Some(address) = read_ipv4(data, destination_offset) else {
            return ClassicTcpIpDecode::Incomplete("missing_destination_ipv4".to_string());
        };
        IpAddr::V4(address)
    };
    let Some(destination_port) = read_u16_be(data, destination_port_offset) else {
        return ClassicTcpIpDecode::Incomplete("missing_destination_port".to_string());
    };
    let Some(source_port) = read_u16_be(data, source_port_offset) else {
        return ClassicTcpIpDecode::Incomplete("missing_source_port".to_string());
    };
    let Some(timestamp_ms) = timestamp
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
    else {
        return ClassicTcpIpDecode::Incomplete("invalid_event_timestamp".to_string());
    };

    ClassicTcpIpDecode::Observation(NetworkObservation {
        timestamp_ms,
        process_id,
        operation,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
    })
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_ipv4(data: &[u8], offset: usize) -> Option<Ipv4Addr> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(Ipv4Addr::from(bytes))
}

fn read_ipv6(data: &[u8], offset: usize) -> Option<Ipv6Addr> {
    let bytes: [u8; 16] = data.get(offset..offset.checked_add(16)?)?.try_into().ok()?;
    Some(Ipv6Addr::from(bytes))
}

fn event_shape(event: &windows_erg::etw::TraceEvent) -> String {
    format!(
        "id={} version={} opcode={} provider={:?}",
        event.id, event.version, event.opcode, event.provider_guid
    )
}

fn publish_diagnostics(
    shared: &Mutex<NetworkTraceDiagnostics>,
    diagnostics: &NetworkTraceDiagnostics,
) {
    *shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = diagnostics.clone();
}

fn supported_operation(operation: TcpOperation) -> Option<NetworkOperation> {
    match operation {
        TcpOperation::Connect => Some(NetworkOperation::Connect),
        TcpOperation::Accept => Some(NetworkOperation::Accept),
        TcpOperation::Disconnect => Some(NetworkOperation::Disconnect),
        TcpOperation::Reconnect => Some(NetworkOperation::Reconnect),
        TcpOperation::Send
        | TcpOperation::Receive
        | TcpOperation::Retransmit
        | TcpOperation::Copy
        | TcpOperation::Unknown => None,
    }
}

fn observation_from_tcp_event(
    event: &TcpEvent,
    timestamp: std::time::SystemTime,
) -> Option<NetworkObservation> {
    let operation = supported_operation(event.operation)?;

    let process_id = event.process_id?.as_u32();
    let source_ip = event.source_ip?;
    let source_port = event.source_port?;
    let destination_ip = event.destination_ip?;
    let destination_port = event.destination_port?;
    let timestamp_ms = timestamp
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()?;

    Some(NetworkObservation {
        timestamp_ms,
        process_id,
        operation,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
    })
}

pub(crate) fn endpoint(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_ipv4_connect_decodes_process_and_endpoints() {
        let mut payload = vec![0u8; 44];
        payload[0..4].copy_from_slice(&1234u32.to_le_bytes());
        payload[8..12].copy_from_slice(&[203, 0, 113, 25]);
        payload[12..16].copy_from_slice(&[192, 0, 2, 10]);
        payload[16..18].copy_from_slice(&443u16.to_be_bytes());
        payload[18..20].copy_from_slice(&51000u16.to_be_bytes());

        let result = decode_classic_tcpip_payload(12, 2, &payload, UNIX_EPOCH);
        match result {
            ClassicTcpIpDecode::Observation(observation) => {
                assert_eq!(observation.process_id, 1234);
                assert_eq!(observation.operation, NetworkOperation::Connect);
                assert_eq!(
                    observation.source_ip,
                    "192.0.2.10".parse::<IpAddr>().unwrap()
                );
                assert_eq!(observation.source_port, 51000);
                assert_eq!(
                    observation.destination_ip,
                    "203.0.113.25".parse::<IpAddr>().unwrap()
                );
                assert_eq!(observation.destination_port, 443);
                assert_eq!(observation.timestamp_ms, 0);
            }
            _ => panic!("expected a decoded IPv4 connect event"),
        }
    }

    #[test]
    fn classic_ipv4_disconnect_uses_shorter_payload_layout() {
        let mut payload = vec![0u8; 28];
        payload[0..4].copy_from_slice(&4321u32.to_le_bytes());
        payload[8..12].copy_from_slice(&[192, 0, 2, 11]);
        payload[12..16].copy_from_slice(&[198, 51, 100, 7]);
        payload[16..18].copy_from_slice(&60000u16.to_be_bytes());
        payload[18..20].copy_from_slice(&443u16.to_be_bytes());

        let result = decode_classic_tcpip_payload(13, 2, &payload, UNIX_EPOCH);
        match result {
            ClassicTcpIpDecode::Observation(observation) => {
                assert_eq!(observation.process_id, 4321);
                assert_eq!(observation.operation, NetworkOperation::Disconnect);
                assert_eq!(observation.source_port, 443);
                assert_eq!(observation.destination_port, 60000);
            }
            _ => panic!("expected a decoded IPv4 disconnect event"),
        }
    }

    #[test]
    fn classic_ipv6_connect_decodes_endpoints() {
        let mut payload = vec![0u8; 68];
        payload[0..4].copy_from_slice(&77u32.to_le_bytes());
        payload[8..24].copy_from_slice(&"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
        payload[24..40].copy_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
        payload[40..42].copy_from_slice(&443u16.to_be_bytes());
        payload[42..44].copy_from_slice(&51515u16.to_be_bytes());

        let result = decode_classic_tcpip_payload(28, 2, &payload, UNIX_EPOCH);
        match result {
            ClassicTcpIpDecode::Observation(observation) => {
                assert_eq!(observation.process_id, 77);
                assert_eq!(observation.operation, NetworkOperation::Connect);
                assert_eq!(
                    observation.source_ip,
                    "2001:db8::10".parse::<IpAddr>().unwrap()
                );
                assert_eq!(observation.source_port, 51515);
                assert_eq!(
                    observation.destination_ip,
                    "2001:db8::20".parse::<IpAddr>().unwrap()
                );
                assert_eq!(observation.destination_port, 443);
            }
            _ => panic!("expected a decoded IPv6 connect event"),
        }
    }

    #[test]
    fn classic_tcp_data_transfer_events_are_ignored() {
        for opcode in [10, 11, 14, 18, 26, 27, 30, 34] {
            assert!(matches!(
                decode_classic_tcpip_payload(opcode, 2, &[0; 80], UNIX_EPOCH),
                ClassicTcpIpDecode::IgnoredOperation
            ));
        }
    }

    #[test]
    fn classic_connection_with_short_payload_is_diagnostic() {
        assert!(matches!(
            decode_classic_tcpip_payload(12, 2, &[0; 28], UNIX_EPOCH),
            ClassicTcpIpDecode::Incomplete(_)
        ));
    }

    #[test]
    fn diagnostic_samples_do_not_include_process_ids_or_endpoint_values() {
        let event_shape = "id=0 version=2 opcode=12 provider=classic-tcpip";
        let raw = raw_event_sample(event_shape, 44);
        let classic = classic_tcp_sample(event_shape, NetworkOperation::Connect);
        let decoded = decoded_tcp_sample(event_shape, "Connect", true, true, true, true, true);

        for sample in [&raw, &classic, &decoded] {
            assert!(!sample.contains("payload_pid=1234"));
            assert!(!sample.contains("203.0.113.17"));
            assert!(!sample.contains("127.0.0.1"));
            assert!(!sample.contains("destination_port=443"));
        }

        assert!(classic.contains("endpoint_data=redacted"));
        assert!(decoded.contains("payload_pid_present=true"));
    }

    #[test]
    fn endpoint_formats_ipv4() {
        assert_eq!(endpoint("192.0.2.5".parse().unwrap(), 443), "192.0.2.5:443");
    }

    #[test]
    fn endpoint_brackets_ipv6() {
        assert_eq!(
            endpoint("2001:db8::5".parse().unwrap(), 443),
            "[2001:db8::5]:443"
        );
    }

    #[test]
    fn operation_names_are_stable() {
        assert_eq!(NetworkOperation::Connect.as_str(), "connect");
        assert_eq!(NetworkOperation::Accept.as_str(), "accept");
        assert_eq!(NetworkOperation::Disconnect.as_str(), "disconnect");
        assert_eq!(NetworkOperation::Reconnect.as_str(), "reconnect");
    }

    #[test]
    fn data_transfer_events_are_not_collected() {
        assert_eq!(supported_operation(TcpOperation::Send), None);
        assert_eq!(supported_operation(TcpOperation::Receive), None);
        assert_eq!(supported_operation(TcpOperation::Retransmit), None);
        assert_eq!(supported_operation(TcpOperation::Copy), None);
        assert_eq!(supported_operation(TcpOperation::Unknown), None);
    }
}
