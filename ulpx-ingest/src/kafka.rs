use crate::{ingest_buffer, IngestionError, IngestionResult};
use futures_util::StreamExt;
use rskafka::client::consumer::StreamConsumerBuilder;
use rskafka::client::partition::UnknownTopicHandling;
use rskafka::client::{partition::PartitionClient, Client, ClientBuilder};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use ulpx_core::framing::Framer;
use ulpx_core::storage::EvidenceStore;

/// Configuration for the Kafka/Redpanda streaming consumer.
#[derive(Debug, Clone, PartialEq)]
pub struct KafkaConfig {
    pub brokers: Vec<String>,
    pub topic: String,
    pub group_id: String,
    pub partition: i32,
    pub retry_backoff_ms: u64,
}

impl KafkaConfig {
    /// Loads configuration from environment variables without hardcoding credentials.
    pub fn from_env() -> Result<Self, String> {
        let brokers_str =
            std::env::var("KAFKA_BROKERS").unwrap_or_else(|_| "localhost:9092".to_string());
        let topic = std::env::var("KAFKA_TOPIC").unwrap_or_else(|_| "ulpx_ingest".to_string());
        // Note: rskafka does not natively support Consumer Groups.
        // We parse group_id for future compatibility or abstraction layers.
        let group_id =
            std::env::var("KAFKA_GROUP_ID").unwrap_or_else(|_| "ulpx_consumer_group".to_string());

        let partition_str = std::env::var("KAFKA_PARTITION").unwrap_or_else(|_| "0".to_string());
        let partition = partition_str
            .parse()
            .map_err(|e| format!("Invalid KAFKA_PARTITION: {}", e))?;

        let retry_str = std::env::var("KAFKA_RETRY_MS").unwrap_or_else(|_| "5000".to_string());
        let retry_backoff_ms = retry_str
            .parse()
            .map_err(|e| format!("Invalid KAFKA_RETRY_MS: {}", e))?;

        let brokers: Vec<String> = brokers_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if brokers.is_empty() {
            return Err("KAFKA_BROKERS must contain at least one broker".to_string());
        }

        Ok(Self {
            brokers,
            topic,
            group_id,
            partition,
            retry_backoff_ms,
        })
    }
}

/// Core processing logic separated from Kafka polling for deterministic offline testing.
///
/// Malformed messages (e.g. framing bounds errors) are surfaced as an error. The
/// caller decides the quarantine or drop policy.
pub fn process_kafka_record(
    payload: &[u8],
    source_name: &str,
    base_index: u64,
    framer: &dyn Framer,
    store: &mut dyn EvidenceStore,
) -> Result<IngestionResult, IngestionError> {
    if payload.is_empty() {
        return Ok(IngestionResult {
            total_records: 0,
            stored_records: 0,
        });
    }

    // The payload enters the exact same ingestion pipeline, preserving lossless constraints.
    // The original broker payload is fully preserved in the ULPX event.
    ingest_buffer(payload, source_name, framer, store, base_index)
}

/// A basic streaming ingester for Kafka/Redpanda.
///
/// **LIMITATION: Unacknowledged Delivery Semantics**
/// The underlying `rskafka` client does not support Kafka Consumer Groups or offset
/// committing. Consequently, this ingester does **not** provide at-least-once delivery.
/// It operates effectively as unacknowledged (fire-and-forget) stream pulling.
///
/// - **Restart/Recovery:** Upon restart, this implementation begins at `Latest`, which
///   means any records produced while the service was down will be lost. (Using `Earliest`
///   would reprocess the entire partition from the beginning).
/// - **Storage Failure:** If a record cannot be stored, processing halts and retries locally,
///   but a process crash at this point would lose the record since the broker offset was
///   never durably tracked.
pub struct KafkaIngester {
    config: KafkaConfig,
    _client: Client,
    partition_client: Arc<PartitionClient>,
}

impl KafkaIngester {
    /// Creates a new KafkaIngester connecting to the specified broker.
    pub async fn new(config: KafkaConfig) -> Result<Self, rskafka::client::error::Error> {
        let client = ClientBuilder::new(config.brokers.clone()).build().await?;
        let partition_client = client
            .partition_client(&config.topic, config.partition, UnknownTopicHandling::Retry)
            .await?;
        Ok(Self {
            config,
            _client: client,
            partition_client: Arc::new(partition_client),
        })
    }

    /// Exposes a stream consumer abstraction.
    /// Because `rskafka` lacks consumer group API, this pulls from the `Latest` offset
    /// without acknowledging success back to the broker.
    pub async fn run_consumer(
        &self,
        framer: &(dyn Framer + Send + Sync),
        store: Arc<Mutex<dyn EvidenceStore + Send + Sync>>,
    ) {
        let mut consumer = StreamConsumerBuilder::new(
            self.partition_client.clone(),
            rskafka::client::consumer::StartOffset::Latest,
        )
        .with_max_wait_ms(100)
        .build();

        // `base_index` is strictly a deterministic local identifier for EventId generation,
        // it is explicitly NOT a Kafka offset and has no relation to broker acknowledgement.
        let mut base_index = 0u64;
        let source_name = format!("kafka-{}", self.config.topic);

        loop {
            match consumer.next().await {
                Some(Ok((record_and_offset, _watermark))) => {
                    let record = record_and_offset.record;
                    let payload = record.value.unwrap_or_default();
                    if payload.is_empty() {
                        continue;
                    }

                    // Loop locally until we successfully process the message, preserving it in memory
                    // in case of transient storage errors. But note: a crash loses this record.
                    loop {
                        let mut locked_store = store.lock().await;

                        match process_kafka_record(
                            &payload,
                            &source_name,
                            base_index,
                            framer,
                            &mut *locked_store,
                        ) {
                            Ok(res) => {
                                // Local ULPX index is advanced, but NO broker offset is committed.
                                base_index += res.total_records as u64;
                                break;
                            }
                            Err(IngestionError::Framing(e)) => {
                                // Malformed payload policy:
                                // We explicitly drop malformed broker payloads that fail framing.
                                // In a full production system, these should route to a quarantine path.
                                eprintln!("Kafka ingestion framing error (dropping malformed payload): {:?}", e);
                                break;
                            }
                            Err(e) => {
                                // Processing failure: Backoff and retry *locally in memory*.
                                // We are holding the message payload, so we don't lose it unless we crash.
                                eprintln!(
                                    "Kafka ingestion storage error: {:?}. Retrying locally...",
                                    e
                                );
                                drop(locked_store);
                                tokio::time::sleep(Duration::from_millis(
                                    self.config.retry_backoff_ms,
                                ))
                                .await;
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    eprintln!("Kafka consume error: {:?}. Backing off.", e);
                    tokio::time::sleep(Duration::from_millis(self.config.retry_backoff_ms)).await;
                }
                None => {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulpx_core::event::{EventId, EventMetadata, RawEvent};
    use ulpx_core::framing::newline::NewlineFramer;
    use ulpx_core::framing::FrameError;
    use ulpx_core::storage::{EvidenceStore, StoreError};

    #[derive(Default)]
    struct MockStore {
        events: Vec<RawEvent>,
        fail_next: bool,
    }

    impl EvidenceStore for MockStore {
        fn store(&mut self, event: RawEvent) -> Result<(), StoreError> {
            if self.fail_next {
                return Err(StoreError::Internal("mock error".to_string()));
            }
            self.events.push(event);
            Ok(())
        }

        fn retrieve(&self, _id: &EventId) -> Result<RawEvent, StoreError> {
            unimplemented!()
        }

        fn list_events(&self, _offset: usize, _limit: usize) -> Vec<EventMetadata> {
            unimplemented!()
        }
    }

    #[test]
    fn test_config_from_env_defaults() {
        // Deterministic test of config parsing
        std::env::remove_var("KAFKA_BROKERS");
        let config = KafkaConfig::from_env().unwrap();
        assert_eq!(config.brokers, vec!["localhost:9092"]);
        assert_eq!(config.topic, "ulpx_ingest");
    }

    #[test]
    fn test_process_kafka_record_successful() {
        let framer = NewlineFramer;
        let mut store = MockStore::default();

        let payload = b"hello\nworld\n";
        let res = process_kafka_record(payload, "test-topic", 100, &framer, &mut store).unwrap();

        assert_eq!(res.total_records, 2);
        assert_eq!(res.stored_records, 2);
        assert_eq!(store.events.len(), 2);
        assert_eq!(store.events[0].as_bytes(), b"hello\n");
        assert_eq!(store.events[1].as_bytes(), b"world\n");
    }

    #[test]
    fn test_process_kafka_record_framing_error() {
        let framer = NewlineFramer;
        let mut store = MockStore::default();

        // Incomplete line
        let payload = b"hello";
        let err =
            process_kafka_record(payload, "test-topic", 100, &framer, &mut store).unwrap_err();

        match err {
            IngestionError::Framing(FrameError::Incomplete) => {}
            _ => panic!("Expected Framing Error"),
        }
        assert_eq!(store.events.len(), 0);
    }

    #[test]
    fn test_process_kafka_record_storage_error() {
        let framer = NewlineFramer;
        let mut store = MockStore {
            fail_next: true,
            ..Default::default()
        };

        let payload = b"hello\n";
        let err =
            process_kafka_record(payload, "test-topic", 100, &framer, &mut store).unwrap_err();

        match err {
            IngestionError::Storage { stored_records, .. } => {
                assert_eq!(stored_records, 0);
            }
            _ => panic!("Expected Storage Error"),
        }
    }
}
