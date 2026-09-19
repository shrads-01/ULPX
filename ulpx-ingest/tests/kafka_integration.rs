use rskafka::client::{partition::Compression, partition::UnknownTopicHandling, ClientBuilder};
use rskafka::record::Record;
use std::sync::Arc;
use tokio::sync::Mutex;
use ulpx_core::framing::newline::NewlineFramer;
use ulpx_core::storage::{EvidenceStore, InMemoryStore};
use ulpx_ingest::kafka::{KafkaConfig, KafkaIngester};

#[tokio::test]
#[ignore = "Requires live Redpanda broker on localhost:9092"]
async fn test_kafka_integration_e2e() {
    let broker = "localhost:9092".to_string();
    let topic = "test_e2e_ulpx_ingest".to_string();

    // 1. Setup client & topic
    let client = ClientBuilder::new(vec![broker.clone()])
        .build()
        .await
        .unwrap();
    let controller = client.controller_client().unwrap();

    // Create topic (ignore error if it exists)
    let _ = controller.create_topic(&topic, 1, 1, 10_000).await;

    // 2. Setup consumer (KafkaIngester)
    let config = KafkaConfig {
        brokers: vec![broker],
        topic: topic.clone(),
        group_id: "test_e2e_group".to_string(),
        partition: 0,
        retry_backoff_ms: 1000,
    };

    let ingester = KafkaIngester::new(config).await.unwrap();
    let store = Arc::new(Mutex::new(InMemoryStore::default()));

    let store_clone = store.clone();

    // 3. Run consumer in background BEFORE producing (because StartOffset::Latest)
    let _handle = tokio::spawn(async move {
        // Need to create a boxed framer since run_consumer expects a reference
        let framer = NewlineFramer;
        ingester.run_consumer(&framer, store_clone).await;
    });

    // Wait for consumer to connect
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // 4. Setup producer (with retry for async topic creation)
    let mut retries = 5;
    let partition_client = loop {
        match client
            .partition_client(&topic, 0, UnknownTopicHandling::Retry)
            .await
        {
            Ok(c) => break c,
            Err(_e) if retries > 0 => {
                retries -= 1;
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(e) => panic!("Failed to get partition client: {:?}", e),
        }
    };
    let records = vec![
        Record {
            key: None,
            value: Some(b"hello integration\n".to_vec()),
            headers: Default::default(),
            timestamp: chrono::Utc::now(),
        },
        Record {
            key: None,
            value: Some(b"world streaming\n".to_vec()),
            headers: Default::default(),
            timestamp: chrono::Utc::now(),
        },
    ];
    partition_client
        .produce(records, Compression::NoCompression)
        .await
        .unwrap();

    // Wait for consumer to process
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // 5. Verify records
    let locked_store = store.lock().await;
    let events = locked_store.list_events(0, 100);
    assert!(events.len() >= 2);
}
