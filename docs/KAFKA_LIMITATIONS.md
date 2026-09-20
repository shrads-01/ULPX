# Kafka Streaming Blocker

The implementation of true durable Kafka consumer group offset semantics is currently blocked.

## Technical Details
* **rskafka**: The current pure-Rust async client explicitly lacks consumer group and offset-commit APIs. It only supports raw \Latest\ or \Earliest\ partition stream pulling.
* **rdkafka**: Fails to build on Windows environments lacking a C-toolchain and CMake.
* **kafka crate**: Older synchronous client fails protocol negotiation with modern Redpanda brokers.

## Current Delivery Limitations
Due to this blocker, the current streaming boundary operates under **Unacknowledged Delivery (Fire-and-Forget)** semantics:
1. **No Durable Offsets**: Broker offsets are not committed.
2. **Restart Behavior**: Upon restart, the consumer resumes from \Latest\, permanently skipping events produced during downtime.
3. **Storage Failure**: Retries are handled locally in memory. A process crash during a storage outage results in permanent data loss since the offset is not tracked on the broker.

