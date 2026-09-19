# ULPX REST API

The ULPX REST API provides interfaces for querying evidence, retrieving interpretations, and replaying events. It operates at `http://localhost:3000` (or the configured port).

## 1. List Events
**Method**: `GET`  
**Path**: `/api/v1/events`  
**Purpose**: Retrieve a paginated list of ingested events.

### Query Parameters
* `limit` (optional): Maximum number of events to return. Default 50, max 500.
* `offset` (optional): Pagination offset. Default 0.

### Response (200 OK)
```json
{
  "events": [
    {
      "event_id": "evt_...",
      "source": "stdin",
      "ingestion_timestamp": 1735689600000,
      "has_integrity": true
    }
  ]
}
```

## 2. Get Raw Evidence
**Method**: `GET`  
**Path**: `/api/v1/evidence/:event_id`  
**Purpose**: Retrieve the original raw evidence and its cryptographic integrity metadata.

### Response (200 OK)
```json
{
  "event_id": "evt_...",
  "source": "stdin",
  "payload_base64": "dmVuZG9yPUFDTUUgcHJvZHVjdD1GaXJld2FsbCBhY3Rpb249REVOWQo=",
  "integrity": {
    "hash_hex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "previous_link": null
  }
}
```

### Error (404 Not Found)
Returned if the event ID does not exist in the store.

## 3. Get Detailed Interpretation
**Method**: `GET`  
**Path**: `/api/v1/interpretation/:event_id/detailed`  
**Purpose**: Retrieve the current canonical interpretation (parsing, inference, semantic mapping, and provenance) of an event using the default pipeline.

### Response (200 OK)
```json
{
  "interpretation_id": "...",
  "source_event_id": "evt_...",
  "pipeline_config_identity": "...",
  "created_at_secs": 1735689600,
  "integrity_verified": true,
  "integrity_error": null,
  "trailing_frame_error": null,
  "frames": [
    {
      "frame_index": 0,
      "frame_bytes_base64": "...",
      "parser_id": "generic-kv-space-eq",
      "parser_version": "1.0",
      "parser_outcome": "Success",
      "inference_decision": {
        "decision": "Recognized",
        "abstention_reason": null,
        "recognized_candidate": {
          "parser_id": "generic-kv-space-eq",
          "format_name": "generic-kv-space-eq",
          "confidence": "Medium",
          "evidence": [
            {
              "detector_id": "generic-kv",
              "description": "...",
              "supports": true
            }
          ]
        },
        "all_candidates": []
      },
      "canonical_event": {
        "parser_id": "generic-kv-space-eq",
        "timestamp": null,
        "source_ip": null,
        "source_hostname": null,
        "dest_ip": null,
        "dest_hostname": null,
        "severity": null,
        "message": null,
        "action": {
          "value": "DENY",
          "provenance": {
            "source_field": "action",
            "byte_span": [30, 34],
            "transformations": [],
            "rule_id": "direct_map",
            "confidence": "Probable"
          }
        }
      },
      "ir_event": {
        "parser_id": "generic-kv-space-eq",
        "fields": {
          "action": {
            "value_type": "String",
            "value": "DENY",
            "byte_span": [30, 34]
          }
        }
      }
    }
  ]
}
```

## 4. Ephemeral Replay
**Method**: `POST`  
**Path**: `/api/v1/replay`  
**Purpose**: Temporarily reprocess an existing event with a custom pipeline configuration. Does NOT mutate the stored original evidence.

### Request Body (JSON)
```json
{
  "event_id": "evt_...",
  "pipeline_config": {
    "framer_id": "NewlineFramer",
    "framer_version": "1.0.0",
    "mapper_id": "default",
    "mapper_version": "1.0.0",
    "parser_registry": [
      "json-flat",
      "cef",
      "syslog-rfc3164"
    ],
    "inference_detectors": [
      "json",
      "cef",
      "syslog",
      "generic-kv-space-eq",
      "generic-csv-3col"
    ]
  }
}
```
*Note: Phase 15 declarative boundary enforcement limits the `framer_id` to exactly `"NewlineFramer"` and version `"1.0.0"`. Unsupported framers return a 400 Bad Request.*

### Response (200 OK)
Returns the same detailed interpretation JSON format as the `GET /api/v1/interpretation/:event_id/detailed` endpoint, but computed ephemerally using the requested pipeline.
