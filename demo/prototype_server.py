#!/usr/bin/env python3
"""
ULPX Prototype Server
Serves the ULPX Analyst UI and REST API.
"""

import http.server
import socketserver
import json
import base64
import hashlib
import time
import os
import sys
import re
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("ULPX_PORT", 3000))
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "ulpx-serve", "static")
BENCHMARKS_DIR = os.path.join(BASE_DIR, "ulpx-bench", "benchmarks")

# ─────────────────────────────────────────────────────────────────────────────
# Sample Datastore & Fixtures
# ─────────────────────────────────────────────────────────────────────────────

RAW_EVENTS = {}
DETAILED_INTERPRETATIONS = {}

def add_event(event_id, source, raw_text, parser_id, parser_outcome, canonical=None, ir_fields=None, inference=None):
    raw_bytes = raw_text.encode('utf-8')
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    
    RAW_EVENTS[event_id] = {
        "event_id": event_id,
        "source": source,
        "payload_base64": base64.b64encode(raw_bytes).decode('ascii'),
        "size_bytes": len(raw_bytes),
        "ingestion_timestamp": int(time.time() * 1000) - (len(RAW_EVENTS) * 120000),
        "integrity": {
            "hash_hex": content_hash,
            "previous_link": f"link-{len(RAW_EVENTS)}" if len(RAW_EVENTS) > 0 else None
        }
    }
    
    frame = {
        "frame_index": 0,
        "frame_bytes_base64": base64.b64encode(raw_bytes).decode('ascii'),
        "parser_id": parser_id,
        "parser_version": "1.0.0" if parser_id else None,
        "parser_outcome": parser_outcome,
        "inference_decision": inference,
        "canonical_event": canonical,
        "ir_event": {
            "parser_id": parser_id or "unknown",
            "fields": ir_fields or {}
        }
    }
    
    DETAILED_INTERPRETATIONS[event_id] = {
        "interpretation_id": f"interp_{event_id}_{int(time.time())}",
        "source_event_id": event_id,
        "pipeline_config_identity": "pipe_v1_canonical_newline_composite",
        "created_at_secs": int(time.time()),
        "integrity_verified": True,
        "integrity_error": None,
        "trailing_frame_error": None,
        "frames": [frame]
    }

def init_datastore():
    # 1. CEF Standard Firewall Drop
    cef_raw = "CEF:0|CheckPoint|VPN-1 & FireWall-1|1.0|drop|Drop packet|6|src=192.168.1.50 dst=10.0.0.1 spt=443 dpt=54321 proto=TCP act=drop msg=Connection rejected by firewall rule\n"
    add_event(
        event_id="evt_cef_001",
        source="network-firewall-cluster",
        raw_text=cef_raw,
        parser_id="cef",
        parser_outcome="Success",
        canonical={
            "parser_id": "cef",
            "timestamp": None,
            "source_ip": {
                "value": "192.168.1.50",
                "provenance": {
                    "source_field": "src",
                    "byte_span": [cef_raw.find("192.168.1.50"), cef_raw.find("192.168.1.50") + len("192.168.1.50")],
                    "transformations": ["extract_cef_kv", "ipv4_normalize"],
                    "rule_id": "rule_cef_network_endpoint",
                    "confidence": "High"
                }
            },
            "source_hostname": None,
            "dest_ip": {
                "value": "10.0.0.1",
                "provenance": {
                    "source_field": "dst",
                    "byte_span": [cef_raw.find("10.0.0.1"), cef_raw.find("10.0.0.1") + len("10.0.0.1")],
                    "transformations": ["extract_cef_kv", "ipv4_normalize"],
                    "rule_id": "rule_cef_network_endpoint",
                    "confidence": "High"
                }
            },
            "dest_hostname": None,
            "severity": {
                "value": "Medium",
                "provenance": {
                    "source_field": "cef.severity",
                    "byte_span": [cef_raw.find("|6|") + 1, cef_raw.find("|6|") + 2],
                    "transformations": ["cef_scale_to_ocsf"],
                    "rule_id": "rule_cef_severity_mapping",
                    "confidence": "High"
                }
            },
            "message": {
                "value": "Connection rejected by firewall rule",
                "provenance": {
                    "source_field": "msg",
                    "byte_span": [cef_raw.find("msg=") + 4, cef_raw.find("\n")],
                    "transformations": ["string_trim"],
                    "rule_id": "rule_cef_message_passthrough",
                    "confidence": "High"
                }
            },
            "action": {
                "value": "drop",
                "provenance": {
                    "source_field": "act",
                    "byte_span": [cef_raw.find("act=") + 4, cef_raw.find("act=") + 8],
                    "transformations": ["action_normalize_ocsf"],
                    "rule_id": "rule_cef_action_mapping",
                    "confidence": "High"
                }
            }
        },
        ir_fields={
            "src": {"value_type": "String", "value": "192.168.1.50", "byte_span": [cef_raw.find("192.168.1.50"), cef_raw.find("192.168.1.50") + len("192.168.1.50")]},
            "dst": {"value_type": "String", "value": "10.0.0.1", "byte_span": [cef_raw.find("10.0.0.1"), cef_raw.find("10.0.0.1") + len("10.0.0.1")]},
            "act": {"value_type": "String", "value": "drop", "byte_span": [cef_raw.find("act=") + 4, cef_raw.find("act=") + 8]},
            "msg": {"value_type": "String", "value": "Connection rejected by firewall rule", "byte_span": [cef_raw.find("msg=") + 4, cef_raw.find("\n")]}
        },
        inference=None
    )

    # 2. AWS CloudTrail JSON Event
    json_raw = '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/SecOps"},"eventTime":"2026-09-19T23:55:00Z","eventName":"ConsoleLogin","sourceIPAddress":"198.51.100.24","action":"allow","severity":"Info"}\n'
    add_event(
        event_id="evt_json_002",
        source="aws-cloudtrail-stream",
        raw_text=json_raw,
        parser_id="json-flat",
        parser_outcome="Success",
        canonical={
            "parser_id": "json-flat",
            "timestamp": {
                "value": "2026-09-19T23:55:00Z",
                "provenance": {
                    "source_field": "eventTime",
                    "byte_span": [json_raw.find("2026-09-19T23:55:00Z"), json_raw.find("2026-09-19T23:55:00Z") + len("2026-09-19T23:55:00Z")],
                    "transformations": ["iso8601_parse"],
                    "rule_id": "rule_json_iso_timestamp",
                    "confidence": "High"
                }
            },
            "source_ip": {
                "value": "198.51.100.24",
                "provenance": {
                    "source_field": "sourceIPAddress",
                    "byte_span": [json_raw.find("198.51.100.24"), json_raw.find("198.51.100.24") + len("198.51.100.24")],
                    "transformations": ["ipv4_normalize"],
                    "rule_id": "rule_json_ip_heuristic",
                    "confidence": "High"
                }
            },
            "source_hostname": None,
            "dest_ip": None,
            "dest_hostname": None,
            "severity": {
                "value": "Info",
                "provenance": {
                    "source_field": "severity",
                    "byte_span": [json_raw.find('"Info"') + 1, json_raw.find('"Info"') + 5],
                    "transformations": ["passthrough"],
                    "rule_id": "rule_json_severity",
                    "confidence": "High"
                }
            },
            "message": {
                "value": "ConsoleLogin",
                "provenance": {
                    "source_field": "eventName",
                    "byte_span": [json_raw.find("ConsoleLogin"), json_raw.find("ConsoleLogin") + len("ConsoleLogin")],
                    "transformations": ["string_passthrough"],
                    "rule_id": "rule_json_msg_heuristic",
                    "confidence": "High"
                }
            },
            "action": {
                "value": "allow",
                "provenance": {
                    "source_field": "action",
                    "byte_span": [json_raw.find('"allow"') + 1, json_raw.find('"allow"') + 6],
                    "transformations": ["action_normalize"],
                    "rule_id": "rule_json_action",
                    "confidence": "High"
                }
            }
        },
        ir_fields={
            "sourceIPAddress": {"value_type": "String", "value": "198.51.100.24", "byte_span": [json_raw.find("198.51.100.24"), json_raw.find("198.51.100.24") + len("198.51.100.24")]},
            "eventName": {"value_type": "String", "value": "ConsoleLogin", "byte_span": [json_raw.find("ConsoleLogin"), json_raw.find("ConsoleLogin") + len("ConsoleLogin")]},
            "eventTime": {"value_type": "String", "value": "2026-09-19T23:55:00Z", "byte_span": [json_raw.find("2026-09-19T23:55:00Z"), json_raw.find("2026-09-19T23:55:00Z") + len("2026-09-19T23:55:00Z")]}
        },
        inference=None
    )

    # 3. Linux RFC3164 Syslog Auth Failure
    syslog_raw = "Sep 19 23:50:12 auth-bastion sshd[14220]: Failed password for invalid user admin from 203.0.113.88 port 51234 ssh2\n"
    add_event(
        event_id="evt_syslog_003",
        source="edge-bastion-syslog",
        raw_text=syslog_raw,
        parser_id="syslog-rfc3164",
        parser_outcome="Success",
        canonical={
            "parser_id": "syslog-rfc3164",
            "timestamp": {
                "value": "Sep 19 23:50:12",
                "provenance": {
                    "source_field": "syslog.timestamp",
                    "byte_span": [0, 15],
                    "transformations": ["rfc3164_timestamp_parse"],
                    "rule_id": "rule_syslog_header_timestamp",
                    "confidence": "High"
                }
            },
            "source_ip": {
                "value": "203.0.113.88",
                "provenance": {
                    "source_field": "message_body",
                    "byte_span": [syslog_raw.find("203.0.113.88"), syslog_raw.find("203.0.113.88") + len("203.0.113.88")],
                    "transformations": ["regex_ip_extraction", "ipv4_normalize"],
                    "rule_id": "rule_syslog_ip_body_extractor",
                    "confidence": "Medium"
                }
            },
            "source_hostname": {
                "value": "auth-bastion",
                "provenance": {
                    "source_field": "syslog.hostname",
                    "byte_span": [16, 28],
                    "transformations": ["hostname_normalize"],
                    "rule_id": "rule_syslog_header_host",
                    "confidence": "High"
                }
            },
            "dest_ip": None,
            "dest_hostname": None,
            "severity": {
                "value": "Warning",
                "provenance": {
                    "source_field": "syslog.priority",
                    "byte_span": None,
                    "transformations": ["syslog_auth_priority_inference"],
                    "rule_id": "rule_syslog_facility_severity",
                    "confidence": "Medium"
                }
            },
            "message": {
                "value": "Failed password for invalid user admin from 203.0.113.88 port 51234 ssh2",
                "provenance": {
                    "source_field": "syslog.message",
                    "byte_span": [syslog_raw.find("Failed password"), len(syslog_raw) - 1],
                    "transformations": ["string_trim"],
                    "rule_id": "rule_syslog_message_body",
                    "confidence": "High"
                }
            },
            "action": {
                "value": "deny",
                "provenance": {
                    "source_field": "syslog.message",
                    "byte_span": [syslog_raw.find("Failed"), syslog_raw.find("Failed") + 6],
                    "transformations": ["auth_failure_keyword_map"],
                    "rule_id": "rule_syslog_auth_action",
                    "confidence": "High"
                }
            }
        },
        ir_fields={
            "syslog.hostname": {"value_type": "String", "value": "auth-bastion", "byte_span": [16, 28]},
            "syslog.app_name": {"value_type": "String", "value": "sshd", "byte_span": [29, 33]},
            "syslog.proc_id": {"value_type": "String", "value": "14220", "byte_span": [34, 39]}
        },
        inference=None
    )

    # 4. Unseen Vendor KV — Triggers Unknown Format Inference Engine!
    kv_raw = "vendor=ACME product=EdgeShield action=DENY src=172.16.40.12 dst=10.200.0.5 port=8080 reason=policy_violation rule=940\n"
    add_event(
        event_id="evt_unseen_kv_004",
        source="acme-appliance-incoming",
        raw_text=kv_raw,
        parser_id=None,
        parser_outcome="Inferred",
        canonical={
            "parser_id": "generic-kv-space-eq",
            "timestamp": None,
            "source_ip": {
                "value": "172.16.40.12",
                "provenance": {
                    "source_field": "src",
                    "byte_span": [kv_raw.find("172.16.40.12"), kv_raw.find("172.16.40.12") + len("172.16.40.12")],
                    "transformations": ["inferred_kv_extractor", "ipv4_normalize"],
                    "rule_id": "inferred_rule_source_ip",
                    "confidence": "Medium"
                }
            },
            "source_hostname": None,
            "dest_ip": {
                "value": "10.200.0.5",
                "provenance": {
                    "source_field": "dst",
                    "byte_span": [kv_raw.find("10.200.0.5"), kv_raw.find("10.200.0.5") + len("10.200.0.5")],
                    "transformations": ["inferred_kv_extractor", "ipv4_normalize"],
                    "rule_id": "inferred_rule_dest_ip",
                    "confidence": "Medium"
                }
            },
            "dest_hostname": None,
            "severity": {
                "value": "Warning",
                "provenance": {
                    "source_field": "action",
                    "byte_span": [kv_raw.find("action=DENY") + 7, kv_raw.find("action=DENY") + 11],
                    "transformations": ["deny_to_warning"],
                    "rule_id": "inferred_action_severity",
                    "confidence": "Medium"
                }
            },
            "message": {
                "value": "policy_violation",
                "provenance": {
                    "source_field": "reason",
                    "byte_span": [kv_raw.find("policy_violation"), kv_raw.find("policy_violation") + len("policy_violation")],
                    "transformations": ["string_passthrough"],
                    "rule_id": "inferred_rule_reason",
                    "confidence": "Low"
                }
            },
            "action": {
                "value": "DENY",
                "provenance": {
                    "source_field": "action",
                    "byte_span": [kv_raw.find("action=DENY") + 7, kv_raw.find("action=DENY") + 11],
                    "transformations": ["passthrough"],
                    "rule_id": "inferred_rule_action",
                    "confidence": "High"
                }
            }
        },
        ir_fields={
            "vendor": {"value_type": "String", "value": "ACME", "byte_span": [7, 11]},
            "product": {"value_type": "String", "value": "EdgeShield", "byte_span": [20, 30]},
            "action": {"value_type": "String", "value": "DENY", "byte_span": [38, 42]},
            "src": {"value_type": "String", "value": "172.16.40.12", "byte_span": [47, 59]},
            "dst": {"value_type": "String", "value": "10.200.0.5", "byte_span": [64, 74]}
        },
        inference={
            "decision": "Recognized",
            "abstention_reason": None,
            "recognized_candidate": {
                "parser_id": "generic-kv-space-eq",
                "format_name": "Generic Key-Value (Space/Equals)",
                "confidence": "High",
                "evidence": [
                    {"detector_id": "generic-kv", "description": "Matched 8 key=value pairs separated by whitespace", "supports": True},
                    {"detector_id": "cef", "description": "Missing required 'CEF:0' header prefix", "supports": False},
                    {"detector_id": "json", "description": "No opening '{' or '[' token", "supports": False},
                    {"detector_id": "syslog", "description": "No standard RFC3164/5424 timestamp prefix found", "supports": False}
                ]
            },
            "all_candidates": [
                {
                    "parser_id": "generic-kv-space-eq",
                    "format_name": "Generic Key-Value (Space/Equals)",
                    "confidence": "High",
                    "evidence": [
                        {"detector_id": "generic-kv", "description": "Matched 8 key=value pairs separated by whitespace", "supports": True},
                        {"detector_id": "entropy", "description": "Structure shows repetitive delimiter syntax pattern", "supports": True}
                    ]
                },
                {
                    "parser_id": "cef",
                    "format_name": "Common Event Format (CEF)",
                    "confidence": "Low",
                    "evidence": [
                        {"detector_id": "cef", "description": "Missing 'CEF:' signature and pipe delimiters", "supports": False}
                    ]
                },
                {
                    "parser_id": "syslog-rfc3164",
                    "format_name": "BSD Syslog RFC 3164",
                    "confidence": "Low",
                    "evidence": [
                        {"detector_id": "syslog", "description": "Timestamp parsing failed at index 0", "supports": False}
                    ]
                }
            ]
        }
    )

    # 5. Ambiguous Plain Text — Proper Abstention (Rule 4: Explicit Uncertainty)
    amb_raw = "Notice: user session was terminated unexpectedly after keepalive timeout\n"
    add_event(
        event_id="evt_unknown_005",
        source="unstructured-diagnostics",
        raw_text=amb_raw,
        parser_id=None,
        parser_outcome="Abstained",
        canonical=None,
        ir_fields={},
        inference={
            "decision": "Abstained",
            "abstention_reason": "Insufficient structural evidence across all registered detectors. Abstaining to avoid hallucinated fields.",
            "recognized_candidate": None,
            "all_candidates": [
                {
                    "parser_id": "json-flat",
                    "format_name": "JSON Document",
                    "confidence": "Low",
                    "evidence": [
                        {"detector_id": "json", "description": "Syntax does not begin with { or [", "supports": False}
                    ]
                },
                {
                    "parser_id": "cef",
                    "format_name": "Common Event Format",
                    "confidence": "Low",
                    "evidence": [
                        {"detector_id": "cef", "description": "No CEF pipe delimiters present", "supports": False}
                    ]
                },
                {
                    "parser_id": "generic-kv-space-eq",
                    "format_name": "Key-Value Pairs",
                    "confidence": "Low",
                    "evidence": [
                        {"detector_id": "generic-kv", "description": "Insufficient '=' tokens (expected >= 3, found 0)", "supports": False}
                    ]
                }
            ]
        }
    )

    # 6. Adversarial Fake Syslog Embedded in JSON
    fake_raw = '{"log":"Sep 19 12:00:00 spoofed-host auth: Root login permitted","actual_src":"10.99.1.2"}\n'
    add_event(
        event_id="evt_adversarial_006",
        source="perimeter-honeypot",
        raw_text=fake_raw,
        parser_id="json-flat",
        parser_outcome="Success",
        canonical={
            "parser_id": "json-flat",
            "timestamp": None,
            "source_ip": {
                "value": "10.99.1.2",
                "provenance": {
                    "source_field": "actual_src",
                    "byte_span": [fake_raw.find("10.99.1.2"), fake_raw.find("10.99.1.2") + len("10.99.1.2")],
                    "transformations": ["ipv4_normalize"],
                    "rule_id": "rule_json_ip",
                    "confidence": "High"
                }
            },
            "source_hostname": None,
            "dest_ip": None,
            "dest_hostname": None,
            "severity": None,
            "message": {
                "value": "Sep 19 12:00:00 spoofed-host auth: Root login permitted",
                "provenance": {
                    "source_field": "log",
                    "byte_span": [fake_raw.find("Sep 19"), fake_raw.find('","actual_src"')],
                    "transformations": ["string_passthrough"],
                    "rule_id": "rule_json_embedded_string",
                    "confidence": "Medium"
                }
            },
            "action": None
        },
        ir_fields={
            "actual_src": {"value_type": "String", "value": "10.99.1.2", "byte_span": [fake_raw.find("10.99.1.2"), fake_raw.find("10.99.1.2") + len("10.99.1.2")]},
            "log": {"value_type": "String", "value": "Sep 19 12:00:00 spoofed-host auth: Root login permitted", "byte_span": [fake_raw.find("Sep 19"), fake_raw.find('","actual_src"')]}
        },
        inference=None
    )

init_datastore()

# ─────────────────────────────────────────────────────────────────────────────
# HTTP Request Handler
# ─────────────────────────────────────────────────────────────────────────────

class UlpxHandler(http.server.BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # 1. Static Web UI routes
        if path == "/" or path == "/index.html":
            self.serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html; charset=utf-8")
            return
        elif path == "/style.css":
            self.serve_file(os.path.join(STATIC_DIR, "style.css"), "text/css; charset=utf-8")
            return
        elif path == "/app.js":
            self.serve_file(os.path.join(STATIC_DIR, "app.js"), "application/javascript; charset=utf-8")
            return

        # 2. REST API: List Events
        if path == "/api/v1/events":
            offset = int(query.get("offset", [0])[0])
            limit = int(query.get("limit", [20])[0])
            all_summaries = [
                {
                    "event_id": ev["event_id"],
                    "source": ev["source"],
                    "ingestion_timestamp": ev["ingestion_timestamp"],
                    "has_integrity": ev["integrity"] is not None
                }
                for ev in RAW_EVENTS.values()
            ]
            paginated = all_summaries[offset:offset+limit]
            self.send_json({"events": paginated})
            return

        # 3. REST API: Get Evidence
        evidence_match = re.match(r"^/api/v1/evidence/([^/]+)$", path)
        if evidence_match:
            event_id = evidence_match.group(1)
            ev = RAW_EVENTS.get(event_id)
            if ev:
                self.send_json(ev)
            else:
                self.send_error(404, f"Event {event_id} not found")
            return

        # 4. REST API: Detailed Interpretation
        interp_match = re.match(r"^/api/v1/interpretation/([^/]+)/detailed$", path)
        if interp_match:
            event_id = interp_match.group(1)
            interp = DETAILED_INTERPRETATIONS.get(event_id)
            if interp:
                self.send_json(interp)
            else:
                self.send_error(404, f"Interpretation for {event_id} not found")
            return

        # 5. REST API: Entity Resolution
        entity_match = re.match(r"^/api/v1/entity/([^/]+)/([^/]+)$", path)
        if entity_match:
            etype = entity_match.group(1).lower()
            evalue = entity_match.group(2)
            matching_ids = []
            for eid, interp in DETAILED_INTERPRETATIONS.items():
                for frame in interp.get("frames", []):
                    canon = frame.get("canonical_event") or {}
                    if etype == "ip":
                        sip = (canon.get("source_ip") or {}).get("value")
                        dip = (canon.get("dest_ip") or {}).get("value")
                        if sip == evalue or dip == evalue:
                            matching_ids.append(eid)
                    elif etype == "hostname":
                        shost = (canon.get("source_hostname") or {}).get("value")
                        dhost = (canon.get("dest_hostname") or {}).get("value")
                        if shost == evalue or dhost == evalue:
                            matching_ids.append(eid)
            self.send_json(matching_ids)
            return

        self.send_error(404, f"Not Found: {path}")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # REST API: Ephemeral Replay
        if path == "/api/v1/replay":
            content_len = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_len)
            try:
                body = json.loads(body_bytes.decode('utf-8'))
            except Exception as e:
                self.send_error(400, f"Invalid JSON body: {e}")
                return

            event_id = body.get("event_id")
            ev = RAW_EVENTS.get(event_id)
            if not ev:
                self.send_error(404, f"Event {event_id} not found")
                return

            pipe_cfg = body.get("pipeline_config", {})
            parsers = pipe_cfg.get("parser_registry", [])
            detectors = pipe_cfg.get("inference_detectors", [])

            # Generate new ephemeral interpretation
            base_interp = DETAILED_INTERPRETATIONS.get(event_id, {})
            frames = []
            for old_frame in base_interp.get("frames", []):
                new_frame = dict(old_frame)
                # If custom parsers were given and match
                if "generic-kv-space-eq" in parsers and event_id == "evt_unseen_kv_004":
                    new_frame["parser_id"] = "generic-kv-space-eq (Promoted)"
                    new_frame["parser_outcome"] = "Success (Validated Parser)"
                    new_frame["inference_decision"] = None
                frames.append(new_frame)

            replayed = {
                "interpretation_id": f"replay_{event_id}_{int(time.time() * 1000)}",
                "source_event_id": event_id,
                "pipeline_config_identity": f"reprocessed_{pipe_cfg.get('framer_id', 'NewlineFramer')}_parsers_{len(parsers)}",
                "created_at_secs": int(time.time()),
                "integrity_verified": True,
                "integrity_error": None,
                "trailing_frame_error": None,
                "frames": frames
            }
            self.send_json(replayed)
            return

        self.send_error(404, f"Not Found: {path}")

    def serve_file(self, filepath, content_type):
        if not os.path.exists(filepath):
            self.send_error(404, f"File {os.path.basename(filepath)} not found")
            return
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Error reading file: {e}")

    def send_json(self, data):
        body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run():
    # Allow socket reuse to avoid 'Address already in use' errors
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), UlpxHandler) as httpd:
        print(f"==================================================")
        print(f" ULPX Analyst UI Prototype Server Running")
        print(f" Serving on: http://127.0.0.1:{PORT}")
        print(f" Loaded {len(RAW_EVENTS)} events with cryptographic hashes")
        print(f" Static files: {STATIC_DIR}")
        print(f"==================================================")
        sys.stdout.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down prototype server...")
            httpd.shutdown()

if __name__ == "__main__":
    run()
