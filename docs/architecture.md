# Architecture and beginner guide

## IDS concepts

- **Network traffic** is communication observed between devices. A **packet** is one unit of that communication.
- A **network flow** is a summary of related packets, usually grouped by source, destination, ports, protocol, and time.
- A **security event** is an observation; an **alert** is a detection that needs review; an **incident** is a set of related alerts handled as one investigation.
- A **network IDS (NIDS)** monitors network-level observations. A **host IDS (HIDS)** monitors activity on one endpoint. This project simulates a network-based hybrid IDS using flow records.
- An IDS detects and alerts. An IPS may take automatic preventive action. This app intentionally does not block or disrupt traffic.

### Detection methods

Signature rules look for configured conditions, such as a high failed-connection ratio or unusual port diversity. They are explainable and fast, but do not cover every possible pattern.

Anomaly detection compares a record's rate and ratio features with a normal baseline. It can surface previously unlisted behavior, but the baseline and workload context matter. A legitimate backup can look unusual. A hybrid combines both signals and leaves the disposition to a human analyst.

## Processing flow

```text
Synthetic flow records
          ↓
Input validation and feature extraction
          ↓
Configurable signature rules + statistical baseline
          ↓
Risk score, classification, and severity
          ↓
Alert persistence and basic source/rule correlation
          ↓
SOC dashboard, analyst notes, and disposition
```

The browser requests batches through the API. The API generates ordinary JSON-shaped records; it does not open sockets. PostgreSQL stores records between reloads. The Python package provides a separate offline teaching implementation and CSV/JSON generators.

## Feature glossary

| Feature | Meaning | Why an analyst might care |
| --- | --- | --- |
| `packet_count` | Packets represented by a flow | Volume and behavior context |
| `byte_count` | Bytes represented by a flow | Helps identify unusually large transfers |
| `duration_seconds` | Flow time span | Used to normalize rates |
| `bytes_per_second` | Bytes divided by duration | Highlights a sudden volume increase |
| `packets_per_second` | Packets divided by duration | Highlights a packet-rate deviation |
| `connection_rate` | Connections divided by duration | Highlights concentrated connection activity |
| `failed_connection_count` | Failed attempts represented in the record | Context for repeated failures |
| `failure_ratio` | Failed attempts divided by connections | Normalizes failures across different flow sizes |
| `syn_count` and `syn_ratio` | SYN count and SYNs divided by packets | Describes a SYN-heavy statistical pattern |
| `unique_destination_ports` | Port diversity represented by the synthetic record | Can indicate a multi-port pattern for triage |
| `unique_destination_ips` | Destination diversity represented by the synthetic record | Shows whether one or many destinations are represented |

Zero duration uses a small denominator guard during feature extraction. Required fields, addresses, ports, protocol, and counts are validated by the Python engine. The API's generated Zod schemas validate all external request bodies and parameters.

## Rules, anomaly scoring, and risk

The editable rules are `IDS-001` through `IDS-007`: connection rate, failures, port diversity, SYN ratio, unusual service port, byte volume, and anomaly threshold. A match is evidence to examine, not proof of attack.

The anomaly score is a bounded 0–100 score based on positive z-score deviations. The baseline uses normal synthetic records when enough samples are present; otherwise it uses fixed documented educational defaults. The hybrid risk score weights rule severity at 70% and anomaly score at 30%.

Risk categories are `NORMAL` 0–20, `SUSPICIOUS` 21–60, and `POTENTIAL_INTRUSION` 61–100. Severity is `INFO` through `CRITICAL` on five bands. These thresholds are training assumptions, not a validated SOC policy.

## Database relationships

```text
network_flows 1 ─── * ids_alerts 1 ─── * incident_notes
detection_rules (editable detector configuration)
```

An alert references the flow it explains. Notes belong to an alert. Rule IDs are stored with the flow and alert to preserve the detection explanation. No payload content is stored.

## API contract summary

The API contract is maintained in `lib/api-spec/openapi.yaml`. Client hooks and server validators are generated from that source.

| Endpoint | Description |
| --- | --- |
| `GET /api/dashboard/stats` | Counts, average risk, open and critical alerts |
| `GET /api/dashboard/traffic` | Traffic timeline and top breakdowns |
| `GET /api/flows` | Recent flow records with optional classification filter |
| `GET /api/alerts` | Recent alerts with severity and status filters |
| `GET /api/alerts/{id}` | Alert, flow, investigation checklist, and notes |
| `PATCH /api/alerts/{id}/status` | Analyst status/resolution update |
| `POST /api/alerts/{id}/notes` | Add a bounded-length analyst note |
| `POST /api/simulation/generate` | Generate and store 1–100 synthetic records |
| `GET /api/rules` | Read editable detection rules |
| `PATCH /api/rules/{id}` | Change a rule threshold or enabled state |

Invalid inputs receive HTTP 400, missing records receive 404, and successful writes return the updated object or created record.

## Run a safe walkthrough

1. Start the API Server and Network IDS Simulation workflows.
2. Generate a small normal batch from the dashboard and inspect its flow list.
3. Generate a suspicious batch or choose “Multi-port probing-like pattern”. This creates records, not network traffic.
4. Open a resulting alert. Compare its named rule, anomaly score, risk score, source and destination fields, and suggested investigation steps.
5. Add a note and move the status to `INVESTIGATING`, then `RESOLVED` or `FALSE_POSITIVE`.
6. Change a rule threshold and generate another batch to observe how tuning changes subsequent detections.
7. Run `python3 -m unittest tests.test_ids_engine -v` to exercise the offline engine and generator.

## SOC workflow and interpretation

Tier 1 SOC work commonly includes validating alert context, checking related logs, comparing behavior to a known baseline, documenting findings, and escalating or resolving according to team procedure. In a real organization, the analyst would consult authorized firewall, authentication, endpoint, asset, and change-management context.

An anomaly should not automatically be mapped to a MITRE ATT&CK technique. Mapping requires sufficient evidence and documented rationale. The alert queue can download a filtered set as ECS-inspired JSON for an offline SIEM exercise; it does not forward the data to a SIEM. See [`mitre-attack.md`](mitre-attack.md) for candidate references and mapping limits.

## Logs, metrics, and traces

Event logs preserve what happened and when, which supports alert review and incident timelines. Metrics summarize rates and system health, helping an operator spot ingestion gaps, rising alert volume, or a failing service. Traces connect a request across UI, API, and database components to help locate latency or errors. A distributed SOC should normalize timestamps, retain stable event identifiers, protect log access, and correlate security telemetry with application health. This training app logs API requests and stores synthetic flow/alert records; it is not a full observability or log-management platform.

## Security boundaries and known limits

- Only RFC documentation ranges are generated by the Python dataset tool and web-service simulator.
- The application generates data objects, not traffic packets; there is no scanner, exploit, DDoS, credential harvesting, or blocking capability.
- This educational app does not include analyst authentication, authorization, or production audit controls. Keep access limited to the project owner until those controls exist.
- Synthetic labels and thresholds are designed for demonstrating software behavior. They cannot establish real-world effectiveness.
- The statistical baseline can produce false positives and false negatives; analyst judgment and calibration are necessary.