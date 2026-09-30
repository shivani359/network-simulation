# Network Intrusion Detection System (IDS) Simulation

## Abstract

This project implements a defensive, educational network intrusion detection simulation. It generates synthetic flow records using reserved documentation IP ranges, extracts flow features, applies configurable signature rules and statistical anomaly scoring, combines the signals into a risk score, and presents resulting alerts in a SOC-style dashboard. Analysts can inspect related flow data, add notes, and record a disposition. The simulator creates only data records and never sends packets or interacts with external networks.

## Introduction and problem statement

Security teams need a way to review network behavior and prioritize events for investigation. A course project may not have access to a production network or safe packet-capture data. The problem addressed here is how to demonstrate flow analysis and alert triage in a repeatable, safe environment without relying on real network infrastructure.

## Objectives

1. Generate normal and suspicious synthetic flow records.
2. Validate IP addresses, ports, protocols, and numeric counters.
3. Extract network-rate, ratio, and diversity features.
4. Detect representative behavior with configurable rules and a statistical baseline.
5. Assign classifications, severity, and risk scores.
6. Persist flows, rules, alerts, and analyst notes.
7. Present overview metrics, analytics, queues, and incident investigation controls.
8. Provide reproducible tests, documentation, and optional ML evaluation.

## Development lifecycle

The implementation follows a small software-development lifecycle: define the defensive/synthetic safety boundary and endpoint requirements; design the OpenAPI contract and relational flow/alert/note/rule schema; implement generators, rules, API, and UI; validate with automated tests and live endpoint checks; then document run, deployment, privacy, and tuning limits. Future maintenance should review thresholds, schema changes, dependencies, access controls, and dataset assumptions.

## Background

An IDS detects and reports potentially suspicious activity; an IPS may also take preventive action. This system intentionally behaves only as an IDS simulation. It processes network-flow summaries, not packet contents. Signature-based detection tests known conditions. Anomaly-based detection identifies statistical deviations from a normal baseline. A hybrid system can combine the two while preserving analyst review.

## Proposed architecture

```text
Synthetic generator → validation / features → rule engine + anomaly scoring
                    → hybrid risk score → alert generation / storage
                    → SOC dashboard → analyst investigation and notes
```

The UI is React/Vite. The API uses Express, OpenAPI-generated validation, and Drizzle/PostgreSQL. A separate Python package demonstrates the generator and IDS functions offline.

## Dataset and simulation

`data/network_traffic.csv` contains 5,000 generated flow rows using the documentation-only IPv4 ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`. Scenarios include normal web, DNS, SSH, email, and database flow summaries plus synthetic high connection rate, repeated failures, multi-port patterns, SYN-heavy patterns, unusual service ports, and high traffic volume.

The dataset is reproducible with seed `2026` for its scenario mix and numeric patterns. UUIDs and timestamps vary per run. No traffic is sent.

## Feature engineering and detection

The engine calculates bytes/sec, packets/sec, connections/sec, failed-connection ratio, SYN ratio, and destination diversity. It guards division by zero and rejects invalid flow records.

Seven example rules describe connection-rate, failure-ratio, port-diversity, SYN-ratio, service-port, volume, and baseline-deviation patterns. The anomaly detector compares positive z-score deviations to a baseline built from normal synthetic flows, falling back to documented defaults when there are too few examples.

The score is the weighted combination `0.70 × rule severity + 0.30 × anomaly score`, clamped to 0–100. Classification bands are project assumptions: normal 0–20, suspicious 21–60, and potential intrusion 61–100. Severity bands are info, low, medium, high, and critical. A rule match or high score is an investigation lead, not proof of malicious behavior.

## Database and investigation

PostgreSQL stores network flows, alerts, detection rules, and incident notes. An alert references its source flow. Analysts can change status among `NEW`, `INVESTIGATING`, `RESOLVED`, and `FALSE_POSITIVE`, add notes, and review defensive investigation suggestions.

## Testing

The standalone suite contains 40 tests and runs with Python's standard library:

```bash
python3 -m unittest tests.test_ids_engine -v
```

It covers valid and malformed records, documentation IP restrictions, ports and protocol, missing/negative values, zero-duration safeguards, rates and ratios, baseline behavior, each principal rule, anomaly and risk bounds, alert output, correlation, dataset reproducibility, and CSV output. The test command was run successfully during implementation; all 40 tests passed.

## Results and evaluation

The project includes a 5,000-row generated CSV and a working web workflow for generating and investigating further records. The optional `ml/train_model.py` trains a random forest and computes held-out accuracy, precision, recall, F1, and confusion matrix from the supplied labels when its optional dependency is installed. No ML score is asserted in this report; synthetic results must not be represented as production detection performance.

## False positives, false negatives, and limitations

A false positive occurs when expected activity is flagged; for example, an authorized bulk transfer may cross a volume threshold. A false negative occurs when suspicious behavior does not trigger an active condition. Inaccurate baselines, coarse flow aggregation, limited features, and synthetic distributions make both possible.

The project has no packet payload inspection, live sensor, analyst authentication, role-based authorization, threat-intelligence feed, or production SIEM integration. It intentionally does not block traffic. Thresholds require authorized data and expert calibration before operational use.

## Privacy and ethical use

IDS data may expose internal addresses, service use, and business patterns even without payloads. This project stores only synthetic flow metadata and analyst notes. Do not use it to monitor a network without authorization. Restrict access to the dashboard; a production deployment would require authentication, authorization, encryption, rate limits, audit logging, and a retention policy.

## Future scope

Potential defensive extensions include authorized PCAP-to-flow ingestion, Zeek or Suricata event import, SIEM forwarding, approved threat-intelligence enrichment, improved behavior baselines, rule tuning, analyst feedback, model-drift monitoring, and production identity/audit controls. Each extension requires explicit authorization and data governance.

## Conclusion

The project demonstrates a safe end-to-end IDS workflow: synthetic data creation, validation, feature extraction, explainable hybrid detections, persistence, dashboard analytics, and analyst triage. Its strongest educational value is in showing how detection signals support investigation—not in claiming that synthetic scores prove real attacks.