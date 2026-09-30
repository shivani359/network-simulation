# Network Intrusion Detection System (IDS) Simulation

A defensive, data-only learning project for exploring network-flow monitoring, explainable detection rules, statistical anomaly scoring, alert triage, and SOC-style investigation.

> **Ethical scope:** This project is designed exclusively for defensive cybersecurity education. All suspicious network behavior is represented using synthetic data or authorized isolated lab environments. The simulator creates records only: it does not send packets, scan hosts, contact IP addresses, exploit systems, or block traffic.

## What this project does

- Creates normal and suspicious synthetic flow records using only the reserved documentation networks `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- Includes a 5,000-row CSV at `data/network_traffic.csv` and a reproducible generator.
- Extracts rate, ratio, and destination-diversity features, with zero-duration and missing-value safeguards.
- Applies configurable signature rules plus a statistical baseline anomaly score.
- Combines detection outputs into a 0–100 risk score, a classification, and alert severity.
- Stores flows, alerts, configurable rules, and analyst notes in PostgreSQL.
- Provides a SOC dashboard, traffic analytics, filterable flow and alert queues, alert investigation, status updates, and analyst notes.
- Runs a data-only simulator from the dashboard or the standalone Python command line.
- Includes 40 standard-library automated tests and an optional supervised ML evaluation script.

This is an educational simulation, not a production IDS, IPS, packet collector, or security product. A match is a reason to investigate, not proof of malicious activity.

## Architecture

```text
Synthetic flow generator ──> Feature extraction ──> Signature rules
          │                           │             Anomaly baseline
          │                           └──────┬──────┘
          │                                  ↓
          └──> CSV / simulation API ──> Risk score ──> Alerts & correlation
                                                   ↓
                                      PostgreSQL event store
                                                   ↓
                          SOC dashboard ──> analyst notes / disposition
```

The web app uses React, Vite, and TypeScript. The shared API uses Express and Drizzle ORM. The standalone generator and IDS toolkit use only the Python standard library. Dashboard charts are calculated from stored synthetic records.

## Repository map

```text
artifacts/network-ids/       React dashboard
artifacts/api-server/        Express API and TypeScript detection engine
lib/api-spec/openapi.yaml    API contract source
lib/db/src/schema/           PostgreSQL flow, alert, note, and rule tables
ids/network_ids.py           Standalone defensive analysis engine
simulator/                   CSV generator and JSON record simulator
ml/train_model.py            Optional supervised evaluation
data/network_traffic.csv     Generated 5,000-row synthetic dataset
tests/test_ids_engine.py     40 standard-library tests
docs/                        Architecture, report, and interview preparation
```

## Run in Replit

The project has managed API and dashboard services. Start the `API Server` and `Network IDS Simulation` workflows. The first dashboard request seeds an empty database with synthetic examples and default detection rules. The database schema is managed by the workspace:

```bash
pnpm --filter @workspace/db run push
pnpm --filter @workspace/api-spec run codegen
pnpm run typecheck
```

## Run the Python tools

No mandatory third-party Python packages are required:

```bash
# Regenerate 5,000 synthetic flows using the fixed seed
python3 -m simulator.generate_dataset --rows 5000 --seed 2026 --output data/network_traffic.csv

# Print 10 synthetic flow records as JSON; no packets are sent
python3 -m simulator.traffic_simulator --mode mixed --speed fast --count 10

# Run the automated unit tests
python3 -m unittest tests.test_ids_engine -v
```

Simulator modes are `normal`, `mixed`, and `suspicious`. Speeds are `slow` and `fast`. If `--count` is omitted or set to `0`, the JSON simulator continues until interrupted.

## Use the dashboard

1. Open the dashboard at the project preview.
2. Generate a normal, mixed, or suspicious batch. Individual examples include high connection rate, repeated failures, multi-port pattern, SYN-heavy pattern, unusual service port, and high volume.
3. Review the flow classification, matched rules, risk score, and alert queue.
4. Open an alert, review the related flow and investigation suggestions, add an analyst note, and set the status to `INVESTIGATING`, `RESOLVED`, or `FALSE_POSITIVE`.
5. Open the rules page to enable or tune the detection thresholds.

The application uses polling for dashboard freshness. The standalone Python simulator prints records to its terminal; it does not post them to the app. Use the dashboard controls to persist generated flows into the database.

## Detection and risk model

The active rule set includes high connection rate, repeated failed connections, destination-port diversity, SYN-heavy behavior, unusual service-port activity, high byte volume, and statistical baseline deviation. Thresholds are project assumptions exposed in the rules UI.

Features include packet and byte rate, connection rate, failed-connection ratio, SYN ratio, and unique destination IP/port counts. The anomaly detector compares positive z-score deviations with a baseline built from normal synthetic flows, or uses documented defaults when the baseline is too small.

The hybrid score uses a 70% rule-severity component and 30% anomaly score. The dashboard classifies scores as `NORMAL` (0–20), `SUSPICIOUS` (21–60), or `POTENTIAL_INTRUSION` (61–100). Severity bands are `INFO`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`. These values are explainable training assumptions and must be calibrated against authorized data before any real SOC use.

### Signature versus anomaly detection

| Method | Strength | Limitation |
| --- | --- | --- |
| Signature / rules | Fast, explainable detection of known patterns | Can miss behavior not represented in its rules |
| Statistical anomaly | Can flag deviations not covered by a named rule | Baseline quality matters; unusual legitimate workloads can create false positives |
| Hybrid | Combines specific evidence and broad deviations | Still requires tuning and analyst context |

## Optional machine learning

The ML script uses a stratified training/test split, a random forest, and calculates accuracy, precision, recall, F1, and a confusion matrix from the CSV. It prints actual metrics when run; this README does not claim a model score.

```bash
python3 -m pip install -r requirements-ml.txt
python3 -m ml.train_model --input data/network_traffic.csv
```

This tests separation in synthetic data only. Synthetic hold-out metrics are not evidence of production detection performance, and accuracy alone can hide poor detection of the suspicious class.

## REST API

The API is served under `/api`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/healthz` | Health check |
| GET | `/api/dashboard/stats` | Flow and alert totals |
| GET | `/api/dashboard/traffic` | Timeline and traffic breakdowns |
| GET | `/api/flows?limit=100&classification=NORMAL` | Recent flow records |
| GET | `/api/alerts?limit=100&severity=HIGH&status=NEW` | Alert queue and filters |
| GET | `/api/alerts/{alertId}` | Alert, related flow, notes, investigation steps |
| PATCH | `/api/alerts/{alertId}/status` | Update analyst disposition |
| POST | `/api/alerts/{alertId}/notes` | Add an analyst note |
| POST | `/api/simulation/generate` | Generate and store a batch of synthetic records |
| GET | `/api/rules` | List configurable detection rules |
| PATCH | `/api/rules/{ruleId}` | Enable/disable a rule or set its threshold |

All request bodies, query parameters, and successful responses are validated with schemas generated from `lib/api-spec/openapi.yaml`. The simulation endpoint accepts at most 100 records per request.

### SIEM-style JSON export

The alert queue's **Export JSON** button downloads the currently loaded and filtered alert records in a nested, ECS-inspired JSON envelope. It includes event time, kind/category/severity/risk, rule, source/destination, protocol, triage status, and an explicit synthetic-data label. MITRE ATT&CK mapping remains `not_assigned`; do not infer a technique from an isolated synthetic pattern. The download is local and does not forward data to an external SIEM.

## Database

- `network_flows` stores flow metadata, extracted classification, scores, and matched rule IDs.
- `ids_alerts` stores detections and analyst disposition; each alert references a flow.
- `incident_notes` stores the investigation notes associated with an alert.
- `detection_rules` stores editable rule enablement and thresholds.

Flow and alert timestamps, classification, source, severity, and status are indexed for the dashboard's common queries. No packet payloads are collected or stored.

## SOC workflow

```text
Synthetic event → detection → alert queue → triage → investigate context
                → escalate / resolve / false positive → document
```

An event is an observation; an alert is a detection needing attention; an incident is a collection of related alerts that warrants coordinated investigation. The app groups related synthetic observations in the Python correlation helper by source, rule, and time window. It does not automatically block traffic.

## Security, privacy, and limitations

- The example addresses are reserved for documentation and must not be mistaken for monitored production assets.
- The app stores flow metadata, not packet contents. Real IDS logs can still reveal internal addresses, services, and business activity.
- This learning build has no analyst authentication or authorization layer. Restrict access to the Replit project; add identity, role checks, API rate limits, secure transport, and audit controls before exposing a real security dashboard.
- The browser does not directly connect to any IP address. No packet capture, external network scan, exploit, denial-of-service, credential collection, or automatic blocking feature exists.
- Thresholds and synthetic distributions are illustrative. False positives and false negatives are expected; analyst review is part of the workflow.
- MITRE ATT&CK mapping and SIEM forwarding are documented as future integration concepts, not automatic claims about these synthetic anomalies.

## Tests

Run:

```bash
python3 -m unittest tests.test_ids_engine -v
```

The suite covers 40 cases across flow validation, malformed inputs, zero-duration feature handling, rules, anomaly/risk bounds, alert creation, correlation, dataset reproducibility, reserved IPs, and CSV output. Database/API persistence is separately exercised through the running service.

## Results and reproducibility

The committed CSV is generated with seed `2026` and contains 5,000 flow rows plus its header. Generate it again with the command above. The CSV UUIDs and timestamps are regenerated on each run; the scenario mix and numeric pattern distribution use the fixed seed.

## GitHub strategy

Suggested repository name: `Network-Intrusion-Detection-System-Simulation`

Description: “Defensive network intrusion detection simulation featuring synthetic traffic generation, signature-based and anomaly-based detection, risk scoring, alert correlation, SOC analytics, and optional machine learning.”

Suggested topics: `cybersecurity`, `intrusion-detection`, `ids`, `network-security`, `soc`, `python`, `anomaly-detection`, `machine-learning`, `security-analytics`, `threat-detection`, `defensive-security`.

Example first upload commands (review the destination before pushing):

```bash
git init
git add README.md docs ids simulator ml tests data requirements.txt requirements-ml.txt .gitignore
git commit -m "Initialize network IDS simulation"
git branch -M main
git remote add origin https://github.com/<your-account>/Network-Intrusion-Detection-System-Simulation.git
git push -u origin main
```

Suggested follow-up commits: “Add synthetic traffic dataset generator”, “Implement signature detection rules”, “Add anomaly detection engine”, “Build SOC dashboard”, “Implement incident investigation workflow”, and “Add automated tests”.

Contribution expectations and repository governance are documented in [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and [`docs/community-and-governance.md`](docs/community-and-governance.md). Read-only SQL examples are in [`docs/sql-examples.sql`](docs/sql-examples.sql). No open-source license is selected; the repository owner should choose one before inviting reuse.

## Screenshot checklist

Recommended filenames if you capture screenshots for a report or repository:

1. `01-dashboard-overview.png`
2. `02-synthetic-dataset-preview.png`
3. `03-normal-vs-suspicious-flows.png`
4. `04-detection-rules.png`
5. `05-alert-queue.png`
6. `06-alert-investigation.png`
7. `07-analyst-notes-and-disposition.png`
8. `08-traffic-analytics.png`
9. `09-automated-tests.png`
10. `10-ml-evaluation.png` (only after running the optional evaluation)

## Project report, career summary, and interview preparation

- Architecture and implementation details: [`docs/architecture.md`](docs/architecture.md)
- Course-style project report: [`docs/project-report.md`](docs/project-report.md)
- Resume, LinkedIn, and exactly ten interview Q&As: [`docs/career-and-interview.md`](docs/career-and-interview.md)
- Cautious ATT&CK candidate mapping guide: [`docs/mitre-attack.md`](docs/mitre-attack.md)

## Future defensive improvements

With authorization and data-governance review: import authorized PCAP-derived flow summaries, integrate Zeek or Suricata alerts, forward normalized JSON to a SIEM, enrich detections with approved threat-intelligence sources, correlate identities and events, tune behavior baselines, monitor model drift, and add authenticated access and an audit trail. Do not use this simulation to scan or attack public or third-party systems.