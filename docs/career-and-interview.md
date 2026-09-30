# Career summary and interview preparation

## Resume bullets

- Built a defensive IDS simulation that generates synthetic network-flow data and applies configurable signature rules plus statistical anomaly scoring to prioritize investigation.
- Implemented an Express/PostgreSQL alert workflow and SOC dashboard for traffic analytics, severity filtering, alert investigation, notes, status disposition, and rule tuning.
- Added a reserved-IP-only dataset generator, an offline Python detection engine, and 40 automated tests covering validation, feature extraction, detection, risk scoring, alert correlation, and CSV output.

Only claim activities you can demonstrate. Optional ML metrics are computed by the script when run; do not add unmeasured numbers to a resume.

## Two-line project description

A safe, data-only network intrusion detection simulation that generates synthetic flow records and applies explainable signature and anomaly-based detection.  
Includes risk scoring, alert investigation, analyst notes, PostgreSQL persistence, dashboard analytics, a Python toolkit, and 40 automated tests.

## LinkedIn project description

Built a defensive Network Intrusion Detection System (IDS) Simulation to practice flow analysis and SOC alert triage without interacting with real networks. The system generates synthetic records on documentation-only IP ranges, extracts network-rate and ratio features, applies configurable signature rules and statistical anomaly scoring, then stores and visualizes detections in a web dashboard. Analysts can review related flow context, add notes, tune thresholds, and document whether an alert is still under investigation, resolved, or a false positive. The project also includes a reproducible CSV generator, an offline Python engine, and 40 standard-library tests. Scores are educational signals, not proof of malicious activity.

## Skills demonstrated

Network security, IDS fundamentals, flow analysis, feature engineering, signature detection, anomaly detection, Python, TypeScript, API design, PostgreSQL, data validation, alert triage, SOC workflow, incident documentation, testing, and defensive security.

## Interview questions and answers

### 1. Explain your project.

I built a defensive IDS simulation that works with synthetic network-flow records rather than live packets. It validates and enriches each record, checks configurable rules, compares features with a normal baseline, combines those signals into a risk score, and stores alerts for an analyst to investigate. The dashboard supports filtering, notes, status changes, traffic analytics, and rule tuning. The goal is to demonstrate an end-to-end SOC workflow safely, not to claim that an anomaly proves an attack.

### 2. What is the difference between an IDS and an IPS?

An IDS monitors activity and reports possible suspicious behavior. An IPS can also take preventive action, such as dropping traffic. I kept this project as an IDS because automatic blocking based on simple student-project thresholds could disrupt legitimate activity and is not needed to demonstrate detection or triage.

### 3. How do signature-based and anomaly-based detection differ?

Signature rules check for known, explicit patterns, such as a configured connection-rate threshold. They are quick and explainable but only cover the behaviors represented in the rules. Anomaly detection compares observations with a baseline and may find unlisted deviations, but it can flag legitimate changes. This project combines them and exposes the reasons so an analyst can review the result.

### 4. Which features did you extract, and why?

I used packet and byte volume, duration, bytes and packets per second, connection rate, failed-connection ratio, SYN ratio, and destination diversity. Rates normalize activity by time; ratios help compare flows of different sizes; destination diversity represents patterns such as activity across many ports. The demo also guards zero duration and validates malformed records.

### 5. How is anomaly detection implemented?

The engine calculates positive z-score deviations for selected flow features against a baseline of records labeled normal. It combines those deviations into a bounded score from 0 to 100. If there are not enough normal examples, it uses documented training defaults. This is intentionally simple and explainable; an operational baseline would need authorized representative data and tuning.

### 6. How do you calculate risk and severity?

The sample risk score weights rule severity at 70% and anomaly score at 30%, then clamps the result to 0–100. Project-defined bands map that score to a classification and one of five severity levels. These are transparent demonstration thresholds, not a universal SOC standard, so I would calibrate them with analysts and authorized data before operational use.

### 7. What does a rule match mean?

A rule match means the observed synthetic record met a configured condition. It is not proof that an intrusion occurred. I would validate the source and destination context, compare related logs and baseline behavior, check for expected changes, and document a disposition before escalating or resolving it.

### 8. Why include optional machine learning, and what metrics matter?

The optional random-forest script demonstrates supervised classification on generated labels and calculates a held-out confusion matrix, precision, recall, F1, and accuracy. Accuracy alone can hide a model that misses the suspicious class, so precision and recall are also useful. Results from synthetic data do not predict production performance, and I do not quote a score unless I have run and documented that evaluation.

### 9. What are false positives and false negatives?

A false positive is legitimate activity flagged as suspicious, such as an expected backup exceeding a volume threshold. A false negative is suspicious activity classified as normal. Both matter: too many false positives increase alert fatigue, while false negatives can leave behavior unnoticed. Better baselines, contextual data, rule tuning, multiple detection methods, and analyst feedback can help.

### 10. How would an analyst investigate one of your alerts?

I would review the matched rule and related flow fields, confirm the time and asset context, compare the behavior with a historical baseline, and consult authorized authentication, firewall, application, or endpoint records if available. I would determine whether the activity was expected, add notes, and resolve, mark false positive, or escalate according to procedure. I would not infer a specific MITRE ATT&CK technique from a statistical anomaly alone.