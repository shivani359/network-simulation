# MITRE ATT&CK reference and mapping limits

This document helps learners distinguish a detection clue from an ATT&CK technique assignment. ATT&CK describes adversary behavior; this application generates synthetic flow summaries. None of its records proves that an adversary performed a technique.

## Candidate references

| Synthetic pattern | ATT&CK reference to review | Evidence needed before mapping |
| --- | --- | --- |
| Multi-destination-port pattern | [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Authorized telemetry showing discovery activity, target context, and an investigative finding. A synthetic diversity count alone is not enough. |
| Repeated failed attempts | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Authentication records showing repeated credential attempts. This project stores failed-connection counts, not login or password events, so it does not assign T1110. |
| High connection rate or SYN-heavy pattern | [T1498 — Network Denial of Service](https://attack.mitre.org/techniques/T1498/) | Evidence of availability impact and supporting network/service telemetry. A high rate or SYN ratio alone does not establish a denial-of-service technique. |
| High byte volume or unusual port | No technique assigned by default | Transfer direction, endpoint context, application, authorization, and corroborating data would be needed to make a meaningful assessment. |

These references are investigation prompts, not automatic tags. Consult the linked ATT&CK technique pages for current descriptions and relationships. A real SOC should follow its own documented mapping procedure and preserve the analyst's rationale.

The official pages were checked on 2026-09-30. ATT&CK content and versioning can change; revisit the current technique pages when updating a mapping.

## SIEM event handling

The dashboard JSON export uses an ECS-inspired nested structure to make the fields recognizable in SIEM ingestion exercises. It identifies the event as synthetic and sets the ATT&CK mapping status to `not_assigned`. The export is downloaded in the browser and is not forwarded automatically.