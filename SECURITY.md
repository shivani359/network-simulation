# Security policy

## Project scope

This is an educational IDS simulation, not a production security product. It generates synthetic records and does not send packets or connect to monitored addresses.

## Reporting a concern

Please do not publish credentials, private network telemetry, personal information, or detailed exploit instructions in a public issue. If GitHub private vulnerability reporting is enabled for the repository, use that channel. Otherwise contact the repository owner privately through a channel listed on the repository profile.

Include the affected version or commit, a concise impact description, and safe reproduction steps. Use synthetic or isolated test data only.

## Deployment guidance

The initial dashboard has no analyst authentication or authorization. Restrict access to the project. Before adapting it for real security workflows, add authenticated access, role checks, secure transport, rate limiting, audit logging, data retention controls, and review by the organization's security and privacy owners.

Do not use this project to scan, exploit, disrupt, or monitor systems without explicit authorization.