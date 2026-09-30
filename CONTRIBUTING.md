# Contributing

Thank you for helping improve this defensive learning project.

## Safety scope

- Keep all generated suspicious behavior as synthetic records.
- Do not add code that sends traffic, scans systems, exploits services, collects credentials, or blocks real connections.
- Use reserved documentation IPs for examples.
- Do not submit private network captures, customer data, credentials, or other sensitive information.

## Before opening a pull request

1. Describe the learning or defensive outcome and the change's limitations.
2. Run `pnpm run typecheck`.
3. Run `python3 -m unittest tests.test_ids_engine -v`.
4. If the OpenAPI spec changes, regenerate clients with `pnpm --filter @workspace/api-spec run codegen`.
5. If the database schema changes, review the migration impact and use the development database only.
6. Update documentation and tests for changed detection behavior. Never claim real-world detection performance from synthetic results.

Small focused pull requests are easier to review. Include screenshots for dashboard changes and note any new environment requirements.

## Issues and review

Use GitHub issues for reproducible bugs, documentation gaps, and scoped feature proposals. Include expected behavior, observed behavior, steps to reproduce, and whether the example data is synthetic. A maintainer should review security-sensitive changes and changes that affect data retention or access control before merge.

## Licensing

No license is declared by this project yet. The repository owner should select and add an appropriate license before inviting reuse or accepting external contributions.