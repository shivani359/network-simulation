# Community and project governance

## Project status

This is a beginner-friendly demonstration and a starter for defensive security learning. It is not a production IDS, a managed monitoring service, or a claim of validated detection performance.

## Maintainer responsibilities

- Keep the synthetic-only safety boundary explicit in code, examples, and screenshots.
- Review detection changes for explainability, false-positive tradeoffs, test coverage, and documentation.
- Require explicit review before changing data-retention behavior, access controls, or external integrations.
- Avoid publishing user telemetry, secrets, credentials, or private security details.
- Record material architecture or threshold changes in the project documentation.

## Contribution process

1. Open an issue describing the defensive learning goal and a small proposed scope.
2. Keep work in a short-lived branch and submit a focused pull request.
3. Include tests and update the README or architecture guide when behavior changes.
4. Run the TypeScript workspace typecheck and Python test suite.
5. Include a dashboard screenshot for visible interface changes.
6. Wait for maintainer review before merging.

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`SECURITY.md`](../SECURITY.md) for contribution and disclosure guidance.

## Community safety

Do not submit requests or code for unauthorized scanning, exploitation, traffic disruption, credential collection, or automatic blocking. Keep sample addresses in reserved documentation ranges and use only synthetic data in public examples. Security reports should avoid public disclosure of secrets or sensitive telemetry.

## Licensing

The project does not choose a license on behalf of its owner. Add a license before describing the repository as open source or inviting reuse under particular terms.