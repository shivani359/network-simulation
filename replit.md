# Network IDS Simulation

A defensive cybersecurity learning app that generates synthetic network-flow records, detects suspicious patterns, and supports SOC-style alert investigation without sending network traffic.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm --filter @workspace/network-ids run dev` — run the IDS dashboard
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string
- `python3 -m unittest tests.test_ids_engine -v` — run the 40 standard-library Python tests
- `python3 -m simulator.generate_dataset --rows 5000 --seed 2026 --output data/network_traffic.csv` — regenerate the sample CSV

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/network-ids/` — React SOC dashboard
- `artifacts/api-server/src/routes/ids.ts` — REST API handlers
- `artifacts/api-server/src/lib/ids.ts` — TypeScript synthetic generator and detector
- `lib/api-spec/openapi.yaml` — API contract source of truth
- `lib/db/src/schema/` — flows, alerts, rules, and incident-note tables
- `ids/network_ids.py` and `simulator/` — offline Python engine and synthetic data tools
- `data/network_traffic.csv` — 5,000 synthetic flow records
- `docs/` — architecture, report, and career/interview guide

## Architecture decisions

- Suspicious activity is represented as synthetic flow records only; the app has no packet sender, scanner, or blocking feature.
- Reserved documentation IP ranges are used to avoid implying real hosts are being monitored.
- PostgreSQL stores flow metadata and investigation notes; packet payloads are never collected.
- The hybrid score is an explainable teaching assumption (70% signature severity, 30% anomaly score), not a production policy.
- The Python generator and tests use the standard library; optional ML dependencies are isolated in `requirements-ml.txt`.

## Product

The dashboard summarizes flows and alerts, plots traffic analytics, generates synthetic batches, filters flows/alerts, shows per-alert flow context and defensive investigation steps, records analyst notes/dispositions, and allows detection thresholds to be tuned.

## User preferences

All suspicious scenarios must remain synthetic and defensive. Clearly explain that a match is a triage signal, not proof of malicious behavior.

## Gotchas

- After editing `lib/api-spec/openapi.yaml`, run API codegen before consuming updated generated types.
- After changing `lib/db` schema exports, run `pnpm run typecheck:libs` before leaf package typechecks.
- The first dashboard summary request seeds an empty development database with example flows and default rules.
- The standalone Python simulator prints JSON only; to persist new flow data in the app, use the dashboard's simulation control.
- The initial learning build has no analyst authentication; keep project access restricted.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
