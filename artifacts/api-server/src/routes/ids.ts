import { randomUUID } from "node:crypto";
import { and, desc, eq, sql } from "drizzle-orm";
import { Router, type IRouter } from "express";
import {
  AddAlertNoteBody,
  AddAlertNoteParams,
  AddAlertNoteResponse,
  GenerateSyntheticFlowsBody,
  GenerateSyntheticFlowsResponse,
  GetAlertParams,
  GetAlertResponse,
  GetAlertsQueryParams,
  GetAlertsResponse,
  GetDashboardStatsResponse,
  GetFlowsQueryParams,
  GetFlowsResponse,
  GetRulesResponse,
  GetTrafficAnalyticsResponse,
  UpdateAlertStatusBody,
  UpdateAlertStatusParams,
  UpdateAlertStatusResponse,
  UpdateRuleBody,
  UpdateRuleParams,
  UpdateRuleResponse,
} from "@workspace/api-zod";
import {
  alertsTable,
  db,
  detectionRulesTable,
  flowsTable,
  incidentNotesTable,
} from "@workspace/db";
import {
  analyzeFlow,
  calculateBaseline,
  DEFAULT_RULES,
  generateSyntheticFlows,
  severityForRisk,
  type DetectionRule,
  type FlowRecord,
  type Severity,
} from "../lib/ids";

const router: IRouter = Router();
const DEFAULT_INVESTIGATION_STEPS = [
  "Review related flow and application logs for the same time window.",
  "Check whether the source is known and expected in this environment.",
  "Compare the observed behavior with the historical synthetic baseline.",
  "Review authentication and firewall records where authorized.",
  "Document whether the activity is expected before closing the alert.",
];

function validationError(res: Parameters<Parameters<IRouter["get"]>[1]>[1], message: string) {
  res.status(400).json({ error: message });
}

async function ensureRules(): Promise<DetectionRule[]> {
  const existing = await db.select().from(detectionRulesTable);
  if (existing.length === 0) {
    await db
      .insert(detectionRulesTable)
      .values(DEFAULT_RULES)
      .onConflictDoNothing();
  }
  const rows = await db.select().from(detectionRulesTable);
  return rows.map((rule) => ({
    ...rule,
    severity: rule.severity as Severity,
    enabled: rule.enabled,
  }));
}

function makeAlertRows(flow: FlowRecord, rules: DetectionRule[]) {
  const ruleLookup = new Map(rules.map((rule) => [rule.ruleId, rule]));
  return flow.ruleIds.flatMap((ruleId) => {
    const rule = ruleLookup.get(ruleId);
    if (!rule) return [];
    return [
      {
        alertId: randomUUID(),
        flowId: flow.flowId,
        timestamp: flow.timestamp,
        sourceIp: flow.sourceIp,
        destinationIp: flow.destinationIp,
        protocol: flow.protocol,
        sourcePort: flow.sourcePort,
        destinationPort: flow.destinationPort,
        ruleId: rule.ruleId,
        alertType: rule.name,
        severity: rule.severity,
        riskScore: flow.riskScore,
        anomalyScore: flow.anomalyScore,
        description: `${rule.description} Matched against synthetic flow ${flow.flowId.slice(0, 8)}.`,
        status: "NEW",
        scenarioType: flow.scenarioType,
        resolutionNotes: "",
      },
    ];
  });
}

function asFlowRows(flows: FlowRecord[]) {
  return flows.map((flow) => ({ ...flow }));
}

async function seedIfEmpty(): Promise<void> {
  await ensureRules();
  const [{ count }] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(flowsTable);
  if (count > 0) return;

  const rules = await ensureRules();
  const baseline = calculateBaseline(generateSyntheticFlows(64, "normal"));
  const rawFlows = generateSyntheticFlows(84, "mixed");
  const analyzed = rawFlows.map((flow) => analyzeFlow(flow, rules, baseline));
  await db.insert(flowsTable).values(asFlowRows(analyzed));
  const alerts = analyzed.flatMap((flow) => makeAlertRows(flow, rules));
  if (alerts.length > 0) await db.insert(alertsTable).values(alerts);
}

router.get("/dashboard/stats", async (_req, res): Promise<void> => {
  await seedIfEmpty();
  const flows = await db.select().from(flowsTable);
  const alerts = await db.select().from(alertsTable);
  const averageRiskScore = flows.length
    ? Number((flows.reduce((sum, flow) => sum + flow.riskScore, 0) / flows.length).toFixed(1))
    : 0;
  const openAlerts = alerts.filter((alert) => alert.status === "NEW" || alert.status === "INVESTIGATING").length;
  const criticalAlerts = alerts.filter(
    (alert) => alert.severity === "CRITICAL" && (alert.status === "NEW" || alert.status === "INVESTIGATING"),
  ).length;
  res.json(
    GetDashboardStatsResponse.parse({
      totalFlows: flows.length,
      normalFlows: flows.filter((flow) => flow.classification === "NORMAL").length,
      suspiciousFlows: flows.filter((flow) => flow.classification !== "NORMAL").length,
      openAlerts,
      criticalAlerts,
      averageRiskScore,
      simulationRunning: false,
      generatedAt: new Date(),
    }),
  );
});

router.get("/dashboard/traffic", async (_req, res): Promise<void> => {
  await seedIfEmpty();
  const flows = await db.select().from(flowsTable).orderBy(desc(flowsTable.timestamp)).limit(1200);
  const alerts = await db.select().from(alertsTable).orderBy(desc(alertsTable.timestamp)).limit(800);
  const bucketSize = 5 * 60 * 1000;
  const end = Math.floor(Date.now() / bucketSize) * bucketSize;
  const bucketMap = new Map<number, FlowRecord[]>();
  for (let i = 11; i >= 0; i -= 1) bucketMap.set(end - i * bucketSize, []);
  for (const flow of flows) {
    const key = Math.floor(flow.timestamp.getTime() / bucketSize) * bucketSize;
    const bucket = bucketMap.get(key);
    if (bucket) bucket.push(flow as FlowRecord);
  }
  const timeline = [...bucketMap.entries()].map(([timestamp, rows]) => ({
    timestamp: new Date(timestamp),
    flows: rows.length,
    suspicious: rows.filter((flow) => flow.classification !== "NORMAL").length,
    averageRisk: rows.length
      ? Number((rows.reduce((sum, flow) => sum + flow.riskScore, 0) / rows.length).toFixed(1))
      : 0,
  }));
  const breakdown = (values: string[], limit = 8) => {
    const counts = new Map<string, number>();
    for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([label, value]) => ({ label, value }));
  };
  const riskBands = [
    { label: "0–20", minimum: 0, maximum: 20 },
    { label: "21–40", minimum: 21, maximum: 40 },
    { label: "41–60", minimum: 41, maximum: 60 },
    { label: "61–80", minimum: 61, maximum: 80 },
    { label: "81–100", minimum: 81, maximum: 100 },
  ];
  res.json(
    GetTrafficAnalyticsResponse.parse({
      timeline,
      protocols: breakdown(flows.map((flow) => flow.protocol)),
      destinationPorts: breakdown(flows.map((flow) => String(flow.destinationPort))),
      severities: breakdown(alerts.map((alert) => alert.severity)),
      alertTypes: breakdown(alerts.map((alert) => alert.alertType)),
      topSources: breakdown(alerts.map((alert) => alert.sourceIp)),
      riskBuckets: riskBands.map((band) => ({
        label: band.label,
        value: flows.filter((flow) => flow.riskScore >= band.minimum && flow.riskScore <= band.maximum).length,
      })),
    }),
  );
});

router.get("/flows", async (req, res): Promise<void> => {
  await seedIfEmpty();
  const query = GetFlowsQueryParams.safeParse(req.query);
  if (!query.success) {
    validationError(res, query.error.message);
    return;
  }
  const filters = query.data.classification
    ? [eq(flowsTable.classification, query.data.classification)]
    : [];
  const rows = await db
    .select()
    .from(flowsTable)
    .where(filters.length ? and(...filters) : undefined)
    .orderBy(desc(flowsTable.timestamp))
    .limit(query.data.limit);
  res.json(GetFlowsResponse.parse(rows));
});

router.get("/alerts", async (req, res): Promise<void> => {
  await seedIfEmpty();
  const query = GetAlertsQueryParams.safeParse(req.query);
  if (!query.success) {
    validationError(res, query.error.message);
    return;
  }
  const filters = [];
  if (query.data.severity) filters.push(eq(alertsTable.severity, query.data.severity));
  if (query.data.status) filters.push(eq(alertsTable.status, query.data.status));
  const rows = await db
    .select()
    .from(alertsTable)
    .where(filters.length ? and(...filters) : undefined)
    .orderBy(desc(alertsTable.timestamp))
    .limit(query.data.limit);
  res.json(GetAlertsResponse.parse(rows));
});

router.get("/alerts/:alertId", async (req, res): Promise<void> => {
  await seedIfEmpty();
  const params = GetAlertParams.safeParse(req.params);
  if (!params.success) {
    validationError(res, params.error.message);
    return;
  }
  const [alert] = await db
    .select()
    .from(alertsTable)
    .where(eq(alertsTable.alertId, params.data.alertId))
    .limit(1);
  if (!alert) {
    res.status(404).json({ error: "Alert not found" });
    return;
  }
  const [flow] = await db
    .select()
    .from(flowsTable)
    .where(eq(flowsTable.flowId, alert.flowId))
    .limit(1);
  const notes = await db
    .select()
    .from(incidentNotesTable)
    .where(eq(incidentNotesTable.alertId, alert.alertId))
    .orderBy(desc(incidentNotesTable.createdAt));
  res.json(
    GetAlertResponse.parse({
      alert,
      flow,
      notes,
      investigationSteps: DEFAULT_INVESTIGATION_STEPS,
    }),
  );
});

router.patch("/alerts/:alertId/status", async (req, res): Promise<void> => {
  const params = UpdateAlertStatusParams.safeParse(req.params);
  const body = UpdateAlertStatusBody.safeParse(req.body);
  if (!params.success || !body.success) {
    const message = !params.success
      ? params.error.message
      : !body.success
        ? body.error.message
        : "Invalid request";
    validationError(res, message);
    return;
  }
  const [updated] = await db
    .update(alertsTable)
    .set({
      status: body.data.status,
      ...(body.data.resolutionNotes !== undefined ? { resolutionNotes: body.data.resolutionNotes } : {}),
    })
    .where(eq(alertsTable.alertId, params.data.alertId))
    .returning();
  if (!updated) {
    res.status(404).json({ error: "Alert not found" });
    return;
  }
  res.json(UpdateAlertStatusResponse.parse(updated));
});

router.post("/alerts/:alertId/notes", async (req, res): Promise<void> => {
  const params = AddAlertNoteParams.safeParse(req.params);
  const body = AddAlertNoteBody.safeParse(req.body);
  if (!params.success || !body.success) {
    const message = !params.success
      ? params.error.message
      : !body.success
        ? body.error.message
        : "Invalid request";
    validationError(res, message);
    return;
  }
  const [alert] = await db
    .select({ alertId: alertsTable.alertId })
    .from(alertsTable)
    .where(eq(alertsTable.alertId, params.data.alertId))
    .limit(1);
  if (!alert) {
    res.status(404).json({ error: "Alert not found" });
    return;
  }
  const [note] = await db
    .insert(incidentNotesTable)
    .values({
      noteId: randomUUID(),
      alertId: alert.alertId,
      note: body.data.note.trim(),
    })
    .returning();
  res.status(201).json(AddAlertNoteResponse.parse(note));
});

router.post("/simulation/generate", async (req, res): Promise<void> => {
  const body = GenerateSyntheticFlowsBody.safeParse(req.body);
  if (!body.success) {
    validationError(res, body.error.message);
    return;
  }
  await seedIfEmpty();
  const rules = await ensureRules();
  const normalFlows = await db
    .select()
    .from(flowsTable)
    .where(eq(flowsTable.classification, "NORMAL"))
    .orderBy(desc(flowsTable.timestamp))
    .limit(600);
  const baseline = calculateBaseline(normalFlows);
  const rawFlows = generateSyntheticFlows(body.data.count, body.data.mode, body.data.scenario);
  const analyzed = rawFlows.map((flow) => analyzeFlow(flow, rules, baseline));
  await db.insert(flowsTable).values(asFlowRows(analyzed));
  const alerts = analyzed.flatMap((flow) => makeAlertRows(flow, rules));
  if (alerts.length > 0) await db.insert(alertsTable).values(alerts);
  res.status(201).json(
    GenerateSyntheticFlowsResponse.parse({
      generated: analyzed.length,
      alertsCreated: alerts.length,
      flows: analyzed,
      alerts,
    }),
  );
});

router.get("/rules", async (_req, res): Promise<void> => {
  const rules = await ensureRules();
  res.json(GetRulesResponse.parse(rules));
});

router.patch("/rules/:ruleId", async (req, res): Promise<void> => {
  const params = UpdateRuleParams.safeParse(req.params);
  const body = UpdateRuleBody.safeParse(req.body);
  if (!params.success || !body.success) {
    const message = !params.success
      ? params.error.message
      : !body.success
        ? body.error.message
        : "Invalid request";
    validationError(res, message);
    return;
  }
  const [updated] = await db
    .update(detectionRulesTable)
    .set(body.data)
    .where(eq(detectionRulesTable.ruleId, params.data.ruleId))
    .returning();
  if (!updated) {
    res.status(404).json({ error: "Detection rule not found" });
    return;
  }
  res.json(UpdateRuleResponse.parse(updated));
});

export default router;