import { index, integer, pgTable, real, text, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { flowsTable } from "./flows";

export const alertsTable = pgTable(
  "ids_alerts",
  {
    alertId: text("alert_id").primaryKey(),
    flowId: text("flow_id").notNull().references(() => flowsTable.flowId, { onDelete: "cascade" }),
    timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
    sourceIp: text("source_ip").notNull(),
    destinationIp: text("destination_ip").notNull(),
    protocol: text("protocol").notNull(),
    sourcePort: integer("source_port").notNull(),
    destinationPort: integer("destination_port").notNull(),
    ruleId: text("rule_id").notNull(),
    alertType: text("alert_type").notNull(),
    severity: text("severity").notNull(),
    riskScore: integer("risk_score").notNull(),
    anomalyScore: integer("anomaly_score").notNull(),
    description: text("description").notNull(),
    status: text("status").notNull().default("NEW"),
    scenarioType: text("scenario_type").notNull(),
    resolutionNotes: text("resolution_notes").notNull().default(""),
  },
  (table) => [
    index("ids_alerts_timestamp_idx").on(table.timestamp),
    index("ids_alerts_status_severity_idx").on(table.status, table.severity),
    index("ids_alerts_source_timestamp_idx").on(table.sourceIp, table.timestamp),
  ],
);

export const insertAlertSchema = createInsertSchema(alertsTable);
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type SecurityAlert = typeof alertsTable.$inferSelect;