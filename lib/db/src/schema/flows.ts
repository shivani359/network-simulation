import { sql } from "drizzle-orm";
import { index, integer, pgTable, real, text, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const flowsTable = pgTable(
  "network_flows",
  {
    flowId: text("flow_id").primaryKey(),
    timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
    sourceIp: text("source_ip").notNull(),
    destinationIp: text("destination_ip").notNull(),
    sourcePort: integer("source_port").notNull(),
    destinationPort: integer("destination_port").notNull(),
    protocol: text("protocol").notNull(),
    packetCount: integer("packet_count").notNull(),
    byteCount: integer("byte_count").notNull(),
    durationSeconds: real("duration_seconds").notNull(),
    connectionCount: integer("connection_count").notNull(),
    failedConnectionCount: integer("failed_connection_count").notNull(),
    synCount: integer("syn_count").notNull(),
    rstCount: integer("rst_count").notNull(),
    averagePacketSize: real("average_packet_size").notNull(),
    uniqueDestinationPorts: integer("unique_destination_ports").notNull(),
    uniqueDestinationIps: integer("unique_destination_ips").notNull(),
    scenarioType: text("scenario_type").notNull(),
    classification: text("classification").notNull(),
    riskScore: integer("risk_score").notNull(),
    anomalyScore: integer("anomaly_score").notNull(),
    ruleIds: text("rule_ids").array().notNull().default(sql`ARRAY[]::text[]`),
  },
  (table) => [
    index("network_flows_timestamp_idx").on(table.timestamp),
    index("network_flows_source_timestamp_idx").on(table.sourceIp, table.timestamp),
    index("network_flows_classification_idx").on(table.classification),
  ],
);

export const insertFlowSchema = createInsertSchema(flowsTable);
export type InsertFlow = z.infer<typeof insertFlowSchema>;
export type NetworkFlow = typeof flowsTable.$inferSelect;