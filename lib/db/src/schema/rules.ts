import { boolean, pgTable, real, text } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const detectionRulesTable = pgTable("detection_rules", {
  ruleId: text("rule_id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(),
  threshold: real("threshold").notNull(),
  thresholdLabel: text("threshold_label").notNull(),
  enabled: boolean("enabled").notNull().default(true),
});

export const insertDetectionRuleSchema = createInsertSchema(detectionRulesTable);
export type InsertDetectionRule = z.infer<typeof insertDetectionRuleSchema>;
export type DetectionRuleRecord = typeof detectionRulesTable.$inferSelect;