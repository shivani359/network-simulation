import { index, pgTable, text, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { alertsTable } from "./alerts";

export const incidentNotesTable = pgTable(
  "incident_notes",
  {
    noteId: text("note_id").primaryKey(),
    alertId: text("alert_id").notNull().references(() => alertsTable.alertId, { onDelete: "cascade" }),
    note: text("note").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("incident_notes_alert_created_idx").on(table.alertId, table.createdAt)],
);

export const insertIncidentNoteSchema = createInsertSchema(incidentNotesTable);
export type InsertIncidentNote = z.infer<typeof insertIncidentNoteSchema>;
export type IncidentNote = typeof incidentNotesTable.$inferSelect;