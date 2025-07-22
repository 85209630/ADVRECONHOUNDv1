import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const scans = pgTable("scans", {
  id: serial("id").primaryKey(),
  target: text("target").notNull(),
  scanType: text("scan_type").notNull(),
  status: text("status").notNull(), // 'pending', 'running', 'completed', 'failed'
  progress: integer("progress").default(0),
  riskScore: integer("risk_score"),
  results: jsonb("results"),
  createdAt: timestamp("created_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const vulnerabilities = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").notNull().references(() => scans.id),
  severity: text("severity").notNull(), // 'critical', 'high', 'medium', 'low'
  type: text("type").notNull(),
  description: text("description").notNull(),
  cvss: text("cvss"),
  remediation: text("remediation"),
});

export const subdomains = pgTable("subdomains", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").notNull().references(() => scans.id),
  subdomain: text("subdomain").notNull(),
  ipAddress: text("ip_address"),
  status: text("status").notNull(), // 'active', 'inactive'
  technologies: jsonb("technologies"),
});

export const technologies = pgTable("technologies", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").notNull().references(() => scans.id),
  name: text("name").notNull(),
  version: text("version"),
  category: text("category").notNull(), // 'web_server', 'framework', 'database', etc.
  confidence: integer("confidence"),
});

export const mitreAttackTechniques = pgTable("mitre_attack_techniques", {
  id: serial("id").primaryKey(),
  techniqueId: text("technique_id").notNull().unique(), // T1001, T1002, etc.
  name: text("name").notNull(),
  description: text("description").notNull(),
  tactic: text("tactic").notNull(), // 'initial-access', 'execution', 'persistence', etc.
  phase: text("phase").notNull(), // 'pre-attack', 'attack', 'post-attack'
  platform: text("platform").notNull(), // 'windows', 'linux', 'macos', 'network', 'web'
  dataSource: text("data_source"),
  detection: text("detection"),
  mitigation: text("mitigation"),
});

export const vulnerabilityMitreMapping = pgTable("vulnerability_mitre_mapping", {
  id: serial("id").primaryKey(),
  vulnerabilityId: integer("vulnerability_id").notNull().references(() => vulnerabilities.id),
  techniqueId: text("technique_id").notNull().references(() => mitreAttackTechniques.techniqueId),
  confidence: integer("confidence").notNull(), // 0-100
  reasoning: text("reasoning"),
});

export const insertScanSchema = createInsertSchema(scans).omit({
  id: true,
  createdAt: true,
  completedAt: true,
  status: true,
  progress: true,
  riskScore: true,
  results: true,
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).omit({
  id: true,
});

export const insertSubdomainSchema = createInsertSchema(subdomains).omit({
  id: true,
});

export const insertTechnologySchema = createInsertSchema(technologies).omit({
  id: true,
});

export const insertMitreAttackTechniqueSchema = createInsertSchema(mitreAttackTechniques).omit({
  id: true,
});

export const insertVulnerabilityMitreMappingSchema = createInsertSchema(vulnerabilityMitreMapping).omit({
  id: true,
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scans.$inferSelect;
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertSubdomain = z.infer<typeof insertSubdomainSchema>;
export type Subdomain = typeof subdomains.$inferSelect;
export type InsertTechnology = z.infer<typeof insertTechnologySchema>;
export type Technology = typeof technologies.$inferSelect;
export type InsertMitreAttackTechnique = z.infer<typeof insertMitreAttackTechniqueSchema>;
export type MitreAttackTechnique = typeof mitreAttackTechniques.$inferSelect;
export type InsertVulnerabilityMitreMapping = z.infer<typeof insertVulnerabilityMitreMappingSchema>;
export type VulnerabilityMitreMapping = typeof vulnerabilityMitreMapping.$inferSelect;
