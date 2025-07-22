import { users, scans, vulnerabilities, subdomains, technologies, mitreAttackTechniques, vulnerabilityMitreMapping, type User, type InsertUser, type Scan, type InsertScan, type Vulnerability, type InsertVulnerability, type Subdomain, type InsertSubdomain, type Technology, type InsertTechnology, type MitreAttackTechnique, type InsertMitreAttackTechnique, type VulnerabilityMitreMapping, type InsertVulnerabilityMitreMapping } from "@shared/schema";
import { db } from "./db";
import { eq } from "drizzle-orm";

export interface IStorage {
  // User operations
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Scan operations
  createScan(scan: { target: string; scanType: string }): Promise<Scan>;
  getScan(id: number): Promise<Scan | undefined>;
  getScans(): Promise<Scan[]>;
  updateScan(id: number, updates: Partial<Scan>): Promise<Scan | undefined>;
  
  // Vulnerability operations
  createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability>;
  getVulnerabilitiesByScan(scanId: number): Promise<Vulnerability[]>;
  
  // Subdomain operations
  createSubdomain(subdomain: InsertSubdomain): Promise<Subdomain>;
  getSubdomainsByScan(scanId: number): Promise<Subdomain[]>;
  
  // Technology operations
  createTechnology(technology: InsertTechnology): Promise<Technology>;
  getTechnologiesByScan(scanId: number): Promise<Technology[]>;
  
  // MITRE ATT&CK operations
  createMitreAttackTechnique(technique: InsertMitreAttackTechnique): Promise<MitreAttackTechnique>;
  getMitreAttackTechnique(techniqueId: string): Promise<MitreAttackTechnique | undefined>;
  getAllMitreAttackTechniques(): Promise<MitreAttackTechnique[]>;
  
  // Vulnerability MITRE mapping operations
  createVulnerabilityMitreMapping(mapping: InsertVulnerabilityMitreMapping): Promise<VulnerabilityMitreMapping>;
  getVulnerabilityMitreMappings(vulnerabilityId: number): Promise<VulnerabilityMitreMapping[]>;
  getMitreMappingsByScan(scanId: number): Promise<VulnerabilityMitreMapping[]>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private scans: Map<number, Scan>;
  private vulnerabilities: Map<number, Vulnerability>;
  private subdomains: Map<number, Subdomain>;
  private technologies: Map<number, Technology>;
  private currentUserId: number;
  private currentScanId: number;
  private currentVulnerabilityId: number;
  private currentSubdomainId: number;
  private currentTechnologyId: number;

  constructor() {
    this.users = new Map();
    this.scans = new Map();
    this.vulnerabilities = new Map();
    this.subdomains = new Map();
    this.technologies = new Map();
    this.currentUserId = 1;
    this.currentScanId = 1;
    this.currentVulnerabilityId = 1;
    this.currentSubdomainId = 1;
    this.currentTechnologyId = 1;
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async createScan(scanRequest: { target: string; scanType: string }): Promise<Scan> {
    const id = this.currentScanId++;
    const scan: Scan = { 
      ...scanRequest, 
      id, 
      status: 'pending',
      createdAt: new Date(),
      completedAt: null,
      progress: 0,
      riskScore: null,
      results: null
    };
    this.scans.set(id, scan);
    return scan;
  }

  async getScan(id: number): Promise<Scan | undefined> {
    return this.scans.get(id);
  }

  async getScans(): Promise<Scan[]> {
    return Array.from(this.scans.values()).sort((a, b) => 
      new Date(b.createdAt!).getTime() - new Date(a.createdAt!).getTime()
    );
  }

  async updateScan(id: number, updates: Partial<Scan>): Promise<Scan | undefined> {
    const scan = this.scans.get(id);
    if (!scan) return undefined;
    
    const updatedScan = { ...scan, ...updates };
    this.scans.set(id, updatedScan);
    return updatedScan;
  }

  async createVulnerability(insertVulnerability: InsertVulnerability): Promise<Vulnerability> {
    const id = this.currentVulnerabilityId++;
    const vulnerability: Vulnerability = { 
      ...insertVulnerability, 
      id,
      cvss: insertVulnerability.cvss || null,
      remediation: insertVulnerability.remediation || null
    };
    this.vulnerabilities.set(id, vulnerability);
    return vulnerability;
  }

  async getVulnerabilitiesByScan(scanId: number): Promise<Vulnerability[]> {
    return Array.from(this.vulnerabilities.values()).filter(
      (vuln) => vuln.scanId === scanId
    );
  }

  async createSubdomain(insertSubdomain: InsertSubdomain): Promise<Subdomain> {
    const id = this.currentSubdomainId++;
    const subdomain: Subdomain = { 
      ...insertSubdomain, 
      id,
      ipAddress: insertSubdomain.ipAddress || null,
      technologies: insertSubdomain.technologies || null
    };
    this.subdomains.set(id, subdomain);
    return subdomain;
  }

  async getSubdomainsByScan(scanId: number): Promise<Subdomain[]> {
    return Array.from(this.subdomains.values()).filter(
      (subdomain) => subdomain.scanId === scanId
    );
  }

  async createTechnology(insertTechnology: InsertTechnology): Promise<Technology> {
    const id = this.currentTechnologyId++;
    const technology: Technology = { 
      ...insertTechnology, 
      id,
      version: insertTechnology.version || null,
      confidence: insertTechnology.confidence || null
    };
    this.technologies.set(id, technology);
    return technology;
  }

  async getTechnologiesByScan(scanId: number): Promise<Technology[]> {
    return Array.from(this.technologies.values()).filter(
      (tech) => tech.scanId === scanId
    );
  }

  async createMitreAttackTechnique(insertTechnique: InsertMitreAttackTechnique): Promise<MitreAttackTechnique> {
    const id = Date.now(); // Simple ID generation for in-memory storage
    const technique: MitreAttackTechnique = { 
      ...insertTechnique, 
      id,
      dataSource: insertTechnique.dataSource || null,
      detection: insertTechnique.detection || null,
      mitigation: insertTechnique.mitigation || null
    };
    // For in-memory storage, we don't actually store these as they're static data
    return technique;
  }

  async getMitreAttackTechnique(techniqueId: string): Promise<MitreAttackTechnique | undefined> {
    // For in-memory storage, return undefined as we don't store these
    return undefined;
  }

  async getAllMitreAttackTechniques(): Promise<MitreAttackTechnique[]> {
    // For in-memory storage, return empty array as we don't store these
    return [];
  }

  async createVulnerabilityMitreMapping(insertMapping: InsertVulnerabilityMitreMapping): Promise<VulnerabilityMitreMapping> {
    const id = Date.now(); // Simple ID generation for in-memory storage
    const mapping: VulnerabilityMitreMapping = { 
      ...insertMapping, 
      id,
      reasoning: insertMapping.reasoning || null
    };
    // For in-memory storage, we don't actually store these
    return mapping;
  }

  async getVulnerabilityMitreMappings(vulnerabilityId: number): Promise<VulnerabilityMitreMapping[]> {
    // For in-memory storage, return empty array as we don't store these
    return [];
  }

  async getMitreMappingsByScan(scanId: number): Promise<VulnerabilityMitreMapping[]> {
    // For in-memory storage, return empty array as we don't store these
    return [];
  }
}

// DatabaseStorage implementation
export class DatabaseStorage implements IStorage {
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  async createScan(scanRequest: { target: string; scanType: string }): Promise<Scan> {
    const [scan] = await db
      .insert(scans)
      .values({
        target: scanRequest.target,
        scanType: scanRequest.scanType,
        status: 'pending',
        progress: 0,
        riskScore: null,
        results: null,
        createdAt: new Date(),
        completedAt: null,
      })
      .returning();
    return scan;
  }

  async getScan(id: number): Promise<Scan | undefined> {
    const [scan] = await db.select().from(scans).where(eq(scans.id, id));
    return scan || undefined;
  }

  async getScans(): Promise<Scan[]> {
    return await db.select().from(scans);
  }

  async updateScan(id: number, updates: Partial<Scan>): Promise<Scan | undefined> {
    const [scan] = await db
      .update(scans)
      .set(updates)
      .where(eq(scans.id, id))
      .returning();
    return scan || undefined;
  }

  async createVulnerability(insertVulnerability: InsertVulnerability): Promise<Vulnerability> {
    const [vulnerability] = await db
      .insert(vulnerabilities)
      .values(insertVulnerability)
      .returning();
    return vulnerability;
  }

  async getVulnerabilitiesByScan(scanId: number): Promise<Vulnerability[]> {
    return await db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, scanId));
  }

  async createSubdomain(insertSubdomain: InsertSubdomain): Promise<Subdomain> {
    const [subdomain] = await db
      .insert(subdomains)
      .values(insertSubdomain)
      .returning();
    return subdomain;
  }

  async getSubdomainsByScan(scanId: number): Promise<Subdomain[]> {
    return await db.select().from(subdomains).where(eq(subdomains.scanId, scanId));
  }

  async createTechnology(insertTechnology: InsertTechnology): Promise<Technology> {
    const [technology] = await db
      .insert(technologies)
      .values(insertTechnology)
      .returning();
    return technology;
  }

  async getTechnologiesByScan(scanId: number): Promise<Technology[]> {
    return await db.select().from(technologies).where(eq(technologies.scanId, scanId));
  }

  async createMitreAttackTechnique(insertTechnique: InsertMitreAttackTechnique): Promise<MitreAttackTechnique> {
    const [technique] = await db
      .insert(mitreAttackTechniques)
      .values(insertTechnique)
      .returning();
    return technique;
  }

  async getMitreAttackTechnique(techniqueId: string): Promise<MitreAttackTechnique | undefined> {
    const [technique] = await db
      .select()
      .from(mitreAttackTechniques)
      .where(eq(mitreAttackTechniques.techniqueId, techniqueId));
    return technique || undefined;
  }

  async getAllMitreAttackTechniques(): Promise<MitreAttackTechnique[]> {
    return await db.select().from(mitreAttackTechniques);
  }

  async createVulnerabilityMitreMapping(insertMapping: InsertVulnerabilityMitreMapping): Promise<VulnerabilityMitreMapping> {
    const [mapping] = await db
      .insert(vulnerabilityMitreMapping)
      .values(insertMapping)
      .returning();
    return mapping;
  }

  async getVulnerabilityMitreMappings(vulnerabilityId: number): Promise<VulnerabilityMitreMapping[]> {
    return await db
      .select()
      .from(vulnerabilityMitreMapping)
      .where(eq(vulnerabilityMitreMapping.vulnerabilityId, vulnerabilityId));
  }

  async getMitreMappingsByScan(scanId: number): Promise<VulnerabilityMitreMapping[]> {
    return await db
      .select({
        id: vulnerabilityMitreMapping.id,
        vulnerabilityId: vulnerabilityMitreMapping.vulnerabilityId,
        techniqueId: vulnerabilityMitreMapping.techniqueId,
        confidence: vulnerabilityMitreMapping.confidence,
        reasoning: vulnerabilityMitreMapping.reasoning
      })
      .from(vulnerabilityMitreMapping)
      .innerJoin(vulnerabilities, eq(vulnerabilityMitreMapping.vulnerabilityId, vulnerabilities.id))
      .where(eq(vulnerabilities.scanId, scanId));
  }
}

export const storage = new DatabaseStorage();
