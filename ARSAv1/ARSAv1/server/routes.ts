import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { ReconnaissanceService } from "./services/reconnaissance";
import { analyzeVulnerabilities, analyzeTechnologies, generateScanReport } from "./services/openai";
import { mitreAttackService, MITRE_ATTACK_TECHNIQUES } from "./services/mitre-attack";
import { insertScanSchema } from "@shared/schema";
import { z } from "zod";

// Validation schema for API requests
const scanRequestSchema = z.object({
  target: z.string().min(1, "Target is required"),
  scanType: z.string().min(1, "Scan type is required"),
});

const reconService = new ReconnaissanceService();

// Initialize MITRE ATT&CK techniques database
async function initializeMitreAttackDatabase() {
  try {
    // Check if techniques are already initialized
    const existingTechniques = await storage.getAllMitreAttackTechniques();
    
    if (existingTechniques.length === 0) {
      // Initialize with predefined techniques
      for (const technique of MITRE_ATTACK_TECHNIQUES) {
        await storage.createMitreAttackTechnique({
          techniqueId: technique.techniqueId,
          name: technique.name,
          description: technique.description,
          tactic: technique.tactic,
          phase: technique.phase,
          platform: technique.platform,
          dataSource: technique.dataSource,
          detection: technique.detection,
          mitigation: technique.mitigation
        });
      }
      console.log('MITRE ATT&CK techniques database initialized');
    }
  } catch (error) {
    console.error('Failed to initialize MITRE ATT&CK database:', error);
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);
  
  // WebSocket server for real-time updates
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });
  
  const clients = new Map<string, WebSocket>();
  
  // Initialize MITRE ATT&CK database
  await initializeMitreAttackDatabase();
  
  wss.on('connection', (ws) => {
    const clientId = Math.random().toString(36).substr(2, 9);
    clients.set(clientId, ws);
    
    ws.on('close', () => {
      clients.delete(clientId);
    });
    
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        // Handle client messages if needed
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    });
  });

  const broadcastUpdate = (scanId: number, update: any) => {
    const message = JSON.stringify({
      type: 'scan_update',
      scanId,
      data: update
    });
    
    clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  };

  // Get all scans
  app.get("/api/scans", async (req, res) => {
    try {
      const scans = await storage.getScans();
      res.json(scans);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch scans" });
    }
  });

  // Get specific scan with details
  app.get("/api/scans/:id", async (req, res) => {
    try {
      const scanId = parseInt(req.params.id);
      const scan = await storage.getScan(scanId);
      
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }

      const [vulnerabilities, subdomains, technologies] = await Promise.all([
        storage.getVulnerabilitiesByScan(scanId),
        storage.getSubdomainsByScan(scanId),
        storage.getTechnologiesByScan(scanId)
      ]);

      res.json({
        scan,
        vulnerabilities,
        subdomains,
        technologies
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch scan details" });
    }
  });

  // Start new scan
  app.post("/api/scans", async (req, res) => {
    try {
      const validatedData = scanRequestSchema.parse(req.body);
      const scan = await storage.createScan(validatedData);
      
      res.json(scan);
      
      // Start background scanning process
      performScan(scan.id, scan.target, scan.scanType, broadcastUpdate);
      
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid scan data", details: error.errors });
      }
      res.status(500).json({ error: "Failed to create scan" });
    }
  });

  // Export scan report
  app.get("/api/scans/:id/report", async (req, res) => {
    try {
      const scanId = parseInt(req.params.id);
      const scan = await storage.getScan(scanId);
      
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }

      const [vulnerabilities, subdomains, technologies] = await Promise.all([
        storage.getVulnerabilitiesByScan(scanId),
        storage.getSubdomainsByScan(scanId),
        storage.getTechnologiesByScan(scanId)
      ]);

      const report = await generateScanReport(scan, vulnerabilities, subdomains, technologies);
      
      res.setHeader('Content-Type', 'text/markdown');
      res.setHeader('Content-Disposition', `attachment; filename="scan_report_${scan.target}_${scanId}.md"`);
      res.send(report);
      
    } catch (error) {
      res.status(500).json({ error: "Failed to generate report" });
    }
  });

  // Background scanning function
  async function performScan(scanId: number, target: string, scanType: string, broadcast: Function) {
    try {
      // Update scan status to running
      await storage.updateScan(scanId, { status: 'running', progress: 0 });
      broadcast(scanId, { status: 'running', progress: 0 });

      // Perform reconnaissance
      broadcast(scanId, { status: 'running', progress: 25, message: 'Starting reconnaissance...' });
      const reconResults = await reconService.performReconnaissance(target);
      
      // Store subdomains
      broadcast(scanId, { status: 'running', progress: 50, message: 'Analyzing subdomains...' });
      for (const subdomain of reconResults.subdomains) {
        await storage.createSubdomain({
          scanId,
          subdomain,
          status: 'active',
          technologies: null,
          ipAddress: null
        });
      }

      // Store technologies
      broadcast(scanId, { status: 'running', progress: 65, message: 'Identifying technologies...' });
      for (const tech of reconResults.technologies) {
        await storage.createTechnology({
          scanId,
          name: tech.name,
          version: tech.version || null,
          category: tech.category,
          confidence: 85
        });
      }

      // AI-powered vulnerability analysis
      broadcast(scanId, { status: 'running', progress: 80, message: 'Analyzing vulnerabilities with AI...' });
      const vulnerabilityAnalysis = await analyzeVulnerabilities(target, reconResults);
      
      // Store vulnerabilities and analyze for MITRE ATT&CK
      const vulnerabilityIds: number[] = [];
      for (const vuln of vulnerabilityAnalysis.vulnerabilities) {
        const vulnerability = await storage.createVulnerability({
          scanId,
          severity: vuln.severity,
          type: vuln.type,
          description: vuln.description,
          cvss: vuln.cvss,
          remediation: vuln.remediation
        });
        vulnerabilityIds.push(vulnerability.id);
      }

      // MITRE ATT&CK framework analysis
      broadcast(scanId, { status: 'running', progress: 90, message: 'Mapping to MITRE ATT&CK framework...' });
      const vulnerabilities = await storage.getVulnerabilitiesByScan(scanId);
      
      for (const vulnerability of vulnerabilities) {
        try {
          const mitreAnalysis = await mitreAttackService.analyzeVulnerabilityForMitre(vulnerability);
          
          // Store MITRE ATT&CK mappings
          for (const mapping of mitreAnalysis.mappings) {
            await storage.createVulnerabilityMitreMapping({
              vulnerabilityId: vulnerability.id,
              techniqueId: mapping.techniqueId,
              confidence: mapping.confidence,
              reasoning: mapping.reasoning
            });
          }
        } catch (error) {
          console.error('MITRE ATT&CK analysis failed for vulnerability:', vulnerability.id, error);
        }
      }

      // Update scan with final results
      await storage.updateScan(scanId, {
        status: 'completed',
        progress: 100,
        riskScore: Math.round(vulnerabilityAnalysis.riskScore),
        results: reconResults,
        completedAt: new Date()
      });

      broadcast(scanId, { 
        status: 'completed', 
        progress: 100, 
        riskScore: vulnerabilityAnalysis.riskScore,
        message: 'Scan completed successfully'
      });

    } catch (error) {
      console.error('Scan error:', error);
      await storage.updateScan(scanId, { 
        status: 'failed', 
        completedAt: new Date() 
      });
      broadcast(scanId, { 
        status: 'failed', 
        message: 'Scan failed: ' + (error as Error).message 
      });
    }
  }

  // MITRE ATT&CK API routes
  app.get("/api/mitre-attack/techniques", async (req, res) => {
    try {
      const techniques = await storage.getAllMitreAttackTechniques();
      res.json(techniques);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch MITRE ATT&CK techniques" });
    }
  });

  app.get("/api/mitre-attack/techniques/:techniqueId", async (req, res) => {
    try {
      const technique = await storage.getMitreAttackTechnique(req.params.techniqueId);
      if (!technique) {
        return res.status(404).json({ error: "Technique not found" });
      }
      res.json(technique);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch MITRE ATT&CK technique" });
    }
  });

  app.get("/api/scans/:id/mitre-mappings", async (req, res) => {
    try {
      const scanId = parseInt(req.params.id);
      const mappings = await storage.getMitreMappingsByScan(scanId);
      
      // Get full technique details for each mapping
      const mappingsWithDetails = await Promise.all(
        mappings.map(async (mapping) => {
          const technique = await storage.getMitreAttackTechnique(mapping.techniqueId);
          return {
            ...mapping,
            technique
          };
        })
      );
      
      res.json(mappingsWithDetails);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch MITRE ATT&CK mappings" });
    }
  });

  app.get("/api/scans/:id/mitre-report", async (req, res) => {
    try {
      const scanId = parseInt(req.params.id);
      const vulnerabilities = await storage.getVulnerabilitiesByScan(scanId);
      
      // Get MITRE analysis results
      const mitreAnalysisResults = [];
      for (const vulnerability of vulnerabilities) {
        try {
          const analysis = await mitreAttackService.analyzeVulnerabilityForMitre(vulnerability);
          mitreAnalysisResults.push(analysis);
        } catch (error) {
          console.error('Failed to analyze vulnerability for MITRE report:', error);
        }
      }
      
      const report = await mitreAttackService.generateMitreAttackReport(vulnerabilities, mitreAnalysisResults);
      
      res.setHeader('Content-Type', 'text/markdown');
      res.setHeader('Content-Disposition', `attachment; filename="mitre_attack_report_${scanId}.md"`);
      res.send(report);
      
    } catch (error) {
      res.status(500).json({ error: "Failed to generate MITRE ATT&CK report" });
    }
  });

  return httpServer;
}
