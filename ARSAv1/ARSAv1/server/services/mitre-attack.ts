import { GoogleGenAI } from "@google/genai";
import { type Vulnerability, type MitreAttackTechnique } from "@shared/schema";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

export interface MitreAttackMapping {
  techniqueId: string;
  confidence: number;
  reasoning: string;
}

export interface MitreAnalysisResult {
  vulnerabilityId: number;
  mappings: MitreAttackMapping[];
  attackPath: string[];
  riskAssessment: {
    likelihood: number;
    impact: number;
    overall: number;
  };
}

// Core MITRE ATT&CK techniques database
export const MITRE_ATTACK_TECHNIQUES: MitreAttackTechnique[] = [
  {
    id: 1,
    techniqueId: "T1190",
    name: "Exploit Public-Facing Application",
    description: "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
    tactic: "initial-access",
    phase: "attack",
    platform: "web",
    dataSource: "Web logs, network traffic",
    detection: "Monitor for unusual network traffic patterns",
    mitigation: "Regular security updates, web application firewalls"
  },
  {
    id: 2,
    techniqueId: "T1189",
    name: "Drive-by Compromise",
    description: "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.",
    tactic: "initial-access",
    phase: "attack",
    platform: "web",
    dataSource: "Web proxy logs, DNS logs",
    detection: "Monitor for malicious web content",
    mitigation: "Browser security, content filtering"
  },
  {
    id: 3,
    techniqueId: "T1055",
    name: "Process Injection",
    description: "Adversaries may inject code into processes in order to evade process-based defenses or elevate privileges.",
    tactic: "defense-evasion",
    phase: "attack",
    platform: "windows",
    dataSource: "Process monitoring, DLL monitoring",
    detection: "Monitor for suspicious process behavior",
    mitigation: "Application control, exploit protection"
  },
  {
    id: 4,
    techniqueId: "T1021",
    name: "Remote Services",
    description: "Adversaries may use valid accounts to log into a service that accepts remote connections.",
    tactic: "lateral-movement",
    phase: "attack",
    platform: "network",
    dataSource: "Authentication logs, network traffic",
    detection: "Monitor for unusual authentication patterns",
    mitigation: "Multi-factor authentication, network segmentation"
  },
  {
    id: 5,
    techniqueId: "T1083",
    name: "File and Directory Discovery",
    description: "Adversaries may enumerate files and directories or search in specific locations of a host or network share.",
    tactic: "discovery",
    phase: "attack",
    platform: "linux",
    dataSource: "File monitoring, process monitoring",
    detection: "Monitor for unusual file access patterns",
    mitigation: "File system permissions, monitoring"
  },
  {
    id: 6,
    techniqueId: "T1046",
    name: "Network Service Scanning",
    description: "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
    tactic: "discovery",
    phase: "attack",
    platform: "network",
    dataSource: "Network device logs, network traffic",
    detection: "Monitor for port scanning activities",
    mitigation: "Network segmentation, intrusion detection"
  },
  {
    id: 7,
    techniqueId: "T1071",
    name: "Application Layer Protocol",
    description: "Adversaries may communicate using application layer protocols to avoid detection and network filtering.",
    tactic: "command-and-control",
    phase: "attack",
    platform: "network",
    dataSource: "Network traffic, packet capture",
    detection: "Monitor for unusual protocol usage",
    mitigation: "Network monitoring, protocol filtering"
  },
  {
    id: 8,
    techniqueId: "T1059",
    name: "Command and Scripting Interpreter",
    description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
    tactic: "execution",
    phase: "attack",
    platform: "linux",
    dataSource: "Process monitoring, command history",
    detection: "Monitor for suspicious command execution",
    mitigation: "Application control, script blocking"
  },
  {
    id: 9,
    techniqueId: "T1543",
    name: "Create or Modify System Process",
    description: "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.",
    tactic: "persistence",
    phase: "attack",
    platform: "linux",
    dataSource: "Service monitoring, process monitoring",
    detection: "Monitor for unauthorized service creation",
    mitigation: "Service monitoring, access controls"
  },
  {
    id: 10,
    techniqueId: "T1068",
    name: "Exploitation for Privilege Escalation",
    description: "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
    tactic: "privilege-escalation",
    phase: "attack",
    platform: "linux",
    dataSource: "System logs, process monitoring",
    detection: "Monitor for privilege escalation attempts",
    mitigation: "Regular patching, exploit protection"
  }
];

export class MitreAttackService {
  
  async analyzeVulnerabilityForMitre(vulnerability: Vulnerability): Promise<MitreAnalysisResult> {
    try {
      const prompt = `
        Analyze this vulnerability for MITRE ATT&CK framework mapping:
        
        Vulnerability Details:
        - Type: ${vulnerability.type}
        - Severity: ${vulnerability.severity}
        - Description: ${vulnerability.description}
        - CVSS: ${vulnerability.cvss || 'N/A'}
        
        Available MITRE ATT&CK Techniques:
        ${MITRE_ATTACK_TECHNIQUES.map(t => `- ${t.techniqueId}: ${t.name} (${t.tactic})`).join('\n')}
        
        Please provide a JSON response with:
        1. mappings: Array of relevant MITRE ATT&CK technique IDs with confidence scores (0-100) and reasoning
        2. attackPath: Array of technique IDs showing potential attack progression
        3. riskAssessment: Object with likelihood, impact, and overall risk scores (0-100)
        
        Only map to techniques that are directly relevant to this vulnerability.
      `;

      const response = await ai.models.generateContent({
        model: "gemini-2.5-pro",
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: "object",
            properties: {
              mappings: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    techniqueId: { type: "string" },
                    confidence: { type: "number" },
                    reasoning: { type: "string" }
                  },
                  required: ["techniqueId", "confidence", "reasoning"]
                }
              },
              attackPath: {
                type: "array",
                items: { type: "string" }
              },
              riskAssessment: {
                type: "object",
                properties: {
                  likelihood: { type: "number" },
                  impact: { type: "number" },
                  overall: { type: "number" }
                },
                required: ["likelihood", "impact", "overall"]
              }
            },
            required: ["mappings", "attackPath", "riskAssessment"]
          }
        },
        contents: prompt,
      });

      const analysis = JSON.parse(response.text);
      
      return {
        vulnerabilityId: vulnerability.id,
        mappings: analysis.mappings,
        attackPath: analysis.attackPath,
        riskAssessment: analysis.riskAssessment
      };
      
    } catch (error) {
      console.error('Error analyzing vulnerability for MITRE ATT&CK:', error);
      
      // Fallback mapping based on vulnerability type
      return this.getFallbackMapping(vulnerability);
    }
  }

  private getFallbackMapping(vulnerability: Vulnerability): MitreAnalysisResult {
    const mappings: MitreAttackMapping[] = [];
    const attackPath: string[] = [];
    
    // Basic mapping based on vulnerability type
    const vulnType = vulnerability.type.toLowerCase();
    
    if (vulnType.includes('sql injection') || vulnType.includes('xss') || vulnType.includes('rce')) {
      mappings.push({
        techniqueId: "T1190",
        confidence: 85,
        reasoning: "Web application vulnerability allowing exploitation of public-facing application"
      });
      attackPath.push("T1190");
    }
    
    if (vulnType.includes('privilege escalation')) {
      mappings.push({
        techniqueId: "T1068",
        confidence: 80,
        reasoning: "Vulnerability allows privilege escalation"
      });
      attackPath.push("T1068");
    }
    
    if (vulnType.includes('service') || vulnType.includes('port')) {
      mappings.push({
        techniqueId: "T1021",
        confidence: 70,
        reasoning: "Remote service vulnerability"
      });
      attackPath.push("T1021");
    }
    
    // Default risk assessment
    const severityScore = this.getSeverityScore(vulnerability.severity);
    
    return {
      vulnerabilityId: vulnerability.id,
      mappings,
      attackPath,
      riskAssessment: {
        likelihood: severityScore * 0.8,
        impact: severityScore,
        overall: severityScore * 0.9
      }
    };
  }

  private getSeverityScore(severity: string): number {
    switch (severity.toLowerCase()) {
      case 'critical': return 95;
      case 'high': return 80;
      case 'medium': return 60;
      case 'low': return 30;
      default: return 50;
    }
  }

  async generateMitreAttackReport(vulnerabilities: Vulnerability[], mappings: MitreAnalysisResult[]): Promise<string> {
    const tacticGroups = new Map<string, MitreAnalysisResult[]>();
    
    mappings.forEach(mapping => {
      mapping.mappings.forEach(m => {
        const technique = MITRE_ATTACK_TECHNIQUES.find(t => t.techniqueId === m.techniqueId);
        if (technique) {
          const tactic = technique.tactic;
          if (!tacticGroups.has(tactic)) {
            tacticGroups.set(tactic, []);
          }
          tacticGroups.get(tactic)!.push(mapping);
        }
      });
    });

    let report = `# MITRE ATT&CK Analysis Report\n\n`;
    report += `## Executive Summary\n`;
    report += `- Total Vulnerabilities Analyzed: ${vulnerabilities.length}\n`;
    report += `- MITRE ATT&CK Techniques Identified: ${mappings.reduce((acc, m) => acc + m.mappings.length, 0)}\n`;
    report += `- Attack Tactics Covered: ${tacticGroups.size}\n\n`;

    report += `## Tactic Coverage\n\n`;
    for (const [tactic, tacticMappings] of tacticGroups) {
      report += `### ${tactic.charAt(0).toUpperCase() + tactic.slice(1).replace('-', ' ')}\n`;
      
      const uniqueTechniques = new Set(tacticMappings.flatMap(m => m.mappings.map(mapping => mapping.techniqueId)));
      for (const techniqueId of uniqueTechniques) {
        const technique = MITRE_ATTACK_TECHNIQUES.find(t => t.techniqueId === techniqueId);
        if (technique) {
          report += `- **${technique.techniqueId}**: ${technique.name}\n`;
          report += `  - ${technique.description}\n`;
          report += `  - Platform: ${technique.platform}\n`;
          report += `  - Detection: ${technique.detection}\n`;
          report += `  - Mitigation: ${technique.mitigation}\n\n`;
        }
      }
    }

    report += `## Attack Path Analysis\n\n`;
    mappings.forEach((mapping, index) => {
      if (mapping.attackPath.length > 0) {
        const vulnerability = vulnerabilities.find(v => v.id === mapping.vulnerabilityId);
        report += `### Attack Path ${index + 1}: ${vulnerability?.type || 'Unknown'}\n`;
        report += `**Risk Level**: ${mapping.riskAssessment.overall}/100\n`;
        report += `**Attack Sequence**: ${mapping.attackPath.join(' → ')}\n\n`;
      }
    });

    return report;
  }

  getTechniquesByTactic(tactic: string): MitreAttackTechnique[] {
    return MITRE_ATTACK_TECHNIQUES.filter(t => t.tactic === tactic);
  }

  getAllTactics(): string[] {
    return [...new Set(MITRE_ATTACK_TECHNIQUES.map(t => t.tactic))];
  }

  getTechniqueById(techniqueId: string): MitreAttackTechnique | undefined {
    return MITRE_ATTACK_TECHNIQUES.find(t => t.techniqueId === techniqueId);
  }
}

export const mitreAttackService = new MitreAttackService();