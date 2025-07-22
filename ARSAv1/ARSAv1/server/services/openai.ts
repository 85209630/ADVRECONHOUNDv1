import { GoogleGenAI } from "@google/genai";

// Use Google's Gemini API which has a generous free tier
const genAI = new GoogleGenAI({ 
  apiKey: process.env.GEMINI_API_KEY || "default_key"
});

export interface VulnerabilityAnalysis {
  riskScore: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  summary: string;
  recommendations: string[];
  vulnerabilities: {
    severity: "critical" | "high" | "medium" | "low";
    type: string;
    description: string;
    cvss: string;
    remediation: string;
  }[];
}

export interface TechnologyAnalysis {
  name: string;
  version: string;
  category: string;
  confidence: number;
  vulnerabilities?: string[];
  recommendations?: string[];
}

export async function analyzeVulnerabilities(
  target: string,
  scanResults: any
): Promise<VulnerabilityAnalysis> {
  try {
    const prompt = `
Analyze the following cybersecurity scan results for target "${target}" and provide a comprehensive vulnerability assessment.

Scan Results:
${JSON.stringify(scanResults, null, 2)}

Please provide a detailed analysis in JSON format with the following structure:
{
  "riskScore": number (0-10),
  "riskLevel": "low" | "medium" | "high" | "critical",
  "summary": "Brief summary of the overall security posture",
  "recommendations": ["Array of high-level recommendations"],
  "vulnerabilities": [
    {
      "severity": "critical" | "high" | "medium" | "low",
      "type": "vulnerability type",
      "description": "detailed description",
      "cvss": "CVSS score if applicable",
      "remediation": "specific remediation steps"
    }
  ]
}

Focus on:
- Actual security implications
- Actionable recommendations
- Prioritization based on risk
- Specific remediation steps
`;

    const response = await genAI.models.generateContent({
      model: "gemini-2.5-flash",
      config: {
        systemInstruction: "You are a cybersecurity expert specializing in vulnerability assessment and risk analysis. Provide thorough, accurate, and actionable security assessments.",
        responseMimeType: "application/json",
        responseSchema: {
          type: "object",
          properties: {
            riskScore: { type: "number" },
            riskLevel: { type: "string", enum: ["low", "medium", "high", "critical"] },
            summary: { type: "string" },
            recommendations: { type: "array", items: { type: "string" } },
            vulnerabilities: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
                  type: { type: "string" },
                  description: { type: "string" },
                  cvss: { type: "string" },
                  remediation: { type: "string" }
                }
              }
            }
          }
        }
      },
      contents: prompt,
    });

    const analysis = JSON.parse(response.text || "{}");
    return analysis;
  } catch (error) {
    console.error("Gemini vulnerability analysis error:", error);
    throw new Error("Failed to analyze vulnerabilities with AI");
  }
}

export async function analyzeTechnologies(
  target: string,
  techStack: any[]
): Promise<TechnologyAnalysis[]> {
  try {
    const prompt = `
Analyze the following technology stack detected for target "${target}":

Technologies:
${JSON.stringify(techStack, null, 2)}

For each technology, provide analysis in JSON format:
{
  "technologies": [
    {
      "name": "technology name",
      "version": "version if available",
      "category": "web_server" | "framework" | "database" | "cms" | "library" | "other",
      "confidence": number (0-100),
      "vulnerabilities": ["known vulnerabilities if any"],
      "recommendations": ["security recommendations"]
    }
  ]
}

Focus on:
- Security implications of each technology
- Known vulnerabilities for specific versions
- Upgrade recommendations
- Security best practices
`;

    const response = await genAI.models.generateContent({
      model: "gemini-2.5-flash",
      config: {
        systemInstruction: "You are a cybersecurity expert specializing in technology stack analysis and vulnerability assessment.",
        responseMimeType: "application/json",
        responseSchema: {
          type: "object",
          properties: {
            technologies: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  version: { type: "string" },
                  category: { type: "string" },
                  confidence: { type: "number" },
                  vulnerabilities: { type: "array", items: { type: "string" } },
                  recommendations: { type: "array", items: { type: "string" } }
                }
              }
            }
          }
        }
      },
      contents: prompt,
    });

    const result = JSON.parse(response.text || "{}");
    return result.technologies || [];
  } catch (error) {
    console.error("Gemini technology analysis error:", error);
    throw new Error("Failed to analyze technologies with AI");
  }
}

export async function generateScanReport(
  scanData: any,
  vulnerabilities: any[],
  subdomains: any[],
  technologies: any[]
): Promise<string> {
  try {
    const prompt = `
Generate a comprehensive cybersecurity assessment report for the following scan:

Target: ${scanData.target}
Scan Type: ${scanData.scanType}
Risk Score: ${scanData.riskScore}

Vulnerabilities Found: ${vulnerabilities.length}
Subdomains Discovered: ${subdomains.length}
Technologies Identified: ${technologies.length}

Data:
Vulnerabilities: ${JSON.stringify(vulnerabilities, null, 2)}
Subdomains: ${JSON.stringify(subdomains, null, 2)}
Technologies: ${JSON.stringify(technologies, null, 2)}

Create a professional security assessment report in markdown format that includes:
1. Executive Summary
2. Risk Assessment
3. Vulnerability Analysis
4. Infrastructure Analysis
5. Recommendations
6. Remediation Priorities

Make it suitable for both technical and non-technical audiences.
`;

    const response = await genAI.models.generateContent({
      model: "gemini-2.5-flash",
      config: {
        systemInstruction: "You are a cybersecurity consultant writing professional security assessment reports."
      },
      contents: prompt,
    });

    return response.text || "";
  } catch (error) {
    console.error("Gemini report generation error:", error);
    throw new Error("Failed to generate report with AI");
  }
}
