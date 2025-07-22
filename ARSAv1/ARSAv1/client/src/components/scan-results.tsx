import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Download, Brain, Bug, Globe, Code, Search } from 'lucide-react';
import { VulnerabilityTable } from './vulnerability-table';
import { TechStackDisplay } from './tech-stack-display';
import { ScanProgress } from './scan-progress';
import { MitreAttackDisplay } from './mitre-attack-display';
import type { Scan, Vulnerability, Subdomain, Technology } from '@shared/schema';

interface ScanResultsProps {
  scan: Scan;
  vulnerabilities: Vulnerability[];
  subdomains: Subdomain[];
  technologies: Technology[];
  scanProgress?: {
    status: string;
    progress: number;
    message?: string;
  };
}

export function ScanResults({ scan, vulnerabilities, subdomains, technologies, scanProgress }: ScanResultsProps) {
  const [isExporting, setIsExporting] = useState(false);

  const handleExportReport = async () => {
    setIsExporting(true);
    try {
      const response = await fetch(`/api/scans/${scan.id}/report`);
      if (!response.ok) throw new Error('Failed to generate report');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `scan_report_${scan.target}_${scan.id}.md`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Export failed:', error);
    } finally {
      setIsExporting(false);
    }
  };

  const getRiskLevel = (score: number) => {
    if (score >= 8) return { level: 'Critical', color: 'bg-red-500' };
    if (score >= 6) return { level: 'High', color: 'bg-orange-500' };
    if (score >= 4) return { level: 'Medium', color: 'bg-yellow-500' };
    return { level: 'Low', color: 'bg-green-500' };
  };

  const currentStatus = scanProgress?.status || scan.status;
  const currentProgress = scanProgress?.progress || scan.progress || 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-3xl font-bold text-white">Scan Results</h2>
          <div className="flex items-center space-x-4 mt-2">
            <span className="text-sm text-gray-400">
              Target: <span className="text-primary font-mono">{scan.target}</span>
            </span>
            <Badge variant="outline" className="text-gray-300">
              {scan.scanType}
            </Badge>
          </div>
        </div>
        <Button
          onClick={handleExportReport}
          disabled={isExporting || scan.status !== 'completed'}
          className="bg-primary hover:bg-primary/90 text-black"
        >
          {isExporting ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-2 border-black border-t-transparent mr-2" />
              Exporting...
            </>
          ) : (
            <>
              <Download className="w-4 h-4 mr-2" />
              Export Report
            </>
          )}
        </Button>
      </div>

      {/* Progress Card */}
      <ScanProgress
        scanId={scan.id}
        status={currentStatus}
        progress={currentProgress}
        message={scanProgress?.message}
        riskScore={scan.riskScore || undefined}
      />

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-gray-800 border-gray-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Subdomains</p>
                <p className="text-2xl font-bold text-primary">{subdomains.length}</p>
              </div>
              <Globe className="w-8 h-8 text-primary" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gray-800 border-gray-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Vulnerabilities</p>
                <p className="text-2xl font-bold text-red-500">{vulnerabilities.length}</p>
              </div>
              <Bug className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gray-800 border-gray-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Technologies</p>
                <p className="text-2xl font-bold text-green-500">{technologies.length}</p>
              </div>
              <Code className="w-8 h-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gray-800 border-gray-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Risk Score</p>
                <p className="text-2xl font-bold text-orange-500">
                  {scan.riskScore ? scan.riskScore.toFixed(1) : 'N/A'}
                </p>
              </div>
              <Brain className="w-8 h-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* AI Risk Analysis */}
      {scan.riskScore && (
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader>
            <CardTitle className="text-xl text-white flex items-center">
              <Brain className="w-5 h-5 text-primary mr-2" />
              AI Risk Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between mb-4">
              <div className="text-center">
                <div className="text-4xl font-bold text-orange-500 mb-2">
                  {scan.riskScore.toFixed(1)}
                </div>
                <Badge className={`${getRiskLevel(scan.riskScore).color} text-white`}>
                  {getRiskLevel(scan.riskScore).level} Risk
                </Badge>
              </div>
              <div className="flex-1 ml-8">
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-300">Risk Assessment</span>
                    <span className="text-sm text-gray-300">{Math.round(scan.riskScore * 10)}%</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div 
                      className="bg-orange-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${scan.riskScore * 10}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
            
            <div className="text-sm text-gray-300">
              <p className="mb-2">
                <strong>Assessment:</strong> The AI analysis indicates a{' '}
                {getRiskLevel(scan.riskScore).level.toLowerCase()} risk level based on discovered vulnerabilities,
                exposed services, and technology stack analysis.
              </p>
              <p>
                <strong>Recommendation:</strong> Review the vulnerability details below and prioritize
                remediation based on severity levels.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabbed Results */}
      <Tabs defaultValue="vulnerabilities" className="w-full">
        <TabsList className="grid w-full grid-cols-5 bg-gray-800 border-gray-700">
          <TabsTrigger value="vulnerabilities" className="text-white">
            Vulnerabilities
          </TabsTrigger>
          <TabsTrigger value="subdomains" className="text-white">
            Subdomains
          </TabsTrigger>
          <TabsTrigger value="technologies" className="text-white">
            Technologies
          </TabsTrigger>
          <TabsTrigger value="mitre" className="text-white">
            MITRE ATT&CK
          </TabsTrigger>
          <TabsTrigger value="osint" className="text-white">
            OSINT
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="vulnerabilities">
          <VulnerabilityTable vulnerabilities={vulnerabilities} />
        </TabsContent>
        
        <TabsContent value="subdomains">
          <Card className="bg-gray-800 border-gray-700">
            <CardHeader>
              <CardTitle className="text-xl text-white flex items-center">
                <Globe className="w-5 h-5 text-blue-500 mr-2" />
                Discovered Subdomains ({subdomains.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {subdomains.length === 0 ? (
                <div className="text-center py-8">
                  <Globe className="w-12 h-12 mx-auto mb-4 text-gray-500 opacity-50" />
                  <p className="text-gray-400">No subdomains discovered</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {subdomains.map((subdomain) => (
                    <div key={subdomain.id} className="bg-gray-900 p-4 rounded-lg">
                      <div className="flex items-center justify-between">
                        <span className="text-white font-mono">{subdomain.subdomain}</span>
                        <Badge className={subdomain.status === 'active' ? 'bg-green-500' : 'bg-gray-500'}>
                          {subdomain.status}
                        </Badge>
                      </div>
                      {subdomain.ipAddress && (
                        <div className="text-sm text-gray-400 mt-1">
                          IP: {subdomain.ipAddress}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="technologies">
          <TechStackDisplay technologies={technologies} />
        </TabsContent>
        
        <TabsContent value="mitre">
          <MitreAttackDisplay scanId={scan.id} />
        </TabsContent>
        
        <TabsContent value="osint">
          <Card className="bg-gray-800 border-gray-700">
            <CardHeader>
              <CardTitle className="text-xl text-white flex items-center">
                <Search className="w-5 h-5 text-purple-500 mr-2" />
                OSINT Information
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8">
                <Search className="w-12 h-12 mx-auto mb-4 text-gray-500 opacity-50" />
                <p className="text-gray-400">OSINT data collection in progress</p>
                <p className="text-sm text-gray-500 mt-2">
                  Open source intelligence gathering will be available in future updates.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
