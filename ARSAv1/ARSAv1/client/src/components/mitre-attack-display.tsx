import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { AlertTriangle, Shield, Eye, Target, Download } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

interface MitreAttackMapping {
  id: number;
  vulnerabilityId: number;
  techniqueId: string;
  confidence: number;
  reasoning: string;
  technique: {
    id: number;
    techniqueId: string;
    name: string;
    description: string;
    tactic: string;
    phase: string;
    platform: string;
    dataSource: string;
    detection: string;
    mitigation: string;
  };
}

interface MitreAttackDisplayProps {
  scanId: number;
}

export function MitreAttackDisplay({ scanId }: MitreAttackDisplayProps) {
  const { data: mappings, isLoading } = useQuery<MitreAttackMapping[]>({
    queryKey: ['/api/scans', scanId, 'mitre-mappings'],
    enabled: !!scanId,
  });

  const [activeTab, setActiveTab] = useState("overview");

  const groupedByTactic = mappings?.reduce((acc, mapping) => {
    const tactic = mapping.technique.tactic;
    if (!acc[tactic]) {
      acc[tactic] = [];
    }
    acc[tactic].push(mapping);
    return acc;
  }, {} as Record<string, MitreAttackMapping[]>) || {};

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return "destructive";
    if (confidence >= 60) return "default";
    return "secondary";
  };

  const getTacticIcon = (tactic: string) => {
    switch (tactic) {
      case "initial-access": return <Target className="w-4 h-4" />;
      case "execution": return <AlertTriangle className="w-4 h-4" />;
      case "persistence": return <Shield className="w-4 h-4" />;
      case "discovery": return <Eye className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  const downloadMitreReport = async () => {
    try {
      const response = await fetch(`/api/scans/${scanId}/mitre-report`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `mitre_attack_report_${scanId}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Failed to download MITRE report:', error);
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>MITRE ATT&CK Analysis</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="h-4 bg-gray-200 rounded w-3/4 animate-pulse"></div>
            <div className="h-4 bg-gray-200 rounded w-1/2 animate-pulse"></div>
            <div className="h-4 bg-gray-200 rounded w-2/3 animate-pulse"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!mappings || mappings.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>MITRE ATT&CK Analysis</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-gray-500">No MITRE ATT&CK mappings found for this scan.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex justify-between items-center">
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            MITRE ATT&CK Analysis
          </CardTitle>
          <Button onClick={downloadMitreReport} variant="outline" size="sm">
            <Download className="w-4 h-4 mr-2" />
            Download Report
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="tactics">Tactics</TabsTrigger>
            <TabsTrigger value="techniques">Techniques</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2">
                    <Target className="w-5 h-5 text-blue-500" />
                    <div>
                      <p className="text-sm font-medium">Total Techniques</p>
                      <p className="text-2xl font-bold">{mappings.length}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2">
                    <Shield className="w-5 h-5 text-green-500" />
                    <div>
                      <p className="text-sm font-medium">Tactics Covered</p>
                      <p className="text-2xl font-bold">{Object.keys(groupedByTactic).length}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-red-500" />
                    <div>
                      <p className="text-sm font-medium">High Confidence</p>
                      <p className="text-2xl font-bold">
                        {mappings.filter(m => m.confidence >= 80).length}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">Tactic Distribution</h3>
              {Object.entries(groupedByTactic).map(([tactic, tacticMappings]) => (
                <div key={tactic} className="space-y-2">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      {getTacticIcon(tactic)}
                      <span className="font-medium capitalize">{tactic.replace('-', ' ')}</span>
                    </div>
                    <Badge variant="outline">{tacticMappings.length} techniques</Badge>
                  </div>
                  <Progress value={(tacticMappings.length / mappings.length) * 100} className="h-2" />
                </div>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="tactics" className="space-y-4">
            {Object.entries(groupedByTactic).map(([tactic, tacticMappings]) => (
              <Card key={tactic}>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    {getTacticIcon(tactic)}
                    <CardTitle className="capitalize">{tactic.replace('-', ' ')}</CardTitle>
                    <Badge variant="outline">{tacticMappings.length} techniques</Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {tacticMappings.map((mapping) => (
                      <div key={mapping.id} className="border rounded-lg p-3">
                        <div className="flex justify-between items-start mb-2">
                          <div>
                            <h4 className="font-medium">
                              {mapping.technique.techniqueId}: {mapping.technique.name}
                            </h4>
                            <p className="text-sm text-gray-600 mt-1">
                              {mapping.technique.description}
                            </p>
                          </div>
                          <Badge variant={getConfidenceColor(mapping.confidence)}>
                            {mapping.confidence}% confidence
                          </Badge>
                        </div>
                        
                        <div className="text-sm space-y-1">
                          <p><strong>Platform:</strong> {mapping.technique.platform}</p>
                          <p><strong>Detection:</strong> {mapping.technique.detection}</p>
                          <p><strong>Mitigation:</strong> {mapping.technique.mitigation}</p>
                          {mapping.reasoning && (
                            <p><strong>Reasoning:</strong> {mapping.reasoning}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))}
          </TabsContent>

          <TabsContent value="techniques" className="space-y-4">
            <div className="grid gap-4">
              {mappings.map((mapping) => (
                <Card key={mapping.id}>
                  <CardHeader>
                    <div className="flex justify-between items-start">
                      <div>
                        <CardTitle className="text-lg">
                          {mapping.technique.techniqueId}: {mapping.technique.name}
                        </CardTitle>
                        <div className="flex items-center gap-2 mt-2">
                          <Badge variant="outline">{mapping.technique.tactic}</Badge>
                          <Badge variant="outline">{mapping.technique.platform}</Badge>
                        </div>
                      </div>
                      <Badge variant={getConfidenceColor(mapping.confidence)}>
                        {mapping.confidence}% confidence
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <p className="text-sm">{mapping.technique.description}</p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                          <h4 className="font-medium mb-1">Detection</h4>
                          <p className="text-gray-600">{mapping.technique.detection}</p>
                        </div>
                        <div>
                          <h4 className="font-medium mb-1">Mitigation</h4>
                          <p className="text-gray-600">{mapping.technique.mitigation}</p>
                        </div>
                      </div>
                      
                      {mapping.reasoning && (
                        <div>
                          <h4 className="font-medium mb-1">AI Analysis</h4>
                          <p className="text-sm text-gray-600">{mapping.reasoning}</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}