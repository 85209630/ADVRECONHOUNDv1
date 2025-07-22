import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ScanForm } from "@/components/scan-form";
import { ScanResults } from "@/components/scan-results";
import { useWebSocket } from "@/hooks/use-websocket";
import {
  Search,
  Brain,
  NetworkIcon,
  Shield,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";
import type {
  Scan,
  Vulnerability,
  Subdomain,
  Technology,
} from "@shared/schema";

export default function Dashboard() {
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [scanUpdates, setScanUpdates] = useState<{ [key: number]: any }>({});
  const { isConnected, lastMessage } = useWebSocket();

  // Fetch recent scans
  const { data: scans, isLoading: scansLoading } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
    refetchInterval: 5000,
  });

  // Fetch active scan details
  const { data: activeScanData, isLoading: activeScanLoading } = useQuery<{
    scan: Scan;
    vulnerabilities: Vulnerability[];
    subdomains: Subdomain[];
    technologies: Technology[];
  }>({
    queryKey: ["/api/scans", activeScanId],
    enabled: !!activeScanId,
    refetchInterval: activeScanId ? 3000 : false,
  });

  // Handle WebSocket updates
  useEffect(() => {
    if (lastMessage && lastMessage.type === "scan_update") {
      setScanUpdates((prev) => ({
        ...prev,
        [lastMessage.scanId]: lastMessage.data,
      }));
    }
  }, [lastMessage]);

  const handleScanStart = (scanId: number) => {
    setActiveScanId(scanId);
  };

  const handleScanSelect = (scanId: number) => {
    setActiveScanId(scanId);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-green-500";
      case "running":
        return "bg-yellow-500";
      case "failed":
        return "bg-red-500";
      default:
        return "bg-gray-500";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="w-4 h-4" />;
      case "running":
        return (
          <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
        );
      case "failed":
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <div className="w-4 h-4 bg-gray-400 rounded-full" />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <Search className="text-primary text-2xl mr-3" />
              <h1 className="text-2xl font-bold text-primary">ReconHound</h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div
                  className={`w-2 h-2 rounded-full ${isConnected ? "bg-green-500" : "bg-red-500"}`}
                />
                <span className="text-sm text-gray-300">
                  {isConnected ? "Connected" : "Disconnected"}
                </span>
              </div>
              <Button className="bg-primary text-black hover:bg-primary/90">
                Profile
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-5xl font-bold mb-6">
            Advanced <span className="text-primary">Reconnaissance</span> &
            Security Analysis
          </h2>
          <p className="text-xl text-gray-300 mb-8 max-w-3xl mx-auto">
            AI-powered vulnerability reconnaissance toolkit for security
            professionals and penetration testers
          </p>

          <ScanForm onScanStart={handleScanStart} />
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h3 className="text-3xl font-bold text-center mb-12">
            Advanced Reconnaissance Features
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <Card className="bg-gray-900 border-gray-700 hover:border-primary transition-colors">
              <CardContent className="p-6">
                <Brain className="text-primary text-3xl mb-4" />
                <h4 className="text-xl font-semibold mb-3">
                  AI-Powered Analysis
                </h4>
                <p className="text-gray-300">
                  Machine learning algorithms analyze vulnerabilities and
                  provide intelligent risk assessments
                </p>
              </CardContent>
            </Card>

            <Card className="bg-gray-900 border-gray-700 hover:border-primary transition-colors">
              <CardContent className="p-6">
                <NetworkIcon className="text-primary text-3xl mb-4" />
                <h4 className="text-xl font-semibold mb-3">
                  Multi-Host Scanning
                </h4>
                <p className="text-gray-300">
                  Simultaneously scan multiple targets with advanced parallel
                  processing capabilities
                </p>
              </CardContent>
            </Card>

            <Card className="bg-gray-900 border-gray-700 hover:border-primary transition-colors">
              <CardContent className="p-6">
                <Shield className="text-primary text-3xl mb-4" />
                <h4 className="text-xl font-semibold mb-3">Ethical Hacking</h4>
                <p className="text-gray-300">
                  Built-in rate limiting and responsible disclosure practices
                  for ethical security testing
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Scan Results or Recent Scans */}
      <section className="py-20 bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          {activeScanData ? (
            <ScanResults
              scan={activeScanData.scan}
              vulnerabilities={activeScanData.vulnerabilities}
              subdomains={activeScanData.subdomains}
              technologies={activeScanData.technologies}
              scanProgress={scanUpdates[activeScanId!]}
            />
          ) : (
            <div className="space-y-6">
              <h3 className="text-3xl font-bold text-center mb-12">
                Recent Scans
              </h3>

              {scansLoading ? (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary border-t-transparent mx-auto mb-4" />
                  <p className="text-gray-400">Loading scan history...</p>
                </div>
              ) : scans && scans.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {scans.map((scan) => (
                    <Card
                      key={scan.id}
                      className="bg-gray-800 border-gray-700 hover:border-primary transition-colors cursor-pointer"
                      onClick={() => handleScanSelect(scan.id)}
                    >
                      <CardHeader className="pb-3">
                        <div className="flex justify-between items-start">
                          <div className="flex-1">
                            <CardTitle className="text-lg text-white truncate">
                              {scan.target}
                            </CardTitle>
                            <p className="text-sm text-gray-400 mt-1">
                              {scan.createdAt
                                ? new Date(scan.createdAt).toLocaleString()
                                : "Unknown"}
                            </p>
                          </div>
                          <Badge
                            className={`${getStatusColor(scan.status)} text-white flex items-center gap-1`}
                          >
                            {getStatusIcon(scan.status)}
                            {scan.status}
                          </Badge>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span className="text-gray-400">Scan Type:</span>
                            <span className="text-gray-300">
                              {scan.scanType}
                            </span>
                          </div>
                          {scan.riskScore && (
                            <div className="flex justify-between text-sm">
                              <span className="text-gray-400">Risk Score:</span>
                              <span className="text-orange-500 font-semibold">
                                {scan.riskScore}
                              </span>
                            </div>
                          )}
                          {scan.progress !== null && (
                            <div className="flex justify-between text-sm">
                              <span className="text-gray-400">Progress:</span>
                              <span className="text-gray-300">
                                {scan.progress}%
                              </span>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12">
                  <Search className="w-16 h-16 mx-auto mb-4 text-gray-500 opacity-50" />
                  <h4 className="text-xl font-semibold mb-2 text-gray-300">
                    No scans yet
                  </h4>
                  <p className="text-gray-400 mb-6">
                    Start your first reconnaissance scan to see results here.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </section>

      {/* Legal Disclaimer */}
      <section className="py-12 bg-gray-800 border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <Alert className="bg-gray-900 border-orange-500">
            <AlertTriangle className="h-4 w-4 text-orange-500" />
            <AlertDescription className="text-gray-300">
              <strong className="text-orange-500">
                Legal Disclaimer & Ethical Use:
              </strong>{" "}
              This tool is intended for authorized security testing and
              educational purposes only. Users must obtain proper authorization
              before scanning any targets. Unauthorized access to computer
              systems is illegal and may result in criminal prosecution.
            </AlertDescription>
          </Alert>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-800 py-8 border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center">
            <div className="flex items-center">
              <Search className="text-primary text-xl mr-3" />
              <span className="text-gray-300">ReconHound © 2025</span>
            </div>
            <div className="flex space-x-6">
              <a
                href="#"
                className="text-gray-400 hover:text-primary transition-colors"
              >
                GitHub
              </a>
              <a
                href="#"
                className="text-gray-400 hover:text-primary transition-colors"
              >
                Documentation
              </a>
              <a
                href="#"
                className="text-gray-400 hover:text-primary transition-colors"
              >
                Support
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
