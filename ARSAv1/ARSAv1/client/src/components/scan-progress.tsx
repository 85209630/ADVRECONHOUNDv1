import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Clock, CheckCircle, AlertCircle, XCircle } from 'lucide-react';

interface ScanProgressProps {
  scanId: number;
  status: string;
  progress: number;
  message?: string;
  riskScore?: number;
}

export function ScanProgress({ scanId, status, progress, message, riskScore }: ScanProgressProps) {
  const getStatusIcon = () => {
    switch (status) {
      case 'running':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-500" />;
      default:
        return <AlertCircle className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case 'running':
        return 'bg-yellow-500';
      case 'completed':
        return 'bg-green-500';
      case 'failed':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getRiskLevel = (score: number) => {
    if (score >= 8) return { level: 'Critical', color: 'bg-red-500' };
    if (score >= 6) return { level: 'High', color: 'bg-orange-500' };
    if (score >= 4) return { level: 'Medium', color: 'bg-yellow-500' };
    return { level: 'Low', color: 'bg-green-500' };
  };

  return (
    <Card className="bg-gray-800 border-gray-700">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg text-white">Scan Progress</CardTitle>
          <div className="flex items-center space-x-2">
            {getStatusIcon()}
            <Badge variant="outline" className={`${getStatusColor()} text-white border-none`}>
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-300">Overall Progress</span>
            <span className="text-sm text-gray-300">{progress}%</span>
          </div>
          <Progress value={progress} className="h-2" />
        </div>

        {message && (
          <div className="text-sm text-gray-400 italic">
            {message}
          </div>
        )}

        {riskScore !== undefined && (
          <div className="bg-gray-900 p-4 rounded-lg">
            <div className="text-center">
              <div className="text-3xl font-bold text-orange-500 mb-2">
                {riskScore.toFixed(1)}
              </div>
              <div className="text-sm text-gray-400 mb-2">Risk Score</div>
              <Badge className={`${getRiskLevel(riskScore).color} text-white`}>
                {getRiskLevel(riskScore).level} Risk
              </Badge>
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-300">Scan ID</span>
            <span className="text-primary font-mono">#{scanId}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-300">Status</span>
            <span className="text-gray-300">{status}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
