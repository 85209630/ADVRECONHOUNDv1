import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Card, CardContent } from '@/components/ui/card';
import { Search, Globe } from 'lucide-react';
import { targetSchema, type TargetInput } from '@/lib/validation';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';

interface ScanFormProps {
  onScanStart: (scanId: number) => void;
}

export function ScanForm({ onScanStart }: ScanFormProps) {
  const [scanOptions, setScanOptions] = useState({
    subdomainEnumeration: true,
    vulnerabilityScanning: true,
    osintGathering: true,
    deepAnalysis: false,
  });

  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<TargetInput>({
    resolver: zodResolver(targetSchema),
    defaultValues: {
      target: '',
      scanType: 'comprehensive',
    },
  });

  const startScanMutation = useMutation({
    mutationFn: async (data: TargetInput) => {
      const response = await apiRequest('POST', '/api/scans', data);
      return response.json();
    },
    onSuccess: (scan) => {
      toast({
        title: "Scan Started",
        description: `Reconnaissance scan initiated for ${scan.target}`,
      });
      queryClient.invalidateQueries({ queryKey: ['/api/scans'] });
      onScanStart(scan.id);
      form.reset();
    },
    onError: (error) => {
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: TargetInput) => {
    startScanMutation.mutate(data);
  };

  return (
    <Card className="bg-gray-800 border-gray-700 max-w-2xl mx-auto">
      <CardContent className="p-8">
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <div className="flex gap-0">
              <FormField
                control={form.control}
                name="target"
                render={({ field }) => (
                  <FormItem className="flex-1">
                    <FormControl>
                      <div className="relative">
                        <Input
                          {...field}
                          placeholder="Enter target domain or IP address"
                          className="bg-gray-900 border-gray-700 text-white placeholder-gray-400 pr-12 rounded-l-xl rounded-r-none focus:border-primary"
                          disabled={startScanMutation.isPending}
                        />
                        <Globe className="absolute right-4 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button
                type="submit"
                disabled={startScanMutation.isPending}
                className="bg-primary hover:bg-primary/90 text-black font-semibold px-8 py-4 rounded-r-xl rounded-l-none"
              >
                {startScanMutation.isPending ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-2 border-black border-t-transparent mr-2" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4 mr-2" />
                    Start Scan
                  </>
                )}
              </Button>
            </div>

            <div className="flex flex-wrap gap-4 justify-center">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="subdomain"
                  checked={scanOptions.subdomainEnumeration}
                  onCheckedChange={(checked) =>
                    setScanOptions(prev => ({ ...prev, subdomainEnumeration: checked as boolean }))
                  }
                />
                <label htmlFor="subdomain" className="text-sm text-gray-300">
                  Subdomain Enumeration
                </label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="vulnerability"
                  checked={scanOptions.vulnerabilityScanning}
                  onCheckedChange={(checked) =>
                    setScanOptions(prev => ({ ...prev, vulnerabilityScanning: checked as boolean }))
                  }
                />
                <label htmlFor="vulnerability" className="text-sm text-gray-300">
                  Vulnerability Scanning
                </label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="osint"
                  checked={scanOptions.osintGathering}
                  onCheckedChange={(checked) =>
                    setScanOptions(prev => ({ ...prev, osintGathering: checked as boolean }))
                  }
                />
                <label htmlFor="osint" className="text-sm text-gray-300">
                  OSINT Gathering
                </label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="deep"
                  checked={scanOptions.deepAnalysis}
                  onCheckedChange={(checked) =>
                    setScanOptions(prev => ({ ...prev, deepAnalysis: checked as boolean }))
                  }
                />
                <label htmlFor="deep" className="text-sm text-gray-300">
                  Deep Analysis
                </label>
              </div>
            </div>
          </form>
        </Form>
      </CardContent>
    </Card>
  );
}
