import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Code, Server, Database, Globe, Layers } from 'lucide-react';
import type { Technology } from '@shared/schema';

interface TechStackDisplayProps {
  technologies: Technology[];
}

export function TechStackDisplay({ technologies }: TechStackDisplayProps) {
  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'web_server':
        return <Server className="w-4 h-4" />;
      case 'database':
        return <Database className="w-4 h-4" />;
      case 'framework':
        return <Code className="w-4 h-4" />;
      case 'cms':
        return <Globe className="w-4 h-4" />;
      default:
        return <Layers className="w-4 h-4" />;
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'web_server':
        return 'bg-blue-500';
      case 'database':
        return 'bg-green-500';
      case 'framework':
        return 'bg-purple-500';
      case 'cms':
        return 'bg-orange-500';
      default:
        return 'bg-gray-500';
    }
  };

  const groupedTechnologies = technologies.reduce((acc, tech) => {
    if (!acc[tech.category]) {
      acc[tech.category] = [];
    }
    acc[tech.category].push(tech);
    return acc;
  }, {} as Record<string, Technology[]>);

  const getCategoryTitle = (category: string) => {
    switch (category) {
      case 'web_server':
        return 'Web Servers';
      case 'database':
        return 'Databases';
      case 'framework':
        return 'Frameworks';
      case 'cms':
        return 'Content Management';
      default:
        return 'Other Technologies';
    }
  };

  if (technologies.length === 0) {
    return (
      <Card className="bg-gray-800 border-gray-700">
        <CardHeader>
          <CardTitle className="text-xl text-white flex items-center">
            <Code className="w-5 h-5 text-green-500 mr-2" />
            Technology Stack
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <div className="text-gray-400 mb-2">
              <Code className="w-12 h-12 mx-auto mb-4 opacity-50" />
              No technologies detected
            </div>
            <p className="text-sm text-gray-500">
              The scan could not identify any specific technologies.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-gray-800 border-gray-700">
      <CardHeader>
        <CardTitle className="text-xl text-white flex items-center">
          <Code className="w-5 h-5 text-green-500 mr-2" />
          Technology Stack ({technologies.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {Object.entries(groupedTechnologies).map(([category, techs]) => (
            <div key={category}>
              <h4 className="text-lg font-semibold mb-3 text-gray-300 flex items-center">
                {getCategoryIcon(category)}
                <span className="ml-2">{getCategoryTitle(category)}</span>
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {techs.map((tech) => (
                  <div key={tech.id} className="bg-gray-900 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <Badge className={`${getCategoryColor(tech.category)} text-white`}>
                          {getCategoryIcon(tech.category)}
                          <span className="ml-1">{tech.category.replace('_', ' ')}</span>
                        </Badge>
                      </div>
                      {tech.confidence && (
                        <div className="text-xs text-gray-400">
                          {tech.confidence}% confidence
                        </div>
                      )}
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-white font-medium">{tech.name}</span>
                      {tech.version && (
                        <span className="text-primary font-mono text-sm">
                          v{tech.version}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
