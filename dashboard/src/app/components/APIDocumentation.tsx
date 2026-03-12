import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Code } from 'lucide-react';

export function APIDocumentation() {
  const endpoints = [
    {
      method: 'GET',
      path: '/health',
      description: 'Check backend health status',
      methodColor: 'bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/50'
    },
    {
      method: 'POST',
      path: '/predict',
      description: 'Single threat prediction',
      methodColor: 'bg-[#00ccff]/20 text-[#00ccff] border-[#00ccff]/50'
    },
    {
      method: 'POST',
      path: '/predict/batch',
      description: 'Batch CSV file processing',
      methodColor: 'bg-[#00ccff]/20 text-[#00ccff] border-[#00ccff]/50'
    },
    {
      method: 'GET',
      path: '/predictions',
      description: 'Get all predictions',
      methodColor: 'bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/50'
    },
    {
      method: 'GET',
      path: '/analytics',
      description: 'Get analytics data',
      methodColor: 'bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/50'
    }
  ];

  return (
    <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Code className="w-5 h-5 text-[#00ccff]" />
          <CardTitle className="text-white">API Endpoints</CardTitle>
        </div>
        <CardDescription className="text-gray-400">
          FastAPI backend endpoints for threat detection
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {endpoints.map((endpoint, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between p-3 bg-[#0f1825]/80 rounded-lg border border-[#1a2540]"
            >
              <div className="flex items-center gap-3">
                <Badge variant="outline" className={endpoint.methodColor}>
                  {endpoint.method}
                </Badge>
                <code className="text-sm text-[#00ff88] font-mono">{endpoint.path}</code>
              </div>
              <span className="text-sm text-gray-400">{endpoint.description}</span>
            </div>
          ))}
        </div>
        
        <div className="mt-4 p-4 bg-[#00ccff]/10 border border-[#00ccff]/30 rounded-lg">
          <p className="text-sm text-[#00ccff]">
            <strong>Note:</strong> Currently running in mock mode. Set VITE_USE_MOCK=false in .env to connect to a real backend.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}