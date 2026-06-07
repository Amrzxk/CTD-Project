import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Code } from 'lucide-react';

export function APIDocumentation() {
  const endpoints = [
    {
      method: 'GET',
      path: '/health',
      description: 'Check backend health status',
      methodColor: 'bg-brand/20 text-brand border-brand/50'
    },
    {
      method: 'POST',
      path: '/predict',
      description: 'Single threat prediction',
      methodColor: 'bg-sev-low/20 text-sev-low border-sev-low/50'
    },
    {
      method: 'POST',
      path: '/predict/batch',
      description: 'Batch CSV file processing',
      methodColor: 'bg-sev-low/20 text-sev-low border-sev-low/50'
    },
    {
      method: 'GET',
      path: '/predictions',
      description: 'Get all predictions',
      methodColor: 'bg-brand/20 text-brand border-brand/50'
    },
    {
      method: 'GET',
      path: '/analytics',
      description: 'Get analytics data',
      methodColor: 'bg-brand/20 text-brand border-brand/50'
    }
  ];

  return (
    <Card className="bg-panel/70 border-line backdrop-blur">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Code className="w-5 h-5 text-sev-low" />
          <CardTitle className="text-foreground">API Endpoints</CardTitle>
        </div>
        <CardDescription className="text-muted-foreground">
          FastAPI backend endpoints for threat detection
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {endpoints.map((endpoint, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between p-3 bg-panel/80 rounded-lg border border-line"
            >
              <div className="flex items-center gap-3">
                <Badge variant="outline" className={endpoint.methodColor}>
                  {endpoint.method}
                </Badge>
                <code className="text-sm text-brand font-mono">{endpoint.path}</code>
              </div>
              <span className="text-sm text-muted-foreground">{endpoint.description}</span>
            </div>
          ))}
        </div>
        
        <div className="mt-4 p-4 bg-sev-low/10 border border-sev-low/30 rounded-lg">
          <p className="text-sm text-sev-low">
            <strong>Note:</strong> Currently running in mock mode. Set VITE_USE_MOCK=false in .env to connect to a real backend.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}