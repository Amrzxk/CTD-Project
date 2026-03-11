// Mock API Service for Cyber Threat Detection
import type { 
  ThreatPrediction, 
  ManualInputForm, 
  BatchPredictionResult, 
  AnalyticsData, 
  BackendHealth,
  AlertNotification,
  LivePacket,
  AnalyzedPacket
} from '../types/threat';

// Configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const USE_MOCK = import.meta.env.VITE_USE_MOCK !== 'false'; // Use mock by default

// Mock data generator
const generateMockPrediction = (input: Partial<ManualInputForm>): ThreatPrediction => {
  const isMalicious = Math.random() > 0.7;
  const confidence = 0.75 + Math.random() * 0.24;
  
  return {
    id: `pred_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    sourceIp: input.sourceIp || `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    destinationIp: input.destinationIp || `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    sourcePort: input.sourcePort || Math.floor(Math.random() * 65535),
    destinationPort: input.destinationPort || Math.floor(Math.random() * 65535),
    protocol: input.protocol || ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
    packetSize: input.packetSize || Math.floor(Math.random() * 1500),
    duration: input.duration || Math.random() * 100,
    prediction: isMalicious ? 'Malicious' : 'Normal',
    confidence: confidence,
    severity: isMalicious 
      ? confidence > 0.9 ? 'High' : confidence > 0.8 ? 'Medium' : 'Low'
      : undefined
  };
};


// Simulate network delay
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

class ThreatDetectionService {
  private mockData: ThreatPrediction[] = [];
  private alerts: AlertNotification[] = [];

  constructor() {
    // Generate some initial mock data
    this.initializeMockData();
  }

  private initializeMockData() {
    const count = 50;
    for (let i = 0; i < count; i++) {
      this.mockData.push(generateMockPrediction({
        sourceIp: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      }));
    }
  }

  // Single prediction endpoint
  async predictSingle(input: ManualInputForm): Promise<ThreatPrediction> {
    if (USE_MOCK) {
      await delay(800); // Simulate network delay
      const prediction = generateMockPrediction(input);
      this.mockData.unshift(prediction);
      
      // Generate alert if malicious and high severity
      if (prediction.prediction === 'Malicious' && prediction.severity === 'High') {
        this.createAlert({
          type: 'critical',
          message: `High severity threat detected from ${prediction.sourceIp}`,
          sourceIp: prediction.sourceIp
        });
      }
      
      return prediction;
    }

    // Real API call
    const response = await fetch(`${API_BASE_URL}/analyze/manual`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input)
    });

    if (!response.ok) {
      throw new Error('Failed to get prediction');
    }

    const data = await response.json();
    console.log("Backend response:", data);
    return data;
  }

  // Batch prediction endpoint (CSV upload)
  async predictBatch(file: File): Promise<BatchPredictionResult> {
    if (USE_MOCK) {
      await delay(2000); // Simulate processing time
      
      // Parse CSV (simplified mock)
      const predictions: ThreatPrediction[] = [];
      const rowCount = Math.floor(Math.random() * 20) + 10;
      
      for (let i = 0; i < rowCount; i++) {
        const pred = generateMockPrediction({});
        predictions.push(pred);
        this.mockData.unshift(pred);
      }

      return {
        success: true,
        total: predictions.length,
        predictions
      };
    }

    // Real API call
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE_URL}/analyze/upload`, {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      throw new Error('Failed to process batch prediction');
    }

    return response.json();
  }

  // Get all predictions
  async getAllPredictions(): Promise<ThreatPrediction[]> {
    if (USE_MOCK) {
      await delay(300);
      return [...this.mockData];
    }

    const response = await fetch(`${API_BASE_URL}/predictions`);
    if (!response.ok) {
      throw new Error('Failed to fetch predictions');
    }

    return response.json();
  }

  // Get analytics data
  async getAnalytics(): Promise<AnalyticsData> {
    if (USE_MOCK) {
      await delay(400);
      
      const normalCount = this.mockData.filter(p => p.prediction === 'Normal').length;
      const maliciousCount = this.mockData.filter(p => p.prediction === 'Malicious').length;

      // Generate timeline data (last 24 hours)
      const timelineData = Array.from({ length: 24 }, (_, i) => ({
        time: `${23 - i}h ago`,
        normal: Math.floor(Math.random() * 40) + 20,
        suspicious: Math.floor(Math.random() * 15) + 2
      })).reverse();

      // Top malicious IPs
      const maliciousIPs = this.mockData
        .filter(p => p.prediction === 'Malicious')
        .reduce((acc, pred) => {
          acc[pred.sourceIp] = (acc[pred.sourceIp] || 0) + 1;
          return acc;
        }, {} as Record<string, number>);

      const topMaliciousIPs = Object.entries(maliciousIPs)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

      // Severity counts
      const severityCounts = this.mockData
        .filter(p => p.prediction === 'Malicious')
        .reduce((acc, pred) => {
          if (pred.severity === 'High') acc.high++;
          else if (pred.severity === 'Medium') acc.medium++;
          else if (pred.severity === 'Low') acc.low++;
          return acc;
        }, { high: 0, medium: 0, low: 0 });

      // Attack category distribution
      const attackCategories = [
        { name: 'DDoS', value: Math.floor(Math.random() * 30) + 15, color: '#ff3366' },
        { name: 'Port Scan', value: Math.floor(Math.random() * 25) + 10, color: '#00ccff' },
        { name: 'Brute Force', value: Math.floor(Math.random() * 20) + 8, color: '#ffaa00' },
        { name: 'SQL Injection', value: Math.floor(Math.random() * 15) + 5, color: '#00ff88' },
        { name: 'XSS', value: Math.floor(Math.random() * 12) + 3, color: '#cc66ff' },
      ];

      // Feature importance data
      const featureImportance = [
        { feature: 'sbytes', importance: 0.89 + Math.random() * 0.1 },
        { feature: 'dbytes', importance: 0.82 + Math.random() * 0.1 },
        { feature: 'dur', importance: 0.76 + Math.random() * 0.1 },
        { feature: 'spkts', importance: 0.71 + Math.random() * 0.08 },
        { feature: 'dpkts', importance: 0.65 + Math.random() * 0.08 },
        { feature: 'sload', importance: 0.58 + Math.random() * 0.08 },
        { feature: 'dload', importance: 0.52 + Math.random() * 0.08 },
        { feature: 'rate', importance: 0.45 + Math.random() * 0.08 },
        { feature: 'sttl', importance: 0.38 + Math.random() * 0.08 },
        { feature: 'dttl', importance: 0.31 + Math.random() * 0.08 },
      ].sort((a, b) => b.importance - a.importance);

      return {
        normalCount,
        maliciousCount,
        timelineData,
        topMaliciousIPs,
        severityCounts,
        attackCategories,
        featureImportance
      };
    }

    const response = await fetch(`${API_BASE_URL}/analytics`);
    if (!response.ok) {
      throw new Error('Failed to fetch analytics');
    }

    return response.json();
  }

  // Health check
  async checkHealth(): Promise<BackendHealth> {
    if (USE_MOCK) {
      await delay(100);
      return {
        status: 'healthy',
        timestamp: new Date().toISOString()
      };
    }

    const response = await fetch(`${API_BASE_URL}/health`);
    if (!response.ok) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }

    return response.json();
  }

  // Alert management
  private createAlert(alert: Omit<AlertNotification, 'id' | 'timestamp'>) {
    const newAlert: AlertNotification = {
      ...alert,
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString()
    };
    this.alerts.unshift(newAlert);
  }

  getAlerts(): AlertNotification[] {
    return [...this.alerts];
  }

  clearAlert(id: string) {
    this.alerts = this.alerts.filter(a => a.id !== id);
  }

  // Export to CSV
  exportToCSV(predictions: ThreatPrediction[]): string {
    const headers = ['Timestamp', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Packet Size', 'Duration', 'Prediction', 'Confidence', 'Severity'];
    const rows = predictions.map(p => [
      p.timestamp,
      p.sourceIp,
      p.destinationIp,
      p.sourcePort,
      p.destinationPort,
      p.protocol,
      p.packetSize,
      p.duration,
      p.prediction,
      p.confidence.toFixed(2),
      p.severity || 'N/A'
    ]);

    return [headers, ...rows].map(row => row.join(',')).join('\n');
  }

  // Generate mock live packets
  generateLivePacket(): LivePacket {
    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'];
    const services = ['http', 'https', 'dns', 'ssh', 'ftp', 'smtp', 'telnet', '-'];
    const states = ['FIN', 'CON', 'INT', 'REQ', 'RST', 'ECO', 'CLO', 'ACC'];
    const predictions: LivePacket['prediction'][] = ['Normal', 'Malicious', 'Suspicious'];
    const predWeights = [0.6, 0.25, 0.15];
    const rand = Math.random();
    const prediction = rand < predWeights[0] ? predictions[0] : rand < predWeights[0] + predWeights[1] ? predictions[1] : predictions[2];

    return {
      id: `pkt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      src_ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      dst_ip: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      sport: Math.floor(Math.random() * 65535),
      dport: [80, 443, 22, 53, 8080, 3306, 21, 25][Math.floor(Math.random() * 8)],
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      service: services[Math.floor(Math.random() * services.length)],
      duration: parseFloat((Math.random() * 120).toFixed(3)),
      sbytes: Math.floor(Math.random() * 50000),
      dbytes: Math.floor(Math.random() * 50000),
      spkts: Math.floor(Math.random() * 500),
      dpkts: Math.floor(Math.random() * 500),
      state: states[Math.floor(Math.random() * states.length)],
      prediction
    };
  }

  getLivePackets(count: number = 20): LivePacket[] {
    return Array.from({ length: count }, () => this.generateLivePacket());
  }

  // Generate mock analyzed packets for packet analyzer
  generateAnalyzedPackets(predictions: ThreatPrediction[]): AnalyzedPacket[] {
    const flagOptions = ['SYN', 'SYN-ACK', 'ACK', 'FIN', 'RST', 'PSH-ACK', 'URG', 'FIN-ACK', 'RST-ACK', 'SYN-FIN'];
    const normalExplanations = [
      'Standard HTTP request pattern',
      'Regular DNS query behavior',
      'Normal connection handshake',
      'Expected packet size range',
      'Typical session duration',
      'Standard port utilization',
    ];

    function maliciousExplanations(attack_type?: string) {
      const attack = attack_type || "network attack";

      return [
        `High packet rate detected - potential ${attack}`,
        'Abnormal destination port behavior',
        'Suspicious connection duration',
        `Suspicious traffic behavior linked to ${attack}`,
        'Unusually large payload size',
        'SYN flood signature detected',
        'Anomalous TTL value',
        'Port scanning behavior detected',
        'Brute force login pattern',
        `Network activity matches known ${attack} characteristics`,
        'Data exfiltration signature',
      ];
  }

    return predictions.map((p) => {
      const rand = Math.random();
      const prediction: AnalyzedPacket['prediction'] = 
        p.prediction === 'Malicious' ? 'Malicious' : 'Normal';

      const riskMap: Record<string, AnalyzedPacket['risk_level']> = {
        Malicious:
          p.severity === 'High'
            ? 'Critical'
            : p.severity === 'Medium'
            ? 'High'
            : 'Medium',
        Normal: 'None',
      };

      const explanationPool = p.prediction === 'Malicious'
        ? maliciousExplanations(p.attack_type)
        : normalExplanations;
      const numExplanations = prediction === 'Normal' ? 1 : (Math.floor(Math.random() * 2) + 2);
      const shuffled = [...explanationPool].sort(() => Math.random() - 0.5);
      const aiExplanations = shuffled.slice(0, numExplanations);

      const sbytes = Math.floor(Math.random() * 50000);
      const dbytes = Math.floor(Math.random() * 50000);
      const dur = parseFloat((p.duration || Math.random() * 60).toFixed(3));

      return {
        id: p.id,
        timestamp: p.timestamp,
        src_ip: p.sourceIp,
        dst_ip: p.destinationIp,
        protocol: p.protocol,
        src_port: p.sourcePort,
        dst_port: p.destinationPort,
        packet_length: p.packetSize || Math.floor(Math.random() * 1500) + 40,
        prediction,
        risk_level: riskMap[prediction],
        ttl: Math.floor(Math.random() * 128) + 32,
        flags: flagOptions[Math.floor(Math.random() * flagOptions.length)],
        duration: dur,
        mlFeatures: {
          sbytes,
          dbytes,
          spkts: Math.floor(Math.random() * 500),
          dpkts: Math.floor(Math.random() * 500),
          sload: parseFloat((Math.random() * 1000000).toFixed(2)),
          dload: parseFloat((Math.random() * 1000000).toFixed(2)),
          rate: parseFloat((Math.random() * 1000).toFixed(2)),
          sttl: Math.floor(Math.random() * 255),
          dttl: Math.floor(Math.random() * 255),
          dur,
        },
        aiExplanations,
      };
    });
  }
}

// Export singleton instance
export const threatService = new ThreatDetectionService();