// TypeScript types for Cyber Threat Detection Dashboard

export interface ThreatPrediction {
  id: string;
  timestamp: string;  
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  packetSize: number;
  duration: number;

  prediction: 'Normal' | 'Malicious';
  confidence: number;
  severity?: 'High' | 'Medium' | 'Low';

  attack_type?: string;
}

export interface ManualInputForm {
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  service: string;
  duration: number;
  sourceBytes: number;
  destinationBytes: number;
  sourcePackets: number;
  destinationPackets: number;
  sourceTTL: number;
  destinationTTL: number;
}

export interface BatchPredictionResult {
  success: boolean;
  total: number;
  predictions: ThreatPrediction[];
}

export interface AnalyticsData {
  normalCount: number;
  maliciousCount: number;
  timelineData: { time: string; normal: number; suspicious: number }[];
  topMaliciousIPs: { ip: string; count: number }[];
  severityCounts: {
    high: number;
    medium: number;
    low: number;
  };
  attackCategories: { name: string; value: number; color: string }[];
  featureImportance: { feature: string; importance: number }[];
}

export interface BackendHealth {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
}

export interface AlertNotification {
  id: string;
  type: 'critical' | 'warning' | 'info';
  message: string;
  timestamp: string;
  sourceIp?: string;
}

export interface LivePacket {
  id: string;
  src_ip: string;
  dst_ip: string;
  sport: number;
  dport: number;
  protocol: string;
  service: string;
  duration: number;
  sbytes: number;
  dbytes: number;
  spkts: number;
  dpkts: number;
  state: string;
  prediction: 'Normal' | 'Malicious' | 'Suspicious';
}

export interface AnalyzedPacket {
  id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  src_port: number;
  dst_port: number;
  packet_length: number;
  prediction: 'Normal' | 'Malicious' | 'Suspicious';
  risk_level: 'Critical' | 'High' | 'Medium' | 'Low' | 'None';
  ttl: number;
  flags: string;
  duration: number;
  mlFeatures: {
    sbytes: number;
    dbytes: number;
    spkts: number;
    dpkts: number;
    sload: number;
    dload: number;
    rate: number;
    sttl: number;
    dttl: number;
    dur: number;
  };
  aiExplanations: string[];
}