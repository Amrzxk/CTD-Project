import type {
  ThreatPrediction,
  ThreatPredictionSummary,
  PredictionsPage,
  PredictionCounts,
  ManualInputForm,
  BatchPredictionResult,
  AnalyticsData,
  AnalyticsRange,
  AckState,
  BackendHealth,
  AlertNotification,
  LivePacket,
  AnalyzedPacket,
  LogFileInfo,
  MitreMatrixData,
  MitreMatrixEntry,
  UploadProgressEvent,
  Suppression,
  SuppressionKind,
  LiveSession,
  LiveSource,
  DetectionMode,
  LiveStreamLifecycleEvent,
  SessionLogFormat,
} from '../types/threat';

// Configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
// Safe default: hit the REAL API unless mock is explicitly requested. The
// old `!== 'false'` default meant "mock unless the build arg is exactly
// 'false'" — one dropped VITE_USE_MOCK build-arg would have shipped an
// all-mock "demo". Opt into mock with VITE_USE_MOCK=true.
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

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

/** Optional listener — set by the AuthContext so a 401 on any API call
 *  can immediately punt the user to /login without a per-page check.
 *  Decoupled from React so non-component code paths (e.g. SSE) can
 *  share it. */
type UnauthorizedHandler = () => void;
let onUnauthorized: UnauthorizedHandler | null = null;
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null) {
  onUnauthorized = handler;
}

/** fetch wrapper that:
 *   1. Always sends the session cookie (`credentials: 'include'`).
 *   2. Defaults to `cache: 'no-store'` so prediction-store reads aren't
 *      served stale by the browser.
 *   3. On 401, fires the registered `onUnauthorized` handler so the app
 *      can redirect to /login without each call site checking.
 *  Returns the same `Response` shape as native fetch so callers don't
 *  need to change. */
export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(input, {
    credentials: 'include',
    cache: 'no-store',
    ...init,
  });
  if (res.status === 401 && onUnauthorized) {
    onUnauthorized();
  }
  return res;
}

/** LRU cache for detail-drawer lookups so toggling back to a recently-viewed
 *  row doesn't hit the network again. Keeping this small (50 entries) is
 *  enough to feel instant during typical SOC review patterns and avoids
 *  retaining the heavy per-row payloads after the user moves on. */
const DETAIL_CACHE_MAX = 50;

class ThreatDetectionService {
  private alerts: AlertNotification[] = [];
  private detailCache = new Map<string, ThreatPrediction>();

  // Single prediction endpoint
  async predictSingle(input: ManualInputForm): Promise<ThreatPrediction> {
    if (USE_MOCK) {
      await delay(800);
      const prediction = generateMockPrediction(input);
      if (prediction.prediction === 'Malicious' && prediction.severity === 'High') {
        this.createAlert({
          type: 'critical',
          message: `High severity threat detected from ${prediction.sourceIp}`,
          sourceIp: prediction.sourceIp,
        });
      }
      return prediction;
    }

    // Real API call
    const response = await apiFetch(`${API_BASE_URL}/analyze/manual`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input)
    });

    if (!response.ok) {
      throw new Error('Failed to get prediction');
    }

    const data = await response.json();
    return data;
  }

  // Batch prediction endpoint (CSV / PCAP upload).
  //
  // If `onProgress` is provided, hits `/analyze/upload/stream` and consumes
  // the NDJSON event stream, calling `onProgress(event)` for each progress
  // line. The final 'result' event carries the same shape the legacy
  // endpoint returns. Without `onProgress` we fall back to the single-shot
  // `/analyze/upload` for backward compatibility.
  async predictBatch(
    file: File,
    onProgress?: (event: UploadProgressEvent) => void,
  ): Promise<BatchPredictionResult> {
    if (USE_MOCK) {
      await delay(2000);
      const predictions: ThreatPredictionSummary[] = [];
      const rowCount = Math.floor(Math.random() * 20) + 10;
      for (let i = 0; i < rowCount; i++) {
        predictions.push(generateMockPrediction({}));
      }
      return { success: true, total: predictions.length, predictions };
    }

    const formData = new FormData();
    formData.append('file', file);

    // Single-shot fallback when caller doesn't care about progress events.
    if (!onProgress) {
      const response = await apiFetch(`${API_BASE_URL}/analyze/upload`, {
        method: 'POST',
        body: formData,
      });
      if (!response.ok) throw new Error('Failed to process batch prediction');
      const data = await response.json();
      // Back-compat: older servers omit `returned`; default it to the row count.
      if (data.returned === undefined) data.returned = data.predictions?.length ?? 0;
      return data;
    }

    // Streaming path — read NDJSON line-by-line.
    const response = await apiFetch(`${API_BASE_URL}/analyze/upload/stream`, {
      method: 'POST',
      body: formData,
    });
    if (!response.ok || !response.body) {
      throw new Error('Failed to process batch prediction');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    // Chunked result protocol: result_begin → result_batch* → result_end.
    // We accumulate `accumulated` across batches and seal it on result_end.
    // Falls back to the legacy single `result` event if the server hasn't
    // adopted chunking yet.
    let accumulated: ThreatPredictionSummary[] = [];
    let accumulatedTotal = 0;
    let finalResult: BatchPredictionResult | null = null;

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let newlineIdx = buffer.indexOf('\n');
      while (newlineIdx >= 0) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);
        newlineIdx = buffer.indexOf('\n');
        if (!line) continue;

        let evt: UploadProgressEvent;
        try {
          evt = JSON.parse(line);
        } catch {
          continue;
        }

        if (evt.event === 'result_begin') {
          accumulated = [];
          accumulatedTotal = evt.total;
          onProgress(evt);
        } else if (evt.event === 'result_batch') {
          for (const p of evt.predictions) accumulated.push(p);
          onProgress(evt);
        } else if (evt.event === 'result_end') {
          finalResult = {
            success: evt.success,
            total: evt.total,
            returned: evt.returned ?? accumulated.length,
            counts: evt.counts,
            predictions: accumulated,
          };
          onProgress(evt);
        } else if (evt.event === 'result') {
          // Legacy single-blob result event — kept for back-compat.
          finalResult = {
            success: evt.success ?? true,
            total: evt.total ?? 0,
            returned: evt.predictions?.length ?? 0,
            predictions: evt.predictions ?? [],
          };
        } else if (evt.event === 'error') {
          throw new Error(evt.detail || 'Streaming upload failed');
        } else {
          onProgress(evt);
        }
      }
    }

    if (!finalResult) {
      throw new Error('Stream ended without a result event');
    }
    // Suppress unused-variable warning when batches arrive but result_end
    // hasn't fired yet (shouldn't happen, but be defensive).
    void accumulatedTotal;
    return finalResult;
  }

  /** Paginated `/predictions` fetch — the preferred way to load a list of
   *  predictions for any table view. Returns a `PredictionsPage` with
   *  `total` so callers can drive pagination controls.
   *
   *  `ack_state` / `severity` / `source` filter server-side so the client
   *  doesn't have to download and re-filter the full store. */
  async getPredictionsPage(opts: {
    limit?: number;
    offset?: number;
    ack_state?: AckState;
    severity?: 'high' | 'medium' | 'low';
    source?: 'confirmed' | 'signature_only' | 'ml_only' | 'benign';
    q?: string;
    src_cidr?: string;
    dst_cidr?: string;
    port_min?: number;
    port_max?: number;
    sort?: 'time' | 'severity' | 'family' | 'source';
    dir?: 'asc' | 'desc';
    group?: 'campaign';
  } = {}): Promise<PredictionsPage> {
    if (USE_MOCK) {
      await delay(150);
      return { total: 0, offset: 0, limit: opts.limit ?? 200, items: [] };
    }
    const params = new URLSearchParams();
    if (opts.limit !== undefined) params.set('limit', String(opts.limit));
    if (opts.offset !== undefined) params.set('offset', String(opts.offset));
    if (opts.ack_state) params.set('ack_state', opts.ack_state);
    if (opts.severity) params.set('severity', opts.severity);
    if (opts.source) params.set('source', opts.source);
    if (opts.q) params.set('q', opts.q);
    if (opts.src_cidr) params.set('src_cidr', opts.src_cidr);
    if (opts.dst_cidr) params.set('dst_cidr', opts.dst_cidr);
    if (opts.port_min !== undefined) params.set('port_min', String(opts.port_min));
    if (opts.port_max !== undefined) params.set('port_max', String(opts.port_max));
    if (opts.sort) params.set('sort', opts.sort);
    if (opts.dir) params.set('dir', opts.dir);
    if (opts.group) params.set('group', opts.group);
    // Cache buster — predictions_store is in-memory state, must never be
    // served from the browser's HTTP cache.
    params.set('_', String(Date.now()));
    const response = await apiFetch(`${API_BASE_URL}/predictions?${params.toString()}`, {
      cache: 'no-store',
    });
    if (!response.ok) throw new Error('Failed to fetch predictions');
    return response.json();
  }

  /** Lazy-fetch the full record (heavy fields included) by id, with a
   *  small LRU cache so toggling back to a recently-viewed row is free. */
  async getPredictionDetail(id: string): Promise<ThreatPrediction> {
    const cached = this.detailCache.get(id);
    if (cached) {
      // Refresh LRU position.
      this.detailCache.delete(id);
      this.detailCache.set(id, cached);
      return cached;
    }
    const response = await apiFetch(
      `${API_BASE_URL}/predictions/${encodeURIComponent(id)}?_=${Date.now()}`,
    );
    if (!response.ok) throw new Error('Failed to fetch prediction detail');
    const data: ThreatPrediction = await response.json();
    this.detailCache.set(id, data);
    if (this.detailCache.size > DETAIL_CACHE_MAX) {
      // Drop the oldest entry — JS Maps preserve insertion order so the
      // first key is the least recently inserted.
      const first = this.detailCache.keys().next().value;
      if (first !== undefined) this.detailCache.delete(first);
    }
    return data;
  }

  /** Tab-badge counts for AlertsPage — cheap aggregate, no row payload. */
  async getPredictionsCounts(): Promise<PredictionCounts> {
    if (USE_MOCK) {
      await delay(100);
      return { total: 0, new: 0, reviewed: 0, escalated: 0, dismissed: 0 };
    }
    const response = await apiFetch(`${API_BASE_URL}/predictions/counts?_=${Date.now()}`, {
      cache: 'no-store',
    });
    if (!response.ok) throw new Error('Failed to fetch prediction counts');
    return response.json();
  }

  /** @deprecated Prefer `getPredictionsPage`. Kept so the legacy
   *  DashboardPage call still compiles during the migration; internally
   *  fetches a single large page. */
  async getAllPredictions(): Promise<ThreatPredictionSummary[]> {
    if (USE_MOCK) return [];
    const page = await this.getPredictionsPage({ limit: 1000, offset: 0 });
    return page.items;
  }

  // Get analytics data — `range` filters predictions to the requested window
  // (1h / 24h / 7d / 30d / all). Default "all" matches the legacy behavior.
  async getAnalytics(range: AnalyticsRange = 'all'): Promise<AnalyticsData> {
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

    const response = await apiFetch(
      `${API_BASE_URL}/analytics?range=${encodeURIComponent(range)}&_=${Date.now()}`,
    );
    if (!response.ok) {
      throw new Error('Failed to fetch analytics');
    }

    return response.json();
  }

  /** Clear the backend's in-memory predictions_store on demand and drop
   *  the local detail-drawer cache so a freshly cleared store doesn't
   *  show stale rows. Returns the previous store size + uvicorn pid so
   *  callers can show a confirmation toast and detect process restarts
   *  (pid before == pid after means same uvicorn, just an in-memory wipe). */
  async clearStore(): Promise<{ cleared: number; pid: number; server_time: string }> {
    const res = await apiFetch(`${API_BASE_URL}/_debug/clear?_=${Date.now()}`, {
      method: 'POST',
      cache: 'no-store',
    });
    if (!res.ok) throw new Error('Failed to clear store');
    this.detailCache.clear();
    return res.json();
  }

  /** Read-only diagnostic dump of the backend store state. Used by the
   *  analytics empty-state when /predictions/counts disagrees with
   *  /analytics — confirms whether the empty result is a stale-cache
   *  or stale-process issue. */
  async getStoreDebug(): Promise<{
    pid: number;
    process_started_at: string;
    server_time: string;
    store_size: number;
    max_stored: number;
    oldest_timestamp: string | null;
    newest_timestamp: string | null;
    sample_ids: string[];
  }> {
    const response = await apiFetch(`${API_BASE_URL}/_debug/store?_=${Date.now()}`, {
      cache: 'no-store',
    });
    if (!response.ok) throw new Error('Failed to fetch debug store info');
    return response.json();
  }

  // Update the ack state on a stored prediction. Returns the updated prediction.
  async ackPrediction(
    id: string,
    state: AckState,
    note?: string | null,
  ): Promise<ThreatPrediction> {
    if (USE_MOCK) {
      await delay(120);
      const idx = this.mockData.findIndex((p) => p.id === id);
      if (idx >= 0) {
        this.mockData[idx] = {
          ...this.mockData[idx],
          ack_state: state,
          ack_at: new Date().toISOString(),
          ack_note: note ?? null,
        };
        return this.mockData[idx];
      }
      throw new Error(`Prediction ${id} not found`);
    }

    const response = await apiFetch(
      `${API_BASE_URL}/predictions/${encodeURIComponent(id)}/ack`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ state, note: note ?? null }),
      },
    );
    if (!response.ok) {
      throw new Error(`Failed to acknowledge prediction ${id}`);
    }
    return response.json();
  }

  /** Suppression rules — server-side enforcement. */
  async listSuppressions(): Promise<Suppression[]> {
    if (USE_MOCK) return [];
    const res = await apiFetch(`${API_BASE_URL}/suppressions?_=${Date.now()}`, { cache: 'no-store' });
    if (!res.ok) throw new Error('Failed to list suppressions');
    return res.json();
  }

  async createSuppression(rule: {
    kind: SuppressionKind;
    value: string;
    expires_at?: string | null;
    note?: string | null;
  }): Promise<Suppression> {
    if (USE_MOCK) {
      return { id: `mock_${Date.now()}`, ...rule, created_at: new Date().toISOString() } as Suppression;
    }
    const res = await apiFetch(`${API_BASE_URL}/suppressions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    if (!res.ok) {
      const detail = await res.json().catch(() => null);
      throw new Error(detail?.detail || 'Failed to create suppression');
    }
    return res.json();
  }

  async deleteSuppression(id: string): Promise<{ removed: boolean }> {
    if (USE_MOCK) return { removed: true };
    const res = await apiFetch(`${API_BASE_URL}/suppressions/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Failed to delete suppression');
    return res.json();
  }

  /** Ack every stored prediction matching a (sourceIp, destinationIp, family)
   *  triple. Used by the grouped/campaign view to ack thousands of children
   *  without round-tripping the full id list. Omitted keys are wildcards. */
  async ackPredictionsByMatch(match: {
    sourceIp?: string | null;
    destinationIp?: string | null;
    family?: string | null;
    state: AckState;
    note?: string | null;
  }): Promise<{ updated: number }> {
    if (USE_MOCK) {
      await delay(120);
      return { updated: 0 };
    }
    const response = await apiFetch(`${API_BASE_URL}/predictions/ack/by-match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(match),
    });
    if (!response.ok) throw new Error('Ack-by-match failed');
    return response.json();
  }

  /** Bulk-ack many predictions in one server pass. Returns
   *  { updated, missing } so the UI can toast progress and warn about ids
   *  that didn't exist (e.g. dropped after MAX_STORED_PREDICTIONS eviction). */
  async ackPredictionsBulk(
    ids: string[],
    state: AckState,
    note?: string | null,
  ): Promise<{ updated: number; missing: string[] }> {
    if (USE_MOCK) {
      await delay(120);
      return { updated: ids.length, missing: [] };
    }
    const response = await apiFetch(`${API_BASE_URL}/predictions/ack/bulk`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids, state, note: note ?? null }),
    });
    if (!response.ok) throw new Error('Bulk acknowledgement failed');
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

    const response = await apiFetch(`${API_BASE_URL}/health`);
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
  exportToCSV(predictions: ThreatPredictionSummary[]): string {
    const headers = [
      'Timestamp','Source IP','Destination IP','Source Port','Destination Port',
      'Protocol','Packet Size','Duration','Prediction','Family','Attack Type',
      'Verdict','Confidence','Severity','Snort SID','Snort Msg','Ack State',
    ];
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
      p.family ?? '',
      p.attack_type ?? '',
      p.source ?? '',
      p.confidence.toFixed(2),
      p.severity || 'N/A',
      p.snort_sid ?? '',
      // Quote the Snort msg — it can contain commas/spaces.
      `"${(p.snort_msg ?? '').replace(/"/g, '""')}"`,
      p.ack_state ?? 'new',
    ]);

    return [headers, ...rows].map(row => row.join(',')).join('\n');
  }

  /** Pretty-printed JSON export of the slim summary shape. Use for bulk
   *  export when downstream consumers want the full row keys (more useful
   *  than the flat CSV when feeding into a SIEM or scripting). */
  exportToJSON(predictions: ThreatPredictionSummary[]): string {
    return JSON.stringify(predictions, null, 2);
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
      const prediction: AnalyzedPacket['prediction'] =
        p.prediction === 'Malicious'
          ? 'Malicious'
          : p.prediction === 'Suspicious'
          ? 'Suspicious'
          : 'Normal';

      const riskMap: Record<string, AnalyzedPacket['risk_level']> = {
        Malicious:
          p.severity === 'High'
            ? 'Critical'
            : p.severity === 'Medium'
            ? 'High'
            : 'Medium',
        Suspicious: 'Medium',
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
        // Carry hierarchical-model fields through so the detail drawer can
        // render per-stage probability bars (same shape as live dashboard).
        severity: p.severity ?? null,
        attack_type: p.attack_type ?? null,
        family: p.family ?? null,
        stage1_p: p.stage1_p,
        stage2_p: p.stage2_p ?? null,
        stage2_probs: p.stage2_probs ?? null,
        stage3_p: p.stage3_p ?? null,
        stage3_probs: p.stage3_probs ?? null,
        // Hybrid verdict + Snort metadata so the upload page can render the
        // same verdict-cell + Snort drawer as the live dashboard.
        source: p.source,
        snort_msg: p.snort_msg,
        snort_sid: p.snort_sid,
        snort_classtype: p.snort_classtype,
        snort_priority: p.snort_priority,
        ack_state: p.ack_state,
        ack_at: p.ack_at,
        ack_note: p.ack_note,
        mitre: p.mitre ?? null,
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

// ---------- Log Files ----------

export async function getLogFiles(): Promise<LogFileInfo[]> {
  const res = await apiFetch(`${API_BASE_URL}/live/logs`);
  if (!res.ok) throw new Error('Failed to list logs');
  return res.json();
}

export function getLogDownloadUrl(filename: string): string {
  return `${API_BASE_URL}/live/logs/${encodeURIComponent(filename)}`;
}

// ---------- MITRE ATT&CK ----------

export async function getMitreMatrix(): Promise<MitreMatrixData> {
  const res = await apiFetch(`${API_BASE_URL}/mitre/matrix`);
  if (!res.ok) throw new Error('Failed to load MITRE matrix');
  return res.json();
}

export async function getMitreLookup(category: string): Promise<MitreMatrixEntry & { category: string }> {
  const res = await apiFetch(`${API_BASE_URL}/mitre/lookup/${encodeURIComponent(category)}`);
  if (!res.ok) throw new Error(`No MITRE mapping for: ${category}`);
  return res.json();
}

// ---------- Live SSE Stream & Session lifecycle ----------

type LivePacketHandler = (packet: LivePacket) => void;
type LifecycleHandler = (event: LiveStreamLifecycleEvent) => void;

/** Exponential-backoff schedule in ms (with ±20% jitter) used when an
 *  EventSource closes unexpectedly. Five attempts is enough for a typical
 *  API restart (`docker compose restart api` finishes in ~10s on this stack);
 *  beyond that we surface a lasting "closed" state and let the user reconnect
 *  explicitly. */
const RECONNECT_BACKOFF_MS = [1000, 2000, 4000, 8000, 16000];

/** Singleton driving the /live/* control plane.
 *
 *  Owns three pieces of state:
 *    1. The active EventSource (current SSE connection).
 *    2. The current session id (mirrored from POST /live/session).
 *    3. A set of subscribers — `subscribe()` for per-packet handlers,
 *       `onLifecycle()` for connection-state pings the UI uses to render
 *       "Reconnecting…" banners.
 *
 *  Reconnect logic is *not* delegated to the browser's native EventSource
 *  retry — we manage it explicitly so the UI can tell the analyst what's
 *  happening and so we can stop after the schedule is exhausted.
 */
class LiveTrafficStream {
  private eventSource: EventSource | null = null;
  private listeners: Set<LivePacketHandler> = new Set();
  private lifecycleListeners: Set<LifecycleHandler> = new Set();
  private _connected = false;
  private _sessionId: string | null = null;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionallyClosed = false;
  // Bumped on every startSession() and closeStream(). Each openStream() snapshots
  // the value; inflight onmessage callbacks from a stale EventSource drop their
  // events if the generation has since moved. Belt-and-braces guard against the
  // server-side warm-up gate — covers buffered events still in the browser parse
  // queue and the reconnect race where a new ES briefly co-exists with the old one.
  private _generation = 0;

  get connected(): boolean {
    return this._connected;
  }

  get sessionId(): string | null {
    return this._sessionId;
  }

  // ----------------- Public control plane -----------------

  /** Start a new live session (auto-stops any existing one on the server)
   *  and immediately open the SSE for it. For interface mode the stream
   *  starts producing events as soon as flows arrive. For pcap mode the
   *  caller must follow up with `attachPcap()`. */
  async startSession(
    source: LiveSource,
    detection_mode: DetectionMode,
    speed: number | null = null,
    persist_to_alerts: boolean | null = null,
  ): Promise<LiveSession> {
    const res = await apiFetch(`${API_BASE_URL}/live/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source, detection_mode, speed, persist_to_alerts }),
    });
    if (!res.ok) {
      const detail = await safeError(res);
      throw new Error(detail || `Failed to start session (HTTP ${res.status})`);
    }
    const session = (await res.json()) as LiveSession;
    this._sessionId = session.session_id;
    // Bump generation BEFORE opening so any inflight onmessage from a
    // prior EventSource that hasn't been GC'd yet drops its payload.
    this._generation += 1;
    this.openStream();
    return session;
  }

  /** Upload the PCAP for a pcap-mode session. Starts replay server-side. */
  async attachPcap(sessionId: string, file: File): Promise<LiveSession> {
    const fd = new FormData();
    fd.append('file', file);
    const res = await apiFetch(
      `${API_BASE_URL}/live/session/${encodeURIComponent(sessionId)}/pcap`,
      { method: 'POST', body: fd },
    );
    if (!res.ok) {
      const detail = await safeError(res);
      throw new Error(detail || `Failed to attach pcap (HTTP ${res.status})`);
    }
    return (await res.json()) as LiveSession;
  }

  /** Stop the active session and close the SSE. Idempotent. */
  async stopSession(): Promise<void> {
    const id = this._sessionId;
    this.intentionallyClosed = true;
    this.closeStream();
    this._sessionId = null;
    if (!id) return;
    try {
      await apiFetch(
        `${API_BASE_URL}/live/session/${encodeURIComponent(id)}`,
        { method: 'DELETE' },
      );
    } catch {
      // Ignore — UI has already been told the session ended.
    }
  }

  /** Fetch the server's view of the active session (may exist on another
   *  worker, hence the round-trip). Returns null if no session is running. */
  async fetchActiveSession(): Promise<LiveSession | null> {
    const res = await apiFetch(`${API_BASE_URL}/live/session`);
    if (!res.ok) return null;
    const data = await res.json();
    return data || null;
  }

  /** Attach to a session that already exists on the server (typical resume
   *  flow after a hard refresh, or when the session was started in another
   *  tab / on another gunicorn worker). Sets the session id so the SSE URL
   *  carries `?session=<id>` and the API can shadow-resolve it from Redis
   *  if the local worker's registry is empty. */
  resumeSession(sessionId: string): void {
    this._sessionId = sessionId;
    this._generation += 1;
    this.intentionallyClosed = false;
    this.openStream();
  }

  /** Build a download URL for the per-session log in the requested format. */
  sessionLogUrl(sessionId: string, format: SessionLogFormat = 'csv'): string {
    return `${API_BASE_URL}/live/session/${encodeURIComponent(sessionId)}/log?format=${format}`;
  }

  /** Fetch the per-session log via the auth cookie and trigger a download.
   *
   *  Why not `window.open(url)`? That's a cross-origin top-level navigation
   *  to the API host. The session cookie is `SameSite=Strict`, so the
   *  browser doesn't send it on that nav and the new tab gets a 401. We
   *  pull the bytes via apiFetch (credentials: 'include'), build a blob
   *  URL, and synthesise an `<a download>` click. The blob URL is revoked
   *  immediately afterwards.
   */
  async downloadSessionLog(
    sessionId: string,
    format: SessionLogFormat = 'csv',
  ): Promise<void> {
    const res = await apiFetch(this.sessionLogUrl(sessionId, format));
    if (!res.ok) {
      const detail = await safeError(res);
      throw new Error(detail || `Failed to download log (HTTP ${res.status})`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement('a');
      a.href = url;
      // Best-effort filename — the backend's Content-Disposition (set by
      // FastAPI's FileResponse) is the authority, but supplying `download`
      // here gives us a fallback if no header is present.
      a.download = `session_${sessionId}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } finally {
      // Give the browser a tick to start the download before tearing
      // down the blob URL. Without this, some browsers (Safari) cancel
      // the in-flight download.
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  }

  // ----------------- Subscriptions -----------------

  subscribe(handler: LivePacketHandler) {
    this.listeners.add(handler);
    return () => {
      this.listeners.delete(handler);
    };
  }

  onLifecycle(handler: LifecycleHandler) {
    this.lifecycleListeners.add(handler);
    return () => {
      this.lifecycleListeners.delete(handler);
    };
  }

  // ----------------- Legacy entry points -----------------

  /** Connect without starting a new session — used by tooling that wants to
   *  observe whichever session happens to be active on the server. */
  connect() {
    this.intentionallyClosed = false;
    this.openStream();
  }

  /** Hard close from the UI. Does NOT stop the server-side session — call
   *  `stopSession()` for that. */
  disconnect() {
    this.intentionallyClosed = true;
    this.closeStream();
  }

  // ----------------- Internals -----------------

  private openStream() {
    if (this.eventSource) return;

    const id = this._sessionId;
    const url =
      `${API_BASE_URL}/live/stream` + (id ? `?session=${encodeURIComponent(id)}` : '');
    // Snapshot the generation at open time. Any handler that fires for this
    // EventSource compares against the current `_generation`; if they differ,
    // a newer session has taken over and these events are stale.
    const gen = this._generation;
    // `withCredentials: true` so the browser sends our httpOnly session
    // cookie on cross-origin SSE (dashboard on :5173 → api on :8000).
    this.eventSource = new EventSource(url, { withCredentials: true });

    this.eventSource.onopen = () => {
      if (gen !== this._generation) return;
      this._connected = true;
      this.reconnectAttempt = 0;
      this.emitLifecycle({ kind: 'open' });
    };

    this.eventSource.onmessage = (event) => {
      if (gen !== this._generation) return;
      try {
        const packet: LivePacket = JSON.parse(event.data);
        this.listeners.forEach((fn) => fn(packet));
      } catch {
        // Skip malformed events — typical only during early WebSocket-like
        // reconnects before the upstream is ready.
      }
    };

    // `event: session_ended` is emitted by the SSE generator when the active
    // session is stopped on the server. Treat as a terminal close — the UI
    // owner can then prompt the analyst to start a fresh session.
    this.eventSource.addEventListener('session_ended', (ev) => {
      if (gen !== this._generation) return;
      let reason: string | undefined;
      try {
        const data = JSON.parse((ev as MessageEvent).data) as { reason?: string };
        reason = data?.reason;
      } catch {
        /* ignore */
      }
      this.intentionallyClosed = true;
      this._sessionId = null;
      this.closeStream();
      this.emitLifecycle({ kind: 'session_ended', reason });
    });

    this.eventSource.onerror = () => {
      // EventSource reports onerror both for transient drops (state CONNECTING)
      // and hard closes (state CLOSED). Only schedule a reconnect on the latter.
      this._connected = false;
      const wasClosed = this.eventSource?.readyState === 2 /* CLOSED */;
      if (this.intentionallyClosed) {
        this.closeStream();
        return;
      }
      if (wasClosed) {
        this.scheduleReconnect();
      }
    };
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.eventSource) {
      try {
        this.eventSource.close();
      } catch {
        /* ignore */
      }
      this.eventSource = null;
    }
    if (this.reconnectAttempt >= RECONNECT_BACKOFF_MS.length) {
      // Give up — emit terminal 'closed' so the UI can recommend manual restart.
      this.reconnectAttempt = 0;
      this.emitLifecycle({ kind: 'closed' });
      return;
    }
    const base = RECONNECT_BACKOFF_MS[this.reconnectAttempt];
    const jitter = base * (Math.random() * 0.4 - 0.2); // ±20%
    const delay = Math.max(250, Math.round(base + jitter));
    this.reconnectAttempt += 1;
    this.emitLifecycle({
      kind: 'reconnecting',
      attempt: this.reconnectAttempt,
      in_ms: delay,
    });
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.openStream();
    }, delay);
  }

  private closeStream() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.eventSource) {
      try {
        this.eventSource.close();
      } catch {
        /* ignore */
      }
      this.eventSource = null;
    }
    // Bump generation so any lingering callbacks from the closed
    // EventSource drop their payloads — see `openStream()` snapshot.
    this._generation += 1;
    if (this._connected) {
      this._connected = false;
      this.emitLifecycle({ kind: 'closed' });
    } else if (this.reconnectAttempt === 0) {
      this.emitLifecycle({ kind: 'closed' });
    }
    this.reconnectAttempt = 0;
  }

  private emitLifecycle(event: LiveStreamLifecycleEvent) {
    this.lifecycleListeners.forEach((fn) => {
      try {
        fn(event);
      } catch {
        /* ignore */
      }
    });
  }
}

async function safeError(res: Response): Promise<string | null> {
  try {
    const data = await res.json();
    if (typeof data?.detail === 'string') return data.detail;
    if (typeof data === 'string') return data;
    return null;
  } catch {
    return null;
  }
}

export const liveTrafficStream = new LiveTrafficStream();

// Export singleton instance
export const threatService = new ThreatDetectionService();