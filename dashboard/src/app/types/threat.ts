// TypeScript types for Cyber Threat Detection Dashboard

/**
 * Hybrid IDS verdict source.
 *
 *  - "confirmed":      both Snort signature AND the ML model flagged this flow
 *  - "signature_only": Snort fired but ML said benign
 *  - "ml_only":        ML flagged it but no Snort signature matched
 *  - "benign":         neither system raised an alert (only sent when DEBUG)
 */
export type ThreatSource = 'confirmed' | 'signature_only' | 'ml_only' | 'benign';

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

  prediction: 'Normal' | 'Malicious' | 'Suspicious';
  confidence: number;
  severity?: 'High' | 'Medium' | 'Low';

  attack_type?: string;
  /** Attack family (DoS, BruteForce, BotnetInfiltration, ...) from stage-2 of the hierarchical model. */
  family?: string | null;
  /** Sub-attack leaf label (DoS-Hulk, FTP-BruteForce, ...) — alias of attack_type for clarity. */
  subtype?: string | null;
  /** Stage-1 binary-gate probability — p(attack). Note: calibration-shifted by the
   *  FPR<=1% threshold; on production NFStream-extracted features expect benign flows
   *  to land in 1e-5 to 1e-3 even though they cross tau1. Use stage2_p / stage3_p for
   *  the meaningful confidence signal. */
  stage1_p?: number;
  /** Top Stage-2 (family) probability. None for Normal predictions. */
  stage2_p?: number | null;
  /** Full Stage-2 per-family probability vector, keyed by family name. */
  stage2_probs?: Record<string, number> | null;
  /** Top Stage-3 (leaf) probability inside the chosen family.
   *  1.0 for single-leaf families (DDoS, Probe, WebAttack). */
  stage3_p?: number | null;
  /** Full Stage-3 per-leaf probability vector for the chosen family. */
  stage3_probs?: Record<string, number> | null;
  /** Hybrid verdict tag (see ThreatSource). Optional for backward-compat with old responses. */
  source?: ThreatSource;
  /** Active model version (manifest SHA-256 prefix or 'legacy-single'). */
  model_version?: string;
  /** Snort alert metadata when source != "ml_only". */
  snort_msg?: string;
  snort_sid?: number;
  snort_classtype?: string;
  snort_priority?: number;

  /** Analyst acknowledgement state. Default "new" on creation; analyst can flip
   *  to "reviewed" / "escalated" / "dismissed" via POST /predictions/{id}/ack. */
  ack_state?: AckState;
  ack_at?: string | null;
  ack_note?: string | null;
  /** Username of the analyst who set the current ack state (null while "new"). */
  ackBy?: string | null;
  /** Full ack audit trail, newest-first — present on the detail endpoint only. */
  ackHistory?: AckHistoryEntry[];

  mitre?: MitreEnrichment | null;
}

/** Acknowledgement workflow state on a stored prediction. */
export type AckState = 'new' | 'reviewed' | 'escalated' | 'dismissed';

/** One entry in a prediction's ack audit trail (newest-first), as returned
 *  inline on `GET /predictions/{id}`. `by` is the actor's username. */
export interface AckHistoryEntry {
  from_state: AckState;
  to_state: AckState;
  note: string | null;
  at: string | null;
  by: string | null;
}

/** Server-side suppression rule. Matched future flows are dropped before
 *  they reach predictions_store — see app/core/suppression.py. */
export type SuppressionKind = 'sid' | 'src_ip' | 'src_cidr' | 'flow_key';
export interface Suppression {
  id: string;
  kind: SuppressionKind;
  value: string;
  created_at: string;
  expires_at?: string | null;
  note?: string | null;
  hits?: number;
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

/**
 * Slim list-view shape returned by `GET /predictions` and the streaming
 * `result_batch` events. Omits the heavy fields (`stage2_probs`,
 * `stage3_probs`, `mlFeatures`, `mitre.techniques`) so a list of 80k+
 * rows stays well under 50 MB. Fetch the full record via
 * `GET /predictions/{id}` when an analyst opens the detail drawer.
 */
export interface ThreatPredictionSummary {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  packetSize: number;
  duration: number;
  prediction: 'Normal' | 'Malicious' | 'Suspicious';
  attack_type?: string | null;
  confidence: number;
  severity?: 'High' | 'Medium' | 'Low' | null;
  family?: string | null;
  subtype?: string | null;
  stage1_p?: number;
  stage2_p?: number | null;
  stage3_p?: number | null;
  source?: ThreatSource;
  model_version?: string;
  ack_state?: AckState;
  ack_at?: string | null;
  ack_note?: string | null;
  /** Username of the analyst who set the current ack state (null while "new"). */
  ackBy?: string | null;
  snort_msg?: string;
  snort_sid?: number;
  snort_classtype?: string;
  snort_priority?: number;
  /** MITRE summary — `tactics` for badges, plus `confidence_band` and
   *  `unmapped` flag. `techniques` lives only on the detail endpoint. */
  mitre?: {
    confidence_band?: string;
    tactics?: MitreTactic[];
    unmapped?: boolean;
    attack_type?: string;
    description?: string;
  } | null;
}

/** Grouped (`?group=campaign`) row — a `ThreatPredictionSummary` for the
 *  representative member plus rollup counts and a capped child id sample
 *  for the drawer's "view related" / bulk-ack flows. */
export interface ThreatPredictionGroup extends ThreatPredictionSummary {
  count: number;
  firstSeen: string;
  lastSeen: string;
  /** Up to 50 child ids — enough for bulk-ack short campaigns. For larger
   *  groups, ack via `POST /predictions/ack/by-match`. */
  sampleIds: string[];
}

/** Paginated `/predictions` response. `grouped` is true when the request
 *  used `?group=campaign`; in that case `items` is `ThreatPredictionGroup[]`. */
export interface PredictionsPage {
  total: number;
  offset: number;
  limit: number;
  grouped?: boolean;
  items: ThreatPredictionSummary[] | ThreatPredictionGroup[];
}

/** Per-ack-state counts for the AlertsPage tab badges. */
export interface PredictionCounts {
  total: number;
  new: number;
  reviewed: number;
  escalated: number;
  dismissed: number;
}

/** True breakdown over the *whole* analysed set, computed server-side.
 *  Stays accurate even when `predictions` is capped for the browser. */
export interface BatchCounts {
  normal: number;
  malicious: number;
  suspicious: number;
  confirmed: number;
  signature_only: number;
  ml_only: number;
  benign: number;
}

export interface BatchPredictionResult {
  success: boolean;
  /** Total flows analysed and persisted to Postgres. */
  total: number;
  /** Number of rows actually returned to the browser. Equals `total` unless
   *  the result was capped (large upload) — see `predictions.length`. */
  returned?: number;
  /** Accurate verdict/prediction counts over all `total` flows. Present on
   *  capped results so the UI can show real numbers, not sample-derived ones. */
  counts?: BatchCounts;
  predictions: ThreatPredictionSummary[];
}

/**
 * NDJSON events emitted by `/analyze/upload/stream`. Stage events fire at
 * each milestone (extract_start, extract_progress, extract_done,
 * snort_start/done, predict_start/done, format_start). `result` is the
 * final line and carries the full predictions list; `error` aborts the
 * stream with a `detail` message.
 */
export type UploadProgressEvent =
  | { event: 'stage'; stage: string; [k: string]: unknown }
  | { event: 'heartbeat' }
  /** Legacy single-shot result line (one giant JSON line). Kept for
   *  backward-compat with callers that still hit the original endpoint. */
  | { event: 'result'; success?: boolean; total?: number; predictions?: ThreatPredictionSummary[] }
  /** Chunked-result protocol: `result_begin` (with `total`), then one or
   *  more `result_batch` events with `predictions` slices, finally
   *  `result_end`. Lets clients accumulate row-by-row without ever
   *  parsing a 100MB JSON line. */
  | { event: 'result_begin'; total: number; returned?: number }
  | { event: 'result_batch'; offset: number; predictions: ThreatPredictionSummary[] }
  | { event: 'result_end'; success: boolean; total: number; returned?: number; counts?: BatchCounts }
  | { event: 'error'; detail?: string };

export type AnalyticsRange = '1h' | '24h' | '7d' | '30d' | 'all';

export interface VerdictBreakdownEntry {
  source: ThreatSource;
  count: number;
  color: string;
}

export interface FamilyBreakdownEntry {
  family: string;
  count: number;
  color: string;
}

export interface LeafBreakdownEntry {
  leaf: string;
  family: string;
  count: number;
  color: string;
}

export interface TopIpEntry {
  ip: string;
  count: number;
}

export interface TopPortEntry {
  port: number;
  count: number;
  /** Well-known service label (e.g. "HTTP", "HTTPS"). Empty if unmapped. */
  label?: string;
}

export interface AttackerVictimPairEntry {
  src: string;
  dst: string;
  count: number;
  topFamily: string;
  color?: string;
}

export interface SeverityByFamilyEntry {
  family: string;
  high: number;
  medium: number;
  low: number;
  total: number;
  color?: string;
}

export interface HourlyTimelineEntry {
  /** ISO hour bucket (e.g. "2026-05-24T15:00:00"). */
  hour: string;
  normal: number;
  malicious: number;
  suspicious: number;
  /** Per-family attack counts for this hour. Empty when the hour had only
   *  benign traffic. Feeds the Hour × Family heatmap. */
  families?: Record<string, number>;
}

export interface MitreTacticCountEntry {
  tactic: string;
  count: number;
  color?: string;
}

export interface MitreTechniqueCountEntry {
  id: string;
  name: string;
  url: string;
  tactic: string;
  count: number;
  color?: string;
}

export interface AnalyticsData {
  normalCount: number;
  maliciousCount: number;
  timelineData: { time?: string; step?: number; normal: number; suspicious: number }[];
  topMaliciousIPs: { ip: string; count: number }[];
  severityCounts: {
    high: number;
    medium: number;
    low: number;
  };
  attackCategories: { name: string; value: number; color: string }[];
  protocolDistribution: { name: string; count: number; color?: string }[];
  featureImportance: { feature: string; importance: number }[];
  /** Subset of `maliciousCount` that came from ml_only (verdict=Suspicious). */
  suspiciousCount?: number;
  /** Hybrid verdict counts (confirmed / signature_only / ml_only / benign). */
  verdictBreakdown?: VerdictBreakdownEntry[];
  /** Per-family counts (6 hierarchical families). */
  familyBreakdown?: FamilyBreakdownEntry[];
  /** Per-leaf counts (15 leaves), each tagged with its family. */
  leafBreakdown?: LeafBreakdownEntry[];
  /** Echo of the range applied by the backend. */
  timeRangeApplied?: AnalyticsRange;
  /** Total flows in the filtered window. */
  totalFlows?: number;
  /** Unfiltered store size — lets the UI distinguish "store empty" from
   *  "store has data but the active time window excluded it". */
  storeTotal?: number;
  /** ISO timestamp from the server when this response was built. Used as
   *  a cache-bust witness — two consecutive responses with the same value
   *  prove the browser/proxy is serving a cached response. */
  serverTime?: string;
  /** Uvicorn worker pid. Used to detect multi-process state mismatches —
   *  if `pid` differs between two responses, multiple workers are running
   *  and each has its own predictions_store. */
  processId?: number;
  // --- SOC rehaul (2026-05-24) ---
  /** Top 5 destination IPs by attack count. */
  topDestinations?: TopIpEntry[];
  /** Top 10 attacked destination ports + service label. */
  topTargetedPorts?: TopPortEntry[];
  /** Top 10 attacker→victim pairs with their dominant attack family. */
  attackerVictimPairs?: AttackerVictimPairEntry[];
  /** Severity counts pivoted by family — stacked bar source. */
  severityByFamily?: SeverityByFamilyEntry[];
  /** Real hour-bucketed timeline (normal / malicious / suspicious). */
  hourlyTimeline?: HourlyTimelineEntry[];
  /** SOC operational KPIs — MTTA, backlog, oldest unacked alert age,
   *  count of alerts already acked in this window. Backed by ack_state
   *  fields already on each prediction. */
  operationalKpis?: {
    mttaSeconds: number | null;
    backlog: number;
    oldestUnackedAgeSeconds: number;
    ackedInWindow: number;
    mttaSampleSize?: number;
  };
  /** Same-shape aggregations over the prior equal-length window. Used by
   *  the KPI cards to render up/down deltas. Null for range=all (no
   *  comparable prior window). */
  prior?: {
    normalCount: number;
    maliciousCount: number;
    severityCounts: { high: number; medium: number; low: number };
    verdictBreakdown: { source: string; count: number }[];
  } | null;
  /** MITRE ATT&CK tactic distribution aggregated from per-row enrichment. */
  mitreTacticCounts?: MitreTacticCountEntry[];
  /** Per-technique flow counts. Each row carries its parent tactic and the
   *  attack.mitre.org URL so the analytics chart can group/color by tactic
   *  and link out to ATT&CK. */
  mitreTechniqueCounts?: MitreTechniqueCountEntry[];
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

/**
 * Live SSE event from /live/stream.
 *
 * The backend prediction field contains the raw model class label:
 *   - "Benign" → displayed as "Normal"
 *   - Any attack label (DDoS, PortScan, Bot, etc.) → displayed as "Malicious"
 *   - "Snort-Only" → displayed as "Malicious" (Snort flagged, no ML flow data)
 *
 * Use `getLiveDisplayPrediction()` helper to normalize for display.
 */
export interface LivePacket {
  id: string;
  timestamp: string;
  flow_key?: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;

  /** Raw model class: "Benign", "DDoS", "PortScan", "Bot", "Snort-Only", etc. */
  prediction: string;
  confidence: number;
  severity?: 'High' | 'Medium' | 'Low' | null;
  attack_type?: string | null;

  /** Hierarchical-model fields (filled when MODEL_MODE=hierarchical). */
  family?: string | null;
  subtype?: string | null;
  /** Stage-1 binary-gate probability — see ThreatPrediction.stage1_p for the
   *  calibration caveat. Prefer stage2_p / stage3_p as the confidence signal. */
  stage1_p?: number;
  /** Top Stage-2 (family) probability. None for Normal predictions. */
  stage2_p?: number | null;
  /** Full Stage-2 per-family probability vector, keyed by family name. */
  stage2_probs?: Record<string, number> | null;
  /** Top Stage-3 (leaf) probability inside the chosen family.
   *  1.0 for single-leaf families (DDoS, Probe, WebAttack). */
  stage3_p?: number | null;
  /** Full Stage-3 per-leaf probability vector for the chosen family. */
  stage3_probs?: Record<string, number> | null;

  /** Hybrid verdict source. */
  source?: ThreatSource;
  model_version?: string;

  /** Snort 3 alert metadata */
  snort_msg: string;
  snort_sid: number;
  snort_classtype: string;
  snort_priority: number;
  snort_action: string;
  snort_timestamp: string;

  /** MITRE ATT&CK enrichment */
  mitre?: MitreEnrichment | null;
}

/** Normalized display prediction for the UI */
export type DisplayPrediction = 'Normal' | 'Malicious' | 'Suspicious';

/** Convert raw backend prediction to UI display label.
 *
 * `Suspicious` is the ml_only verdict cell — ML flagged but Snort didn't
 * corroborate. The eval data shows ml_only precision = 0.48, so we render
 * these as a distinct middle state rather than collapsing them to Malicious.
 */
export function getLiveDisplayPrediction(raw: string): DisplayPrediction {
  const lower = raw.toLowerCase();
  if (lower === 'benign' || lower === 'normal') return 'Normal';
  if (lower === 'suspicious') return 'Suspicious';
  return 'Malicious';
}

export interface LogFileInfo {
  filename: string;
  size_bytes: number;
  created: string;
}

// --- Live session control plane (POST /live/session etc.) ---

/** Where the live stream pulls flows from. */
export type LiveSource = 'interface' | 'pcap';

/** Detection engines active for the session. */
export type DetectionMode = 'ml' | 'snort' | 'hybrid';

/** PCAP replay speed multiplier. 0 means "Max" (no pacing). */
export type ReplaySpeed = 0 | 1 | 2 | 10;

/** Server-side description of the active live session. */
export interface LiveSession {
  session_id: string;
  source: LiveSource;
  detection_mode: DetectionMode;
  speed: number | null;
  started_at: string;
  pcap_attached: boolean;
  /** Server-side flag: events stream into the Alerts queue (Postgres) when true.
   *  Defaults to true for pcap sessions and false for interface sessions. */
  persist_to_alerts: boolean;
  log_csv_url: string;
  log_ndjson_url: string;
  row_count: number;
}

/** Lifecycle event emitted by the LiveTrafficStream singleton. */
export type LiveStreamLifecycleEvent =
  | { kind: 'open' }
  | { kind: 'reconnecting'; attempt: number; in_ms: number }
  | { kind: 'closed' }
  | { kind: 'session_ended'; reason?: string };

/** Format of the downloaded session log. */
export type SessionLogFormat = 'csv' | 'ndjson';

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
  /** Severity tier as emitted by the hierarchical model (kept alongside risk_level
   *  so the upload-page detail panel can render the same ConfidenceQuality cue as
   *  the live dashboard). */
  severity?: 'High' | 'Medium' | 'Low' | null;
  /** Sub-attack leaf label. */
  attack_type?: string | null;
  /** Attack family from Stage 2 of the hierarchical model. */
  family?: string | null;
  /** Stage-1 binary gate probability (routing only — see ThreatPrediction.stage1_p). */
  stage1_p?: number;
  /** Top Stage-2 (family) probability. */
  stage2_p?: number | null;
  /** Full Stage-2 per-family probability vector. */
  stage2_probs?: Record<string, number> | null;
  /** Top Stage-3 (leaf) probability inside the chosen family. */
  stage3_p?: number | null;
  /** Full Stage-3 per-leaf probability vector. */
  stage3_probs?: Record<string, number> | null;
  /** Hybrid verdict source (confirmed / signature_only / ml_only / benign). */
  source?: ThreatSource;
  /** Snort alert metadata for confirmed/signature_only rows. */
  snort_msg?: string;
  snort_sid?: number;
  snort_classtype?: string;
  snort_priority?: number;
  /** Analyst acknowledgement state. */
  ack_state?: AckState;
  ack_at?: string | null;
  ack_note?: string | null;
  /** MITRE ATT&CK enrichment, when the backend mapper resolved it. */
  mitre?: MitreEnrichment | null;
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

// --- MITRE ATT&CK Types ---

export interface MitreTechnique {
  id: string;
  name: string;
  url: string;
}

export interface MitreTactic {
  id: string;
  name: string;
  techniques?: MitreTechnique[];
}

export interface MitreEnrichment {
  confidence_band: 'low' | 'high' | 'very_high';
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
}

export interface MitreConfidenceBand {
  min: number;
  max: number;
  label: string;
}

export interface MitreMatrixEntry {
  category: string;
  description: string;
  tactics: {
    id: string;
    name: string;
    techniques: MitreTechnique[];
  }[];
}

export interface MitreMatrixData {
  version: string;
  framework: string;
  min_confidence: number;
  confidence_bands: Record<string, MitreConfidenceBand>;
  entries: MitreMatrixEntry[];
  /** Attack-type leaves observed at runtime that have no mapping entry. */
  unmapped_attack_types?: string[];
}
