import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'motion/react';
import { Eye, ShieldAlert, Gauge, Info, Target, ExternalLink } from 'lucide-react';
import { toast } from 'sonner';

import { Badge } from '../components/ui/badge';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../components/ui/alert-dialog';

import { LiveStreamHeader } from '../components/LiveStreamHeader';
import { LiveStatsRow } from '../components/LiveStatsRow';
import { LiveAnalyticsRow } from '../components/LiveAnalyticsRow';
import { LiveEventTable } from '../components/LiveEventTable';
import { RiskBadge, severityToRisk, type RiskLevel } from '../components/RiskBadge';
import { ConfidenceQuality } from '../components/ConfidenceQuality';
import { StageProbBars } from '../components/StageProbBars';
import { VerdictBadge, sourceMeta } from '../components/VerdictBadge';

import {
  useRingBufferCount,
  useRingBufferItems,
} from '../hooks/useRingBuffer';
import { useLiveStream } from '../contexts/LiveStreamContext';
import { liveTrafficStream } from '../services/threatDetectionService';
import type {
  DetectionMode,
  LivePacket,
  LiveSource,
  ReplaySpeed,
} from '../types/threat';
import { getLiveDisplayPrediction } from '../types/threat';

/** Dedicated SOC live page.
 *
 *  All cross-route state — the ring buffer, EPS counter, SSE subscription,
 *  active session, drawer selection — lives in `LiveStreamProvider` so it
 *  survives navigation. This page is a thin consumer: it owns only the
 *  pre-start form state (source / mode / speed) and the "supersede an
 *  existing session" confirm dialog. */
export default function LiveStreamPage() {
  // --- Form state (only meaningful while idle) ---
  const [source, setSource] = useState<LiveSource>('interface');
  const [mode, setMode] = useState<DetectionMode>('hybrid');
  const [speed, setSpeed] = useState<ReplaySpeed>(1);
  // Persist toggle — track the analyst's explicit choice so we can send a
  // boolean rather than null and override the per-source server default.
  // Mirrors the server policy on each source flip so the box visually
  // matches what would happen if they started right now.
  const [persistToAlerts, setPersistToAlerts] = useState(false);
  useEffect(() => {
    setPersistToAlerts(source === 'pcap');
  }, [source]);

  // Confirm dialog when a session is already running (server side) and
  // the user tries to start a new one.
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pendingStart, setPendingStart] = useState<
    {
      source: LiveSource;
      mode: DetectionMode;
      speed: ReplaySpeed;
      persist: boolean;
    } | null
  >(null);

  // --- Cross-route state (from provider) ---
  const {
    store,
    eps,
    activeSession,
    connected,
    reconnecting,
    selected,
    setSelected,
    startSession,
    stopSession,
    attachPcap,
    downloadSessionLog,
    clear,
  } = useLiveStream();

  // Remember the most recent session id so the log stays downloadable after
  // Stop — the server serves a stopped session's log from disk by id.
  const [lastSessionId, setLastSessionId] = useState<string | null>(null);
  useEffect(() => {
    if (activeSession?.session_id) setLastSessionId(activeSession.session_id);
  }, [activeSession]);

  // Subscribe to the store with fine-grained re-renders. Only this page
  // (and the components it passes `items`/`count` into) re-renders on push;
  // the rest of the app shell does not.
  const items = useRingBufferItems(store);
  const count = useRingBufferCount(store);

  // -----------------------------------------------------------------
  // Actions
  // -----------------------------------------------------------------

  const reallyStart = useCallback(
    async (
      src: LiveSource,
      det: DetectionMode,
      spd: ReplaySpeed,
      persist: boolean,
    ) => {
      try {
        const session = await startSession(
          src,
          det,
          src === 'pcap' ? Number(spd) : null,
          persist,
        );
        if (src === 'interface') {
          toast.success('Live session started — capturing on interface.');
        } else {
          toast.info('Session ready. Upload a PCAP to begin replay.');
        }
        return session;
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Could not start session');
      }
    },
    [startSession],
  );

  const handleStart = useCallback(async () => {
    // Probe the server: if a session already exists, ask before clobbering.
    try {
      const existing = await liveTrafficStream.fetchActiveSession();
      if (existing) {
        setPendingStart({ source, mode, speed, persist: persistToAlerts });
        setConfirmOpen(true);
        return;
      }
    } catch {
      /* fall through to start */
    }
    reallyStart(source, mode, speed, persistToAlerts);
  }, [source, mode, speed, persistToAlerts, reallyStart]);

  const handleConfirmedStart = useCallback(() => {
    setConfirmOpen(false);
    if (!pendingStart) return;
    reallyStart(
      pendingStart.source,
      pendingStart.mode,
      pendingStart.speed,
      pendingStart.persist,
    );
    setPendingStart(null);
  }, [pendingStart, reallyStart]);

  const handleStop = useCallback(async () => {
    await stopSession();
    toast.info('Live session stopped.');
  }, [stopSession]);

  const handleAttachPcap = useCallback(
    async (file: File) => {
      if (!activeSession) {
        toast.error('No active session');
        return;
      }
      try {
        await attachPcap(activeSession.session_id, file);
        toast.success(`Replay started: ${file.name}`);
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : 'Could not attach pcap',
        );
      }
    },
    [activeSession, attachPcap],
  );

  const handleDownloadLog = useCallback(
    async (format: 'csv' | 'ndjson') => {
      const sid = activeSession?.session_id ?? lastSessionId;
      if (!sid) {
        toast.error('No session log available yet');
        return;
      }
      try {
        await downloadSessionLog(sid, format);
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : 'Could not download log',
        );
      }
    },
    [activeSession, lastSessionId, downloadSessionLog],
  );

  const handleSelect = useCallback(
    (pkt: LivePacket) => {
      setSelected(pkt);
    },
    [setSelected],
  );

  // -----------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------

  const selectedIdMemo = useMemo(() => selected?.id ?? null, [selected]);

  return (
    <div className="min-h-screen bg-bg text-foreground">
      <div className="container mx-auto px-4 py-6 space-y-4">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="space-y-4"
        >
          <LiveStreamHeader
            active={activeSession}
            connected={connected}
            reconnecting={reconnecting}
            source={source}
            setSource={setSource}
            mode={mode}
            setMode={setMode}
            speed={speed}
            setSpeed={setSpeed}
            persistToAlerts={persistToAlerts}
            setPersistToAlerts={setPersistToAlerts}
            onStart={handleStart}
            onStop={handleStop}
            onAttachPcap={handleAttachPcap}
            onDownloadLog={handleDownloadLog}
            logAvailable={Boolean(activeSession || lastSessionId)}
            onClearView={clear}
            eventCount={count}
            rateEps={eps}
          />

          <LiveStatsRow
            packets={items}
            totalReceived={count}
            rateEps={eps}
          />

          <LiveAnalyticsRow packets={items} />

          <div className="grid lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <LiveEventTable
                packets={items}
                selectedId={selectedIdMemo}
                onSelect={handleSelect}
              />
            </div>
            <div className="lg:col-span-1">
              <PacketDetailDrawer packet={selected} />
            </div>
          </div>
        </motion.div>
      </div>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Replace the active session?</AlertDialogTitle>
            <AlertDialogDescription>
              Another live session is already running on the server. Starting a
              new one will stop the existing session and close its SSE stream.
              The previous session's log files remain available on disk.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep current</AlertDialogCancel>
            <AlertDialogAction onClick={handleConfirmedStart}>
              Replace
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inline detail drawer — mirrors the pre-existing dashboard drawer style
// ---------------------------------------------------------------------------

function PacketDetailDrawer({ packet }: { packet: LivePacket | null }) {
  if (!packet) {
    return (
      <div className="bg-bg/80 border border-line rounded-lg p-4 h-[604px]">
        <h3 className="text-sm font-semibold text-sev-low mb-4 flex items-center gap-2">
          <Eye className="w-4 h-4" />
          Packet Details
        </h3>
        <div className="flex flex-col items-center justify-center h-[480px] text-center">
          <Eye className="w-10 h-10 text-faint mb-3" />
          <p className="text-muted-foreground text-sm">Select an event row</p>
          <p className="text-faint text-xs mt-1">
            Click on any row to view full details
          </p>
        </div>
      </div>
    );
  }

  const dp = getLiveDisplayPrediction(packet.prediction);
  const riskLevel: RiskLevel = severityToRisk(packet.severity);
  const meta = sourceMeta(packet.source);

  return (
    <div className="bg-bg/80 border border-line rounded-lg p-4 h-[604px] overflow-y-auto">
      <h3 className="text-sm font-semibold text-sev-low mb-4 flex items-center gap-2">
        <Eye className="w-4 h-4" />
        Packet Details
      </h3>
      <div className="space-y-4">
        <div className="p-3 rounded-lg bg-panel/80 border border-line">
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert className="w-4 h-4 text-sev-high" />
            <span className="text-xs text-muted-foreground font-semibold">Risk Level</span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <RiskBadge risk={riskLevel} />
              <ConfidenceQuality stage2_p={packet.stage2_p ?? null} />
            </div>
            <Badge
              variant="outline"
              className={
                dp === 'Malicious'
                  ? 'border-sev-high/50 text-sev-high'
                  : dp === 'Suspicious'
                    ? 'border-sev-med/50 text-sev-med'
                    : 'border-brand/40 text-brand'
              }
            >
              {dp}
            </Badge>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-panel/80 border border-line">
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert className="w-4 h-4 text-sev-low" />
            <span className="text-xs text-muted-foreground font-semibold">Hybrid Verdict</span>
          </div>
          <div className="flex items-center justify-between">
            <VerdictBadge source={packet.source} />
            <span
              className="text-[10px] font-mono text-muted-foreground"
              title="Model version (manifest hash prefix)"
            >
              {packet.model_version || 'unknown'}
            </span>
          </div>
          <div className="text-[10px] text-faint mt-1">{meta.label}</div>
        </div>

        {packet.attack_type && dp !== 'Normal' && (
          <div className="p-3 rounded-lg bg-sev-high/5 border border-sev-high/20 space-y-3">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <ShieldAlert className="w-4 h-4 text-sev-high" />
                <span className="text-xs text-muted-foreground font-semibold">
                  Attack Classification
                </span>
              </div>
              <div className="space-y-1">
                <div className="text-sm font-bold text-sev-high">
                  {packet.attack_type}
                </div>
                {packet.family && (
                  <div className="text-[11px] text-muted-foreground">
                    <span className="text-muted-foreground">Family:</span>{' '}
                    <span className="font-mono">{packet.family}</span>
                  </div>
                )}
              </div>
            </div>
            <StageProbBars
              probs={packet.stage2_probs ?? null}
              label="Stage-2 family vector"
              highlight={packet.family ?? null}
            />
            <StageProbBars
              probs={packet.stage3_probs ?? null}
              label="Stage-3 leaf vector"
              highlight={packet.attack_type ?? null}
            />
          </div>
        )}

        {packet.snort_msg && (
          <div className="p-3 rounded-lg bg-sev-med/5 border border-sev-med/20">
            <div className="flex items-center gap-2 mb-2">
              <ShieldAlert className="w-4 h-4 text-sev-med" />
              <span className="text-xs text-muted-foreground font-semibold">Snort Alert</span>
            </div>
            <div className="space-y-1.5">
              {[
                { label: 'Message', value: packet.snort_msg },
                { label: 'SID', value: packet.snort_sid },
                { label: 'Classtype', value: packet.snort_classtype },
                { label: 'Priority', value: packet.snort_priority },
                { label: 'Action', value: packet.snort_action },
              ]
                .filter((item) => item.value)
                .map((item) => (
                  <div
                    key={item.label}
                    className="flex justify-between items-center py-1 border-b border-line/40 last:border-0"
                  >
                    <span className="text-[11px] text-muted-foreground">{item.label}</span>
                    <span className="text-[11px] font-mono text-sev-med">
                      {item.value}
                    </span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {packet.mitre && (
          <div className="p-3 rounded-lg border border-sev-low/25 bg-sev-low/5">
            <div className="flex items-center gap-2 mb-2">
              <Target className="w-4 h-4 text-sev-low" />
              <span className="text-xs text-muted-foreground font-semibold">MITRE ATT&CK</span>
            </div>
            <div className="space-y-1.5">
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wide">
                  Tactics
                </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {packet.mitre.tactics.map((t) => (
                    <Badge
                      key={t.id}
                      variant="outline"
                      className="text-[10px] py-0 text-sev-low border-sev-low/30"
                    >
                      {t.name}
                    </Badge>
                  ))}
                </div>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wide">
                  Techniques
                </span>
                <div className="space-y-1 mt-1">
                  {packet.mitre.techniques.map((t) => (
                    <a
                      key={t.id}
                      href={t.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-between text-[11px] py-0.5 group hover:text-sev-low transition-colors"
                    >
                      <span className="text-foreground group-hover:text-sev-low">
                        <code className="text-[10px] text-muted-foreground mr-1.5">
                          {t.id}
                        </code>
                        {t.name}
                      </span>
                      <ExternalLink className="w-3 h-3 text-faint group-hover:text-sev-low shrink-0" />
                    </a>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="p-3 rounded-lg bg-panel/80 border border-line">
          <div className="flex items-center gap-2 mb-2">
            <Gauge className="w-4 h-4 text-sev-low" />
            <span className="text-xs text-muted-foreground font-semibold">Model Confidence</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xl font-bold">
              {(packet.confidence * 100).toFixed(1)}%
            </span>
            <div className="flex-1 h-2 bg-line/60 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${Math.max(0, Math.min(1, packet.confidence)) * 100}%`,
                  backgroundColor: dp === 'Malicious' ? '#f0494b' : '#f2a93b',
                }}
              />
            </div>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-panel/80 border border-line">
          <div className="flex items-center gap-2 mb-2">
            <Info className="w-4 h-4 text-sev-low" />
            <span className="text-xs text-muted-foreground font-semibold">Network Information</span>
          </div>
          <div className="space-y-1.5">
            {[
              { label: 'Source IP', value: packet.src_ip },
              { label: 'Destination IP', value: packet.dst_ip },
              { label: 'Source Port', value: packet.src_port },
              { label: 'Destination Port', value: packet.dst_port },
              { label: 'Protocol', value: packet.protocol },
              {
                label: 'Timestamp',
                value: packet.timestamp
                  ? new Date(packet.timestamp).toLocaleString()
                  : '-',
              },
              { label: 'Flow Key', value: packet.flow_key || '-' },
            ].map((item) => (
              <div
                key={item.label}
                className="flex justify-between items-center py-1 border-b border-line/40 last:border-0"
              >
                <span className="text-[11px] text-muted-foreground">{item.label}</span>
                <span className="text-[11px] font-mono text-foreground truncate ml-2">
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="text-center pt-1">
          <span className="text-[10px] text-faint font-mono">{packet.id}</span>
        </div>
      </div>
    </div>
  );
}
