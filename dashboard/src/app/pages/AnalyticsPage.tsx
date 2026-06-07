import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import {
  AlertTriangle, Shield, Activity, TrendingUp, TrendingDown, BarChart3, Wifi,
  ShieldCheck, ShieldAlert, Layers, Target, Globe, Network,
  Crosshair, Clock, RefreshCw, Trash2, Flame, Inbox,
} from 'lucide-react';
import { motion } from 'motion/react';
import { toast } from 'sonner';
import {
  PieChart, Pie, Cell, AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend, ResponsiveContainer, ReferenceDot,
} from 'recharts';
import { useNavigate } from 'react-router';
import { threatService } from '../services/threatDetectionService';
import { TimeRangeSelector, loadRange } from '../components/TimeRangeSelector';
import { DetectorAgreementMatrix } from '../components/DetectorAgreementMatrix';
import type { AnalyticsData, AnalyticsRange } from '../types/threat';

const TIME_RANGE_STORAGE_KEY = 'hids.analytics.timeRange';

// Pretty labels for the four hybrid-verdict cells.
const VERDICT_LABEL: Record<string, string> = {
  confirmed: 'Confirmed',
  signature_only: 'Signature-only',
  ml_only: 'ML-only',
  benign: 'Benign',
};

// Custom tooltip — shared by donut + bar charts so the styling stays consistent.
const DarkTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload || !payload.length) return null;
  return (
    <div
      style={{
        background: 'linear-gradient(135deg, rgba(15,24,37,0.95), rgba(18,28,45,0.97))',
        border: '1px solid rgba(76,141,214,0.35)',
        borderRadius: '10px',
        padding: '10px 14px',
        boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
        backdropFilter: 'blur(12px)',
        minWidth: '140px',
      }}
    >
      {label && (
        <div style={{ color: '#f0f2f5', fontWeight: 600, fontSize: '12px', marginBottom: '6px' }}>
          {label}
        </div>
      )}
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
          <span
            style={{
              width: '10px',
              height: '10px',
              borderRadius: '2px',
              backgroundColor: p.color || p.fill,
              display: 'inline-block',
            }}
          />
          <span style={{ color: '#9ca3af' }}>{p.name}:</span>
          <span style={{ color: '#fff', fontWeight: 700, fontFamily: 'monospace' }}>
            {typeof p.value === 'number' ? p.value.toLocaleString() : String(p.value)}
          </span>
        </div>
      ))}
    </div>
  );
};

// Pie-chart-specific tooltip (renders percentage of total).
const PiePercentTooltip = ({ active, payload }: any) => {
  if (!active || !payload || !payload.length) return null;
  const { name, value, payload: entryPayload } = payload[0];
  const color = entryPayload?.color || '#f2a93b';
  const total = entryPayload?._total ?? value;
  const percent = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0';
  return (
    <div
      style={{
        background: 'linear-gradient(135deg, rgba(15,24,37,0.95), rgba(18,28,45,0.97))',
        border: `1px solid ${color}55`,
        borderRadius: '10px',
        padding: '12px 16px',
        boxShadow: `0 4px 24px rgba(0,0,0,0.5)`,
        backdropFilter: 'blur(12px)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
        <span style={{ width: '10px', height: '10px', borderRadius: '3px', backgroundColor: color, display: 'inline-block' }} />
        <span style={{ color: '#f0f2f5', fontWeight: 600, fontSize: '13px' }}>{name}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', paddingLeft: '18px' }}>
        <span style={{ color, fontWeight: 700, fontSize: '17px', fontFamily: 'monospace' }}>{value.toLocaleString()}</span>
        <span style={{ color: '#9ca3af', fontSize: '12px' }}>({percent}%)</span>
      </div>
    </div>
  );
};

function formatHourLabel(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' });
  } catch {
    return iso;
  }
}

// Range-widening order. If the user-selected range returns 0 flows but
// the store has data, we walk this list until we find one that does.
const WIDEN_ORDER: AnalyticsRange[] = ['1h', '24h', '7d', '30d', 'all'];

// One row of the heatmap. Rendered as a React.Fragment so each cell becomes
// a direct child of the outer grid (grid-template-columns flows naturally
// across rows without a wrapping div per row).
function FragmentRow({
  label, families, counts, intensity, colorFor,
}: {
  label: string;
  families: string[];
  counts: Record<string, number>;
  intensity: (n: number) => number;
  colorFor: (f: string) => string;
}) {
  return (
    <>
      <div className="text-[11px] font-mono text-muted-foreground py-1 pr-2 whitespace-nowrap">
        {label}
      </div>
      {families.map((f) => {
        const c = counts[f] ?? 0;
        const alpha = intensity(c);
        const color = colorFor(f);
        // Convert hex to rgba so we can apply alpha. Cheap inline parse —
        // these are short fixed-format hex codes from our palette.
        const r = parseInt(color.slice(1, 3), 16);
        const g = parseInt(color.slice(3, 5), 16);
        const b = parseInt(color.slice(5, 7), 16);
        return (
          <div
            key={f}
            className="h-7 rounded-sm flex items-center justify-center text-[10px] font-mono transition hover:ring-1 hover:ring-brand/40"
            style={{
              background: c > 0
                ? `rgba(${r}, ${g}, ${b}, ${0.1 + alpha * 0.75})`
                : 'rgba(26, 37, 64, 0.3)',
              color: alpha > 0.4 ? '#fff' : '#9ca3af',
            }}
            title={`${label} · ${f} · ${c.toLocaleString()} flow${c === 1 ? '' : 's'}`}
          >
            {c > 0 ? c.toLocaleString() : ''}
          </div>
        );
      })}
    </>
  );
}

export default function AnalyticsPage() {
  const navigate = useNavigate();
  // Build an /alerts URL from a partial filter spec. Used by every
  // chart's onClick so drilldown is one place, one query-string format.
  const goToAlerts = (params: Record<string, string | number | undefined>) => {
    const usp = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== '') usp.set(k, String(v));
    }
    navigate(`/alerts?${usp.toString()}`);
  };
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastLoaded, setLastLoaded] = useState<Date | null>(null);
  const [timeRange, setTimeRange] = useState<AnalyticsRange>(() => loadRange(TIME_RANGE_STORAGE_KEY));
  // Tracks whether we auto-widened the window because the user's selection
  // was empty. Surfaces a one-line banner so the analyst understands why
  // the chip on the right may not match what they clicked.
  const [autoWidenedFrom, setAutoWidenedFrom] = useState<AnalyticsRange | null>(null);
  // Independent cross-check of the raw store size via /predictions/counts.
  // If this disagrees with analytics.storeTotal we have a real bug to debug;
  // if both are 0 the store is genuinely empty (most likely cause: uvicorn
  // --reload restarted the process and wiped predictions_store).
  const [rawStoreTotal, setRawStoreTotal] = useState<number | null>(null);
  // Y-axis scale for the timeline chart. Default linear, log mode keeps the
  // small Normal/Suspicious series readable next to a 50k+ Malicious spike.
  const [timelineScale, setTimelineScale] = useState<'linear' | 'log'>('linear');

  useEffect(() => {
    loadAnalytics(timeRange, { autoWiden: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeRange]);

  const loadAnalytics = async (
    range: AnalyticsRange,
    opts: { autoWiden?: boolean } = {},
  ) => {
    setLoading(true);
    setAutoWidenedFrom(null);
    // Fire the raw counts cross-check in parallel — independent of the
    // analytics aggregation, so a contradiction surfaces clearly.
    threatService
      .getPredictionsCounts()
      .then((c) => setRawStoreTotal(c.total))
      .catch(() => setRawStoreTotal(null));
    try {
      const data = await threatService.getAnalytics(range);
      // Auto-widen: if the user's window is empty BUT the store has data,
      // walk WIDEN_ORDER until we find a range that contains flows. Stops
      // at 'all' which always covers everything in the store. This avoids
      // the common case where an upload from 2 hours ago is invisible
      // because the page is stuck on the 1h preset.
      if (
        opts.autoWiden &&
        (data.totalFlows ?? 0) === 0 &&
        (data.storeTotal ?? 0) > 0 &&
        range !== 'all'
      ) {
        const startIdx = WIDEN_ORDER.indexOf(range);
        for (const wider of WIDEN_ORDER.slice(startIdx + 1)) {
          const widerData = await threatService.getAnalytics(wider);
          if ((widerData.totalFlows ?? 0) > 0) {
            setAnalytics(widerData);
            setAutoWidenedFrom(range);
            setTimeRange(wider);
            setLastLoaded(new Date());
            return;
          }
        }
      }
      setAnalytics(data);
      setLastLoaded(new Date());
    } catch (error) {
      console.error('Failed to load analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  // Wipe the backend's in-memory predictions_store on demand. Confirms
  // first because there's no undo — once cleared the data is gone unless
  // the original PCAP/CSV is re-uploaded.
  const handleReset = async () => {
    const ok = window.confirm(
      'Reset all analytics data?\n\nThis clears the backend\'s in-memory predictions store. ' +
      'Live capture continues, but uploaded batch data and historical alerts will be gone. ' +
      'This cannot be undone.',
    );
    if (!ok) return;
    try {
      const result = await threatService.clearStore();
      toast.success(
        result.cleared > 0
          ? `Cleared ${result.cleared.toLocaleString()} predictions`
          : 'Store was already empty',
      );
      await loadAnalytics(timeRange);
      setRawStoreTotal(0);
    } catch (err) {
      console.error('Failed to clear store:', err);
      toast.error('Failed to clear store — check backend logs');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-bg via-bg to-bg flex items-center justify-center">
        <div className="text-center">
          <Activity className="w-12 h-12 mx-auto mb-4 text-brand animate-pulse" />
          <p className="text-muted-foreground">Loading analytics...</p>
        </div>
      </div>
    );
  }

  // Empty-state gate — uses totalFlows (or the legacy normal+malicious sum).
  // Four cases:
  //   (a) Store has data, narrow window excluded it → user just needs to widen.
  //   (b) Inconsistent: range=all AND store has data AND totalFlows=0 → backend
  //       is impossible per the code; almost always a stale process or HTTP
  //       cache. Show real recovery steps and a /_debug/store link.
  //   (c) Store is empty per BOTH endpoints — genuinely no data.
  //   (d) Counts endpoint disagrees with analytics storeTotal — surface loudly.
  const flowCount = analytics?.totalFlows
    ?? ((analytics?.normalCount ?? 0) + (analytics?.maliciousCount ?? 0));
  if (!analytics || flowCount === 0) {
    const analyticsStoreTotal = analytics?.storeTotal ?? 0;
    const storeHasData = analyticsStoreTotal > 0 || (rawStoreTotal ?? 0) > 0;
    const contradiction =
      rawStoreTotal !== null && rawStoreTotal > 0 && analyticsStoreTotal === 0;
    // Inconsistent: user is on 'all' (or auto-widen reached 'all'), store has
    // data per at least one endpoint, but totalFlows is 0. Impossible per code.
    const appliedRange = analytics?.timeRangeApplied ?? timeRange;
    const inconsistent = appliedRange === 'all' && storeHasData && flowCount === 0;
    const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    return (
      <div className="min-h-screen bg-gradient-to-br from-bg via-bg to-bg flex flex-col items-center justify-center p-4">
        <div className="text-center bg-panel/70 p-8 rounded-2xl border border-line backdrop-blur max-w-lg shadow-2xl">
          <Activity className="w-16 h-16 text-muted-foreground mx-auto mb-4 opacity-70" />
          {inconsistent ? (
            <>
              <h2 className="text-2xl font-bold text-sev-high mb-3">
                Backend returned an inconsistent response
              </h2>
              <p className="text-foreground mb-4">
                You're on <span className="font-mono text-sev-low">all</span>, the store has{' '}
                <span className="font-mono text-sev-low">
                  {(analyticsStoreTotal || rawStoreTotal || 0).toLocaleString()}
                </span>{' '}
                stored predictions, but the analytics endpoint reports{' '}
                <span className="font-mono text-sev-high">0 flows</span>. This is impossible per
                the backend code — almost always a stale process or HTTP cache.
              </p>
              <div className="text-left text-[12px] bg-line/40 border border-line rounded-lg p-3 mb-4 space-y-1">
                <p className="text-foreground font-semibold mb-1">Recovery steps:</p>
                <ol className="list-decimal list-inside text-muted-foreground space-y-0.5">
                  <li>
                    Hard-refresh this page (<span className="font-mono">Ctrl-F5</span>) to bust any
                    cached response.
                  </li>
                  <li>
                    Confirm only one uvicorn is running on{' '}
                    <span className="font-mono">:8000</span>:{' '}
                    <span className="font-mono text-sev-med">netstat -ano | findstr :8000</span>.
                    Kill duplicates with <span className="font-mono">taskkill /PID &lt;pid&gt; /F</span>.
                  </li>
                  <li>
                    Open{' '}
                    <a
                      href={`${apiBase}/_debug/store`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sev-low underline underline-offset-2"
                    >
                      /_debug/store
                    </a>{' '}
                    — the backend's view of reality. If <span className="font-mono">store_size</span>{' '}
                    is 0 there too, the predictions never landed in this process.
                  </li>
                </ol>
                <p className="text-muted-foreground text-[11px] pt-2">
                  Backend: pid ={' '}
                  <span className="font-mono text-sev-low">
                    {analytics?.processId ?? '—'}
                  </span>{' '}
                  · serverTime ={' '}
                  <span className="font-mono text-sev-low">
                    {analytics?.serverTime?.slice(11, 19) ?? '—'}
                  </span>{' '}
                  · counts.total ={' '}
                  <span className="font-mono text-sev-low">
                    {rawStoreTotal !== null ? rawStoreTotal.toLocaleString() : '—'}
                  </span>{' '}
                  · analytics.storeTotal ={' '}
                  <span className="font-mono text-sev-low">
                    {analyticsStoreTotal.toLocaleString()}
                  </span>{' '}
                  · totalFlows ={' '}
                  <span className="font-mono text-sev-high">{flowCount}</span>
                </p>
              </div>
              <div className="flex items-center justify-center gap-2">
                <button
                  type="button"
                  onClick={() => loadAnalytics(timeRange)}
                  className="px-3 py-1.5 rounded-md border border-sev-low/40 text-sev-low text-xs hover:bg-sev-low/10 inline-flex items-center gap-1"
                >
                  <RefreshCw className="w-3 h-3" />
                  Reload analytics
                </button>
                <button
                  type="button"
                  onClick={handleReset}
                  className="px-3 py-1.5 rounded-md border border-sev-high/40 text-sev-high text-xs hover:bg-sev-high/10 inline-flex items-center gap-1"
                  title="Wipe the backend's in-memory predictions store"
                >
                  <Trash2 className="w-3 h-3" />
                  Reset data
                </button>
              </div>
            </>
          ) : storeHasData ? (
            <>
              <h2 className="text-2xl font-bold text-foreground mb-3">No flows in this time window</h2>
              <p className="text-muted-foreground mb-4">
                The store has{' '}
                <span className="font-mono text-sev-low">
                  {(analyticsStoreTotal || rawStoreTotal || 0).toLocaleString()}
                </span>{' '}
                stored predictions, but none fall within{' '}
                <span className="font-mono text-sev-low">{analytics?.timeRangeApplied ?? timeRange}</span>.
                Your upload is older than this range — widen to <span className="font-mono">All</span> to see it.
              </p>
              <div className="flex items-center justify-center gap-2 mb-3">
                <button
                  type="button"
                  onClick={() => setTimeRange('all')}
                  className="px-3 py-1.5 rounded-md border border-brand/40 text-brand text-xs hover:bg-brand/10"
                >
                  Switch to All
                </button>
                <TimeRangeSelector value={timeRange} onChange={setTimeRange} storageKey={TIME_RANGE_STORAGE_KEY} />
              </div>
            </>
          ) : (
            <>
              <h2 className="text-2xl font-bold text-foreground mb-3">No analysis data yet</h2>
              <p className="text-muted-foreground mb-4">
                The prediction store is empty.
              </p>
              {/* Most common root cause: uvicorn --reload restarts on any
                  source-file change and wipes the in-memory store. Tell
                  the user explicitly so they don't keep re-uploading. */}
              <div className="text-left text-[12px] bg-line/40 border border-line rounded-lg p-3 mb-4 space-y-1">
                <p className="text-foreground font-semibold">Common causes:</p>
                <ul className="list-disc list-inside text-muted-foreground space-y-0.5">
                  <li>
                    The backend was restarted after upload — predictions are
                    held in memory only and don't survive process restarts.
                  </li>
                  <li>
                    <span className="font-mono text-sev-med">uvicorn --reload</span> auto-restarts
                    on any file edit (used by <span className="font-mono">start_workers.ps1</span>),
                    which wipes the store. Use <span className="font-mono">start_all.ps1</span> for
                    persistent state during a session.
                  </li>
                  <li>Upload may have produced 0 flows — check the upload page for the flow count.</li>
                </ul>
                <p className="text-muted-foreground text-[11px] pt-1">
                  Backend reports: store size ={' '}
                  <span className="font-mono text-sev-low">
                    {rawStoreTotal !== null ? rawStoreTotal.toLocaleString() : '—'}
                  </span>{' '}
                  (via /predictions/counts) ·{' '}
                  analytics storeTotal ={' '}
                  <span className="font-mono text-sev-low">
                    {analyticsStoreTotal.toLocaleString()}
                  </span>
                </p>
              </div>
              {contradiction && (
                <div className="text-[12px] bg-sev-high/10 border border-sev-high/30 rounded-lg p-3 mb-4 text-left">
                  <p className="text-sev-high font-semibold mb-1">⚠ Contradiction detected</p>
                  <p className="text-foreground">
                    /predictions/counts reports {rawStoreTotal} stored predictions but
                    /analytics reports 0. The backend may need to be restarted to pick
                    up the latest <span className="font-mono">storeTotal</span> field — try
                    stopping and restarting <span className="font-mono">start_all.ps1</span>.
                  </p>
                </div>
              )}
              <div className="flex items-center justify-center gap-2">
                <TimeRangeSelector value={timeRange} onChange={setTimeRange} storageKey={TIME_RANGE_STORAGE_KEY} />
                <button
                  type="button"
                  onClick={() => loadAnalytics(timeRange)}
                  className="px-3 py-1.5 rounded-md border border-sev-low/40 text-sev-low text-xs hover:bg-sev-low/10 inline-flex items-center gap-1"
                >
                  <RefreshCw className="w-3 h-3" />
                  Reload
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    );
  }

  const totalThreats = analytics.normalCount + analytics.maliciousCount;
  const threatPercentage = totalThreats > 0 ? ((analytics.maliciousCount / totalThreats) * 100).toFixed(1) : '0.0';

  /** Render an up/down arrow + percentage delta vs the prior window.
   *  `goodWhenDown` flips the colour semantic (e.g. backlog up = bad,
   *  benign-count up = good). Returns null when there's no comparable
   *  prior value (e.g. range=all). */
  const TrendDelta = ({
    current,
    prior,
    goodWhenDown = true,
  }: {
    current: number;
    prior: number | undefined;
    goodWhenDown?: boolean;
  }) => {
    if (prior === undefined) return null;
    if (prior === 0 && current === 0) return null;
    if (prior === 0) {
      return (
        <span className="text-[10px] font-mono inline-flex items-center gap-0.5 text-sev-med">
          <TrendingUp className="w-3 h-3" />
          new
        </span>
      );
    }
    const delta = ((current - prior) / prior) * 100;
    if (Math.abs(delta) < 1) {
      return <span className="text-[10px] font-mono text-muted-foreground">≈</span>;
    }
    const up = delta > 0;
    // up + goodWhenDown → bad (red). up + !goodWhenDown → good (green).
    const isBad = up === goodWhenDown;
    const color = isBad ? 'text-sev-high' : 'text-brand';
    const Arrow = up ? TrendingUp : TrendingDown;
    return (
      <span className={`text-[10px] font-mono inline-flex items-center gap-0.5 ${color}`} title={`${prior.toLocaleString()} prior · ${current.toLocaleString()} now`}>
        <Arrow className="w-3 h-3" />
        {up ? '+' : ''}{delta.toFixed(0)}%
      </span>
    );
  };

  const priorVerdict = (src: string): number | undefined => {
    if (!analytics.prior) return undefined;
    const entry = analytics.prior.verdictBreakdown.find((v) => v.source === src);
    return entry?.count ?? 0;
  };

  const protocolData = analytics.protocolDistribution || [];
  const hourlyTimeline = (analytics.hourlyTimeline ?? []).map((h) => ({
    ...h,
    hourLabel: formatHourLabel(h.hour),
  }));

  return (
    <div className="min-h-screen bg-gradient-to-br from-bg via-bg to-bg py-12">
      <div className="container mx-auto px-4">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          {/* Header */}
          <div className="mb-8 flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="text-4xl font-bold text-foreground mb-2">Analytics Dashboard</h1>
              <p className="text-muted-foreground">
                Hybrid IDS threat intelligence
                {analytics?.timeRangeApplied && analytics?.totalFlows !== undefined && (
                  <> · <span className="text-foreground font-mono">{analytics.totalFlows.toLocaleString()}</span> flows
                  in window <span className="text-foreground font-mono">{analytics.timeRangeApplied}</span></>
                )}
                {lastLoaded && (
                  <> · loaded <span className="text-foreground font-mono">{lastLoaded.toLocaleTimeString()}</span></>
                )}
              </p>
              {/* Backend identity chip — if pid changes between refreshes,
                  multiple uvicorn workers are running; if serverTime stays
                  the same the response is being cached somewhere. */}
              {(analytics?.processId !== undefined || analytics?.serverTime) && (
                <p className="text-[10px] text-faint font-mono mt-1">
                  backend pid={analytics.processId ?? '—'} ·
                  serverTime={analytics.serverTime?.slice(11, 19) ?? '—'}
                </p>
              )}
            </div>
            <div className="flex items-center gap-2">
              <TimeRangeSelector value={timeRange} onChange={setTimeRange} storageKey={TIME_RANGE_STORAGE_KEY} />
              <button
                type="button"
                onClick={() => loadAnalytics(timeRange)}
                className="px-3 py-1.5 rounded-md border border-sev-low/40 text-sev-low text-xs hover:bg-sev-low/10 inline-flex items-center gap-1"
              >
                <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                Reload
              </button>
              <button
                type="button"
                onClick={handleReset}
                className="px-3 py-1.5 rounded-md border border-sev-high/40 text-sev-high text-xs hover:bg-sev-high/10 inline-flex items-center gap-1"
                title="Clear the backend's in-memory predictions store"
              >
                <Trash2 className="w-3 h-3" />
                Reset data
              </button>
            </div>
          </div>

          {/* Auto-widen banner — surfaces when the user-selected window
              had no flows so we picked a wider one for them. Lets them
              snap back to the original range in one click. */}
          {autoWidenedFrom && (
            <div className="mb-6 flex items-center justify-between gap-3 px-4 py-3 rounded-lg border border-sev-low/30 bg-sev-low/5">
              <div className="flex items-center gap-2 text-sm text-sev-low">
                <Activity className="w-4 h-4" />
                <span>
                  Your <span className="font-mono">{autoWidenedFrom}</span> window had no flows,
                  so the view was widened to{' '}
                  <span className="font-mono">{analytics?.timeRangeApplied ?? timeRange}</span>{' '}
                  to show your stored data.
                </span>
              </div>
              <button
                type="button"
                onClick={() => setTimeRange(autoWidenedFrom)}
                className="text-xs text-foreground hover:text-foreground underline underline-offset-2"
              >
                Restore {autoWidenedFrom}
              </button>
            </div>
          )}

          {/* ───── SECTION 0: SOC OPERATIONAL KPIs ───── */}
          {/* Built from existing ack_state fields. MTTA = mean time to ack;
              backlog = unacked `new` count in this window; oldest unacked
              = max age in that bucket; acked in window = closed work. */}
          {analytics.operationalKpis && (() => {
            const k = analytics.operationalKpis;
            const fmtSeconds = (s: number | null) => {
              if (s === null || !Number.isFinite(s)) return '—';
              if (s < 60) return `${Math.round(s)}s`;
              if (s < 3600) return `${Math.round(s / 60)}m`;
              if (s < 86400) return `${(s / 3600).toFixed(1)}h`;
              return `${(s / 86400).toFixed(1)}d`;
            };
            return (
              <div className="grid md:grid-cols-4 gap-6 mb-8">
                <Card className="bg-panel/70 border-line backdrop-blur">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Clock className="w-8 h-8 text-sev-low" />
                      <span className="text-xs text-sev-low font-semibold uppercase tracking-wide">MTTA</span>
                    </div>
                    <p className="text-3xl font-bold text-foreground mb-1">
                      {fmtSeconds(k.mttaSeconds)}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      Mean time to ack
                      {k.mttaSampleSize !== undefined && (
                        <span className="text-faint"> · n={k.mttaSampleSize}</span>
                      )}
                    </p>
                  </CardContent>
                </Card>
                <Card className="bg-panel/70 border-line backdrop-blur">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between mb-2">
                      <Inbox className="w-8 h-8 text-sev-high" />
                      <span className="text-xs text-sev-high font-semibold uppercase tracking-wide">Backlog</span>
                    </div>
                    <p className="text-3xl font-bold text-foreground mb-1">
                      {k.backlog.toLocaleString()}
                    </p>
                    <p className="text-sm text-muted-foreground">Unacked alerts in window</p>
                  </CardContent>
                </Card>
                <Card className="bg-panel/70 border-line backdrop-blur">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between mb-2">
                      <AlertTriangle className="w-8 h-8 text-sev-med" />
                      <span className="text-xs text-sev-med font-semibold uppercase tracking-wide">Oldest unacked</span>
                    </div>
                    <p className="text-3xl font-bold text-foreground mb-1">
                      {fmtSeconds(k.oldestUnackedAgeSeconds)}
                    </p>
                    <p className="text-sm text-muted-foreground">Age of stalest queue entry</p>
                  </CardContent>
                </Card>
                <Card className="bg-panel/70 border-line backdrop-blur">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between mb-2">
                      <ShieldCheck className="w-8 h-8 text-brand" />
                      <span className="text-xs text-brand font-semibold uppercase tracking-wide">Closed</span>
                    </div>
                    <p className="text-3xl font-bold text-foreground mb-1">
                      {k.ackedInWindow.toLocaleString()}
                    </p>
                    <p className="text-sm text-muted-foreground">Acked / escalated / dismissed</p>
                  </CardContent>
                </Card>
              </div>
            );
          })()}

          {/* ───── SECTION 1: HEADLINE KPIs ───── */}
          {/* Hybrid verdict KPIs — the SOC-facing summary. */}
          {analytics?.verdictBreakdown && analytics.verdictBreakdown.length > 0 && (
            <div className="grid md:grid-cols-4 gap-6 mb-8">
              {(['confirmed', 'signature_only', 'ml_only', 'benign'] as const).map((src) => {
                const entry = analytics.verdictBreakdown?.find((v) => v.source === src);
                const count = entry?.count ?? 0;
                const color = entry?.color ?? '#aaaaaa';
                const Icon = src === 'confirmed' ? ShieldAlert
                           : src === 'signature_only' ? AlertTriangle
                           : src === 'ml_only' ? Activity
                           : ShieldCheck;
                return (
                  <Card key={src} className="border backdrop-blur" style={{ borderColor: `${color}66`, backgroundColor: `${color}10` }}>
                    <CardContent className="p-6">
                      <div className="flex items-center justify-between mb-2">
                        <Icon className="w-8 h-8" style={{ color }} />
                        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color }}>
                          {VERDICT_LABEL[src]}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 mb-1">
                        <p className="text-3xl font-bold text-foreground">{count.toLocaleString()}</p>
                        <TrendDelta
                          current={count}
                          prior={priorVerdict(src)}
                          goodWhenDown={src !== 'benign'}
                        />
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {src === 'confirmed' && 'ML + Snort agreed'}
                        {src === 'signature_only' && 'Snort fired, ML did not'}
                        {src === 'ml_only' && 'ML fired, Snort did not'}
                        {src === 'benign' && 'Neither detector flagged'}
                      </p>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}

          {/* Severity KPIs */}
          <div className="grid md:grid-cols-4 gap-6 mb-10">
            <Card className="bg-gradient-to-br from-sev-high/15 to-sev-high/5 border-sev-high/40 backdrop-blur">
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-2">
                  <AlertTriangle className="w-8 h-8 text-sev-high" />
                  <span className="text-xs text-sev-high font-semibold">HIGH</span>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  <p className="text-3xl font-bold text-foreground">{analytics.severityCounts.high}</p>
                  <TrendDelta current={analytics.severityCounts.high} prior={analytics.prior?.severityCounts.high} />
                </div>
                <p className="text-sm text-muted-foreground">High Severity</p>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-sev-med/15 to-sev-med/5 border-sev-med/40 backdrop-blur">
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-2">
                  <AlertTriangle className="w-8 h-8 text-sev-med" />
                  <span className="text-xs text-sev-med font-semibold">MEDIUM</span>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  <p className="text-3xl font-bold text-foreground">{analytics.severityCounts.medium}</p>
                  <TrendDelta current={analytics.severityCounts.medium} prior={analytics.prior?.severityCounts.medium} />
                </div>
                <p className="text-sm text-muted-foreground">Medium Severity</p>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-sev-low/15 to-sev-low/5 border-sev-low/40 backdrop-blur">
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-2">
                  <Shield className="w-8 h-8 text-sev-low" />
                  <span className="text-xs text-sev-low font-semibold">LOW</span>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  <p className="text-3xl font-bold text-foreground">{analytics.severityCounts.low}</p>
                  <TrendDelta current={analytics.severityCounts.low} prior={analytics.prior?.severityCounts.low} />
                </div>
                <p className="text-sm text-muted-foreground">Low / Suspicious</p>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-brand/15 to-brand/5 border-brand/40 backdrop-blur">
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-2">
                  <TrendingUp className="w-8 h-8 text-brand" />
                  <span className="text-xs text-brand font-semibold">RATE</span>
                </div>
                <p className="text-3xl font-bold text-foreground mb-1">{threatPercentage}%</p>
                <p className="text-sm text-muted-foreground">Threat Detection Rate</p>
              </CardContent>
            </Card>
          </div>

          {/* ───── SECTION 2: VERDICT + FAMILY ───── */}
          <h2 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-sev-low" /> Detection Breakdown
          </h2>
          <div className="grid lg:grid-cols-2 gap-8 mb-10">
            <Card className="bg-panel/70 border-line backdrop-blur">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-sev-low" />
                  Verdict Source Distribution
                </CardTitle>
                <p className="text-xs text-muted-foreground mt-1">
                  Where the hybrid IDS placed each flow. ML-only is the high-FP cell.
                </p>
              </CardHeader>
              <CardContent>
                {analytics?.verdictBreakdown && analytics.verdictBreakdown.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={analytics.verdictBreakdown.map((v) => ({
                          name: VERDICT_LABEL[v.source] ?? v.source,
                          value: v.count,
                          color: v.color,
                          source: v.source,
                          _total: analytics.verdictBreakdown!.reduce((s, x) => s + x.count, 0),
                        }))}
                        cx="50%" cy="50%"
                        innerRadius={60} outerRadius={100}
                        dataKey="value" strokeWidth={2} stroke="var(--panel)"
                        cursor="pointer"
                        onClick={(data: { source?: string }) => {
                          if (data?.source) goToAlerts({ source: data.source });
                        }}
                      >
                        {analytics.verdictBreakdown.map((v) => (
                          <Cell key={v.source} fill={v.color} />
                        ))}
                      </Pie>
                      <Tooltip content={<PiePercentTooltip />} wrapperStyle={{ outline: 'none', zIndex: 50 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-center py-12 text-muted-foreground text-sm">No verdict data.</div>
                )}
              </CardContent>
            </Card>

            <Card className="bg-panel/70 border-line backdrop-blur">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <Layers className="w-5 h-5 text-sev-low" />
                  Attack Family Breakdown
                </CardTitle>
                <p className="text-xs text-muted-foreground mt-1">
                  Six hierarchical families from Stage 2 of the ML model.
                </p>
              </CardHeader>
              <CardContent>
                {analytics?.familyBreakdown && analytics.familyBreakdown.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={analytics.familyBreakdown} layout="vertical" margin={{ left: 20, right: 30 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" horizontal={false} />
                      <XAxis type="number" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                      <YAxis type="category" dataKey="family" stroke="#9ca3af" style={{ fontSize: '12px', fontFamily: 'monospace' }} width={140} />
                      <Tooltip content={<DarkTooltip />} />
                      <Bar
                        dataKey="count"
                        name="Flows"
                        radius={[0, 6, 6, 0]}
                        cursor="pointer"
                        onClick={(data: { family?: string }) => {
                          if (data?.family) goToAlerts({ q: data.family });
                        }}
                      >
                        {analytics.familyBreakdown.map((f) => (
                          <Cell key={f.family} fill={f.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-center py-12 text-muted-foreground text-sm">No family data.</div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Detector-agreement 2x2 matrix — derived from the same
              verdictBreakdown numbers, so it costs nothing extra.
              Click a cell to drill into Alerts. */}
          {analytics?.verdictBreakdown && analytics.verdictBreakdown.length > 0 && (
            <div className="mb-10">
              <DetectorAgreementMatrix verdictBreakdown={analytics.verdictBreakdown} />
            </div>
          )}

          {/* Severity-by-family stacked bar */}
          {analytics?.severityByFamily && analytics.severityByFamily.length > 0 && (
            <Card className="bg-panel/70 border-line backdrop-blur mb-10">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <BarChart3 className="w-5 h-5 text-sev-low" />
                  Severity by Family
                </CardTitle>
                <p className="text-xs text-muted-foreground mt-1">
                  Which families produce the most critical work. Stacked: High (red), Medium (yellow), Low (cyan).
                </p>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={320}>
                  <BarChart data={analytics.severityByFamily} margin={{ left: 0, right: 20, top: 10, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
                    <XAxis dataKey="family" stroke="#9ca3af" style={{ fontSize: '12px', fontFamily: 'monospace' }} />
                    <YAxis stroke="#9ca3af" style={{ fontSize: '12px' }} />
                    <Tooltip content={<DarkTooltip />} />
                    <Legend iconType="circle" wrapperStyle={{ paddingTop: 10 }} />
                    <Bar dataKey="high" stackId="sev" fill="#f0494b" name="High" radius={[0, 0, 0, 0]} />
                    <Bar dataKey="medium" stackId="sev" fill="#e0a640" name="Medium" />
                    <Bar dataKey="low" stackId="sev" fill="#4c8dd6" name="Low" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Leaf class breakdown table — kept, polished. */}
          {analytics?.leafBreakdown && analytics.leafBreakdown.length > 0 && (
            <Card className="bg-panel/70 border-line backdrop-blur mb-10">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <BarChart3 className="w-5 h-5 text-sev-low" />
                  Leaf Class Breakdown
                </CardTitle>
                <p className="text-xs text-muted-foreground mt-1">
                  15 sub-attack labels emitted by Stage 3, tagged with their parent family.
                </p>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-line text-left text-xs text-muted-foreground uppercase tracking-wide">
                        <th className="py-2 pr-4">Leaf</th>
                        <th className="py-2 pr-4">Family</th>
                        <th className="py-2 pr-4 text-right">Count</th>
                        <th className="py-2 pr-4 text-right">Share</th>
                        <th className="py-2 w-40">Bar</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(() => {
                        const total = analytics.leafBreakdown!.reduce((s, l) => s + l.count, 0) || 1;
                        const max = Math.max(...analytics.leafBreakdown!.map((l) => l.count));
                        return analytics.leafBreakdown!.map((l) => {
                          const pct = (l.count / total) * 100;
                          const widthPct = (l.count / max) * 100;
                          return (
                            <tr
                              key={l.leaf}
                              onClick={() => goToAlerts({ q: l.leaf })}
                              className="border-b border-line/40 hover:bg-line/30 cursor-pointer"
                              title={`Click to filter Alerts by ${l.leaf}`}
                            >
                              <td className="py-2 pr-4 font-mono text-foreground">{l.leaf}</td>
                              <td className="py-2 pr-4 text-muted-foreground font-mono text-xs">{l.family}</td>
                              <td className="py-2 pr-4 text-right font-mono text-foreground">{l.count.toLocaleString()}</td>
                              <td className="py-2 pr-4 text-right font-mono text-muted-foreground text-xs">{pct.toFixed(1)}%</td>
                              <td className="py-2 pr-4">
                                <div className="h-2 rounded-full bg-line/60 overflow-hidden">
                                  <div className="h-full rounded-full" style={{ width: `${widthPct}%`, backgroundColor: l.color }} />
                                </div>
                              </td>
                            </tr>
                          );
                        });
                      })()}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {/* ───── SECTION 3: TARGETS ───── */}
          <h2 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-sev-high" /> Attack Targets
          </h2>
          <div className="grid lg:grid-cols-3 gap-8 mb-10">
            {/* Top attacker IPs */}
            <Card className="bg-panel/70 border-line backdrop-blur">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-sev-high" />
                  Top Attacker IPs
                </CardTitle>
              </CardHeader>
              <CardContent>
                {analytics.topMaliciousIPs.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={analytics.topMaliciousIPs} layout="vertical" margin={{ left: 10, right: 20 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" horizontal={false} />
                      <XAxis type="number" stroke="#9ca3af" style={{ fontSize: '11px' }} />
                      <YAxis type="category" dataKey="ip" stroke="#9ca3af" style={{ fontSize: '11px', fontFamily: 'monospace' }} width={110} />
                      <Tooltip content={<DarkTooltip />} />
                      <Bar
                        dataKey="count"
                        fill="#f0494b"
                        name="Attacks"
                        radius={[0, 6, 6, 0]}
                        cursor="pointer"
                        onClick={(data: { ip?: string }) => {
                          if (data?.ip) goToAlerts({ q: data.ip });
                        }}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-center py-12 text-muted-foreground text-sm">No malicious source IPs.</div>
                )}
              </CardContent>
            </Card>

            {/* Top targeted destinations */}
            <Card className="bg-panel/70 border-line backdrop-blur">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <Target className="w-5 h-5 text-sev-med" />
                  Top Targeted Destinations
                </CardTitle>
              </CardHeader>
              <CardContent>
                {analytics.topDestinations && analytics.topDestinations.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={analytics.topDestinations} layout="vertical" margin={{ left: 10, right: 20 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" horizontal={false} />
                      <XAxis type="number" stroke="#9ca3af" style={{ fontSize: '11px' }} />
                      <YAxis type="category" dataKey="ip" stroke="#9ca3af" style={{ fontSize: '11px', fontFamily: 'monospace' }} width={110} />
                      <Tooltip content={<DarkTooltip />} />
                      <Bar dataKey="count" fill="#e0a640" name="Times targeted" radius={[0, 6, 6, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-center py-12 text-muted-foreground text-sm">No destination data.</div>
                )}
              </CardContent>
            </Card>

            {/* Top targeted ports */}
            <Card className="bg-panel/70 border-line backdrop-blur">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <Network className="w-5 h-5 text-sev-low" />
                  Top Targeted Ports
                </CardTitle>
                <p className="text-xs text-muted-foreground mt-1">
                  Well-known services labelled (HTTP/HTTPS/SSH/...).
                </p>
              </CardHeader>
              <CardContent>
                {analytics.topTargetedPorts && analytics.topTargetedPorts.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart
                      data={analytics.topTargetedPorts.map((p) => ({
                        ...p,
                        portLabel: p.label ? `${p.port} (${p.label})` : String(p.port),
                      }))}
                      layout="vertical"
                      margin={{ left: 10, right: 20 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" horizontal={false} />
                      <XAxis type="number" stroke="#9ca3af" style={{ fontSize: '11px' }} />
                      <YAxis type="category" dataKey="portLabel" stroke="#9ca3af" style={{ fontSize: '11px', fontFamily: 'monospace' }} width={130} />
                      <Tooltip content={<DarkTooltip />} />
                      <Bar dataKey="count" fill="#4c8dd6" name="Attacks" radius={[0, 6, 6, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-center py-12 text-muted-foreground text-sm">No port data.</div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Attacker → Victim pairs table. Folds bidirectional 5-tuples
              (A→B and B→A) into a single conversation row so the response
              traffic from a flood victim doesn't look like the victim is
              attacking back. The side with the larger flow count is treated
              as the attacker; the reverse-direction count is shown as a
              small annotation. */}
          {analytics.attackerVictimPairs && analytics.attackerVictimPairs.length > 0 && (() => {
            type Pair = NonNullable<typeof analytics.attackerVictimPairs>[number];
            const groups = new Map<string, { forward: Pair; reverse: Pair | null }>();
            for (const p of analytics.attackerVictimPairs) {
              const key = [p.src, p.dst].sort().join('|');
              const existing = groups.get(key);
              if (!existing) {
                groups.set(key, { forward: p, reverse: null });
              } else if (p.count > existing.forward.count) {
                groups.set(key, { forward: p, reverse: existing.forward });
              } else {
                existing.reverse = p;
              }
            }
            const folded = Array.from(groups.values()).sort(
              (a, b) => b.forward.count - a.forward.count,
            );
            return (
            <Card className="bg-panel/70 border-line backdrop-blur mb-10">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <Crosshair className="w-5 h-5 text-sev-high" />
                  Top Attacker → Victim Pairs
                </CardTitle>
                <p className="text-xs text-muted-foreground mt-1">
                  Conversation-level view: each row is one IP pair, attributed to the side that
                  generated more attack flows. Reverse-direction traffic (victim responses flagged
                  by the per-flow model) is folded in as an annotation, not a separate row.
                </p>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-line text-left text-xs text-muted-foreground uppercase tracking-wide">
                        <th className="py-2 pr-4">Source IP</th>
                        <th className="py-2 pr-4">→</th>
                        <th className="py-2 pr-4">Destination IP</th>
                        <th className="py-2 pr-4">Dominant Family</th>
                        <th className="py-2 pr-4 text-right">Attack Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {folded.map(({ forward, reverse }, i) => (
                        <tr key={i} className="border-b border-line/40 hover:bg-line/30">
                          <td className="py-2 pr-4 font-mono text-foreground">{forward.src}</td>
                          <td className="py-2 pr-4 text-muted-foreground">→</td>
                          <td className="py-2 pr-4 font-mono text-foreground">{forward.dst}</td>
                          <td className="py-2 pr-4">
                            <span
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-mono"
                              style={{
                                color: forward.color ?? '#aaa',
                                borderColor: `${forward.color ?? '#aaa'}55`,
                                backgroundColor: `${forward.color ?? '#aaa'}10`,
                              }}
                            >
                              {forward.topFamily}
                            </span>
                            {reverse && (
                              <span
                                className="ml-2 inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono text-muted-foreground border-line bg-line/30"
                                title={`Reverse direction (${reverse.src} → ${reverse.dst}) classified as ${reverse.topFamily} — likely victim response traffic flagged by the per-flow model`}
                              >
                                ↔ {reverse.topFamily}
                              </span>
                            )}
                          </td>
                          <td className="py-2 pr-4 text-right font-mono text-foreground">
                            <div>{forward.count.toLocaleString()}</div>
                            {reverse && (
                              <div className="text-[10px] text-muted-foreground">
                                + {reverse.count.toLocaleString()} reverse
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
            );
          })()}

          {/* ───── SECTION 4: TIMELINE + MITRE ───── */}
          <h2 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
            <Clock className="w-4 h-4 text-brand" /> Activity Over Time
          </h2>
          {hourlyTimeline.length > 0 && (() => {
            // Headline stats above the chart: total flows in window, peak
            // malicious hour, peak malicious count. Computed once per render
            // from the already-binned data — no extra pass over predictions.
            const totals = hourlyTimeline.reduce(
              (acc, h) => ({
                normal: acc.normal + h.normal,
                malicious: acc.malicious + h.malicious,
                suspicious: acc.suspicious + h.suspicious,
              }),
              { normal: 0, malicious: 0, suspicious: 0 },
            );
            const peak = hourlyTimeline.reduce(
              (acc, h) => (h.malicious > acc.value ? { value: h.malicious, entry: h } : acc),
              { value: 0, entry: null as (typeof hourlyTimeline)[number] | null },
            );
            // Anomaly detection — rolling z-score over the prior 6 hours
            // of `malicious`. We only flag hours where there's enough prior
            // history (≥ 3 points) and stdev > 0 to avoid false positives on
            // sparse windows. Threshold 2.5 picks out unusual spikes without
            // marking every busy hour.
            const ANOM_Z = 2.5;
            const ANOM_LOOKBACK = 6;
            const anomalies: { hourLabel: string; value: number; z: number }[] = [];
            for (let i = ANOM_LOOKBACK; i < hourlyTimeline.length; i++) {
              const prior = hourlyTimeline.slice(i - ANOM_LOOKBACK, i).map((p) => p.malicious);
              if (prior.length < 3) continue;
              const mean = prior.reduce((s, x) => s + x, 0) / prior.length;
              const variance = prior.reduce((s, x) => s + (x - mean) ** 2, 0) / prior.length;
              const stdev = Math.sqrt(variance);
              if (stdev <= 0) continue;
              const z = (hourlyTimeline[i].malicious - mean) / stdev;
              if (z >= ANOM_Z) {
                anomalies.push({
                  hourLabel: hourlyTimeline[i].hourLabel,
                  value: hourlyTimeline[i].malicious,
                  z,
                });
              }
            }
            // Log-scale guard: Recharts' log scale chokes on 0 values. Map
            // zeros to 0.5 only when log is active, so the line still draws
            // on the floor instead of vanishing.
            const chartData = timelineScale === 'log'
              ? hourlyTimeline.map((h) => ({
                  ...h,
                  normal: h.normal > 0 ? h.normal : 0.5,
                  malicious: h.malicious > 0 ? h.malicious : 0.5,
                  suspicious: h.suspicious > 0 ? h.suspicious : 0.5,
                }))
              : hourlyTimeline;
            const SeriesPill = ({ color, label, value }: { color: string; label: string; value: number }) => (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border bg-panel-raised/60"
                   style={{ borderColor: `${color}44` }}>
                <span className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
                <span className="text-[11px] text-muted-foreground uppercase tracking-wide">{label}</span>
                <span className="font-mono text-sm text-foreground">{value.toLocaleString()}</span>
              </div>
            );
            return (
            <Card className="bg-panel/70 border-line backdrop-blur mb-10">
              <CardHeader>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div>
                    <CardTitle className="text-foreground flex items-center gap-2">
                      <Clock className="w-5 h-5 text-brand" />
                      Hourly Attack Timeline
                    </CardTitle>
                    <p className="text-xs text-muted-foreground mt-1">
                      Independent overlay of normal / malicious (confirmed + sig-only) /
                      suspicious (ML-only). Toggle log scale when a spike crushes the
                      smaller series.
                    </p>
                  </div>
                  {/* Linear / log toggle */}
                  <div className="inline-flex rounded-lg border border-line overflow-hidden text-xs">
                    {(['linear', 'log'] as const).map((s) => (
                      <button
                        key={s}
                        type="button"
                        onClick={() => setTimelineScale(s)}
                        className={`px-2.5 py-1 font-mono uppercase tracking-wide transition ${
                          timelineScale === s
                            ? 'bg-brand/20 text-brand'
                            : 'text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
                {/* Summary chips */}
                <div className="flex flex-wrap items-center gap-2 mt-4">
                  <SeriesPill color="#f2a93b" label="Total normal" value={totals.normal} />
                  <SeriesPill color="#e0a640" label="Total suspicious" value={totals.suspicious} />
                  <SeriesPill color="#f0494b" label="Total malicious" value={totals.malicious} />
                  {peak.entry && (
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-sev-high/40 bg-sev-high/5">
                      <Flame className="w-3.5 h-3.5 text-sev-high" />
                      <span className="text-[11px] text-muted-foreground uppercase tracking-wide">Peak hour</span>
                      <span className="font-mono text-sm text-foreground">{peak.entry.hourLabel}</span>
                      <span className="font-mono text-xs text-sev-high">
                        ({peak.value.toLocaleString()} malicious)
                      </span>
                    </div>
                  )}
                  {anomalies.length > 0 && (
                    <div
                      className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-sev-med/40 bg-sev-med/5"
                      title={`Hours with malicious flows >= ${ANOM_Z} stdev above the prior ${ANOM_LOOKBACK}h mean.\n\n` +
                        anomalies.map((a) => `${a.hourLabel}: ${a.value.toLocaleString()} flows (z=${a.z.toFixed(1)})`).join('\n')}
                    >
                      <AlertTriangle className="w-3.5 h-3.5 text-sev-med" />
                      <span className="text-[11px] text-muted-foreground uppercase tracking-wide">Anomalies</span>
                      <span className="font-mono text-sm text-foreground">{anomalies.length}</span>
                      <span className="font-mono text-xs text-sev-med">
                        hour{anomalies.length === 1 ? '' : 's'} (z≥{ANOM_Z})
                      </span>
                    </div>
                  )}
                </div>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={420}>
                  <AreaChart data={chartData} margin={{ left: 8, right: 24, top: 16, bottom: 4 }}>
                    <defs>
                      <linearGradient id="gNormal" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#f2a93b" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#f2a93b" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gMal" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#f0494b" stopOpacity={0.45} />
                        <stop offset="100%" stopColor="#f0494b" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gSusp" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#e0a640" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#e0a640" stopOpacity={0.02} />
                      </linearGradient>
                      {/* Subtle glow on stroke. SVG drop-shadow > CSS filter
                          because Recharts redraws strokes on hover. */}
                      <filter id="glowMal" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur in="SourceGraphic" stdDeviation="2.5" />
                        <feMerge><feMergeNode /><feMergeNode in="SourceGraphic" /></feMerge>
                      </filter>
                    </defs>
                    <CartesianGrid strokeDasharray="2 6" stroke="var(--line)" vertical={false} />
                    <XAxis
                      dataKey="hourLabel"
                      stroke="#9ca3af"
                      style={{ fontSize: '11px' }}
                      tickLine={false}
                      axisLine={{ stroke: 'var(--line)' }}
                      interval="preserveStartEnd"
                      minTickGap={40}
                    />
                    <YAxis
                      stroke="#9ca3af"
                      style={{ fontSize: '11px' }}
                      tickLine={false}
                      axisLine={false}
                      scale={timelineScale}
                      domain={timelineScale === 'log' ? [0.5, 'auto'] : [0, 'auto']}
                      allowDataOverflow={timelineScale === 'log'}
                      tickFormatter={(v: number) =>
                        v >= 1000 ? `${(v / 1000).toFixed(v >= 10000 ? 0 : 1)}k` : String(Math.round(v))
                      }
                    />
                    <Tooltip content={<DarkTooltip />} />
                    <Legend iconType="circle" wrapperStyle={{ paddingTop: 12 }} />
                    {/* Layered (NOT stacked) — each series is independent so a
                        huge Malicious spike no longer hides Normal/Suspicious. */}
                    <Area
                      type="monotone" dataKey="normal" stroke="#f2a93b" strokeWidth={2}
                      fill="url(#gNormal)" name="Normal" isAnimationActive={false}
                      activeDot={{ r: 4, strokeWidth: 0 }}
                    />
                    <Area
                      type="monotone" dataKey="suspicious" stroke="#e0a640" strokeWidth={2}
                      fill="url(#gSusp)" name="Suspicious" isAnimationActive={false}
                      activeDot={{ r: 4, strokeWidth: 0 }}
                    />
                    <Area
                      type="monotone" dataKey="malicious" stroke="#f0494b" strokeWidth={2.5}
                      fill="url(#gMal)" name="Malicious" isAnimationActive={false}
                      filter="url(#glowMal)"
                      activeDot={{ r: 5, strokeWidth: 0 }}
                    />
                    {peak.entry && peak.value > 0 && (
                      <ReferenceDot
                        x={peak.entry.hourLabel}
                        y={peak.value}
                        r={6}
                        fill="#f0494b"
                        stroke="#fff"
                        strokeWidth={1.5}
                        ifOverflow="extendDomain"
                      />
                    )}
                    {anomalies.map((a, i) => (
                      <ReferenceDot
                        key={`anom-${i}`}
                        x={a.hourLabel}
                        y={a.value}
                        r={5}
                        fill="#e0a640"
                        stroke="var(--panel)"
                        strokeWidth={1.5}
                        ifOverflow="extendDomain"
                      />
                    ))}
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
            );
          })()}

          {/* Hour × Family heatmap. Rows = hours, columns = the 6 hierarchical
              families that appeared in the window. Cell intensity = count on a
              log scale so a 50k DoS hour doesn't drown out a 3-flow Probe hour.
              Empty hours render as faint blank cells for visual continuity. */}
          {hourlyTimeline.length > 0 && (() => {
            const familySet = new Set<string>();
            for (const h of hourlyTimeline) {
              for (const f of Object.keys(h.families ?? {})) familySet.add(f);
            }
            const families = Array.from(familySet);
            if (families.length === 0) return null;
            // Stable order: most-active families first.
            const familyTotals = new Map<string, number>();
            for (const f of families) familyTotals.set(f, 0);
            let globalMax = 0;
            for (const h of hourlyTimeline) {
              for (const [f, c] of Object.entries(h.families ?? {})) {
                familyTotals.set(f, (familyTotals.get(f) ?? 0) + c);
                if (c > globalMax) globalMax = c;
              }
            }
            families.sort((a, b) => (familyTotals.get(b) ?? 0) - (familyTotals.get(a) ?? 0));
            // Log color intensity 0..1 from raw count.
            const intensity = (count: number) => {
              if (count <= 0 || globalMax <= 0) return 0;
              return Math.log10(count + 1) / Math.log10(globalMax + 1);
            };
            // Per-family base color so each column has its own hue, intensity
            // controls opacity. Mirrors the backend family palette.
            const FAMILY_COLOR: Record<string, string> = {
              DoS: '#f0494b',
              DDoS: '#e0a640',
              Probe: '#4c8dd6',
              BruteForce: '#e0a640',
              WebAttack: '#a371f7',
              BotnetInfiltration: '#a371f7',
            };
            const colorFor = (f: string) => FAMILY_COLOR[f] ?? '#aaaaaa';
            return (
              <Card className="bg-panel/70 border-line backdrop-blur mb-10">
                <CardHeader>
                  <CardTitle className="text-foreground flex items-center gap-2">
                    <Flame className="w-5 h-5 text-sev-med" />
                    Attack Heatmap — Hour × Family
                  </CardTitle>
                  <p className="text-xs text-muted-foreground mt-1">
                    Which attack family was active when. Cell intensity is log-scaled
                    so a single rare attack still surfaces next to a 50k flood.
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="overflow-x-auto">
                    <div
                      className="grid gap-1"
                      style={{
                        gridTemplateColumns: `140px repeat(${families.length}, minmax(80px, 1fr))`,
                      }}
                    >
                      {/* Header row */}
                      <div className="text-[11px] text-muted-foreground uppercase tracking-wide pb-2">
                        Hour
                      </div>
                      {families.map((f) => (
                        <div
                          key={f}
                          className="text-[11px] font-mono pb-2 text-center"
                          style={{ color: colorFor(f) }}
                        >
                          {f}
                        </div>
                      ))}
                      {/* Data rows */}
                      {hourlyTimeline.map((h) => (
                        <FragmentRow
                          key={h.hour}
                          label={h.hourLabel}
                          families={families}
                          counts={h.families ?? {}}
                          intensity={intensity}
                          colorFor={colorFor}
                        />
                      ))}
                    </div>
                    {/* Legend */}
                    <div className="flex items-center gap-3 mt-4 pt-3 border-t border-line/60 text-[11px] text-muted-foreground">
                      <span>Intensity (log scale):</span>
                      <div className="flex items-center gap-1">
                        {[0.1, 0.25, 0.5, 0.75, 1].map((a, i) => (
                          <div key={i} className="w-6 h-3 rounded-sm" style={{ background: `rgba(240,73,75,${a})` }} />
                        ))}
                      </div>
                      <span>1 → {globalMax.toLocaleString()}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })()}

          {/* MITRE technique distribution + protocol distribution side-by-side */}
          <div className="grid lg:grid-cols-2 gap-8 mb-10">
            {analytics.mitreTechniqueCounts && analytics.mitreTechniqueCounts.length > 0 ? (
              <Card className="bg-panel/70 border-line backdrop-blur">
                <CardHeader>
                  <CardTitle className="text-foreground flex items-center gap-2">
                    <Globe className="w-5 h-5 text-chart-5" />
                    MITRE ATT&amp;CK Technique Distribution
                  </CardTitle>
                  <p className="text-xs text-muted-foreground mt-1">
                    Per-technique flow counts (log scale). Colored by parent tactic — click a bar to open the ATT&amp;CK page.
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-[1fr_140px] gap-3">
                    <ResponsiveContainer width="100%" height={Math.max(240, analytics.mitreTechniqueCounts.length * 28 + 40)}>
                      <BarChart
                        data={analytics.mitreTechniqueCounts}
                        layout="vertical"
                        margin={{ left: 10, right: 20, top: 4, bottom: 4 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" horizontal={false} />
                        <XAxis
                          type="number"
                          scale="log"
                          domain={[1, 'auto']}
                          allowDataOverflow
                          stroke="#9ca3af"
                          style={{ fontSize: '11px' }}
                        />
                        <YAxis
                          type="category"
                          dataKey="id"
                          stroke="#9ca3af"
                          style={{ fontSize: '11px' }}
                          width={70}
                        />
                        <Tooltip
                          content={({ active, payload }) => {
                            if (!active || !payload || !payload.length) return null;
                            const row = payload[0].payload as {
                              id: string; name: string; tactic: string; count: number; url: string;
                            };
                            return (
                              <div className="bg-panel border border-line rounded p-2 text-[11px] text-foreground shadow-lg">
                                <div className="font-mono text-chart-5">{row.id}</div>
                                <div className="text-foreground">{row.name}</div>
                                <div className="text-muted-foreground">Tactic · {row.tactic || 'Unknown'}</div>
                                <div className="text-muted-foreground mt-1">Flows: <span className="text-foreground">{row.count.toLocaleString()}</span></div>
                                <div className="text-[10px] text-faint mt-1">Click bar to open attack.mitre.org</div>
                              </div>
                            );
                          }}
                        />
                        <Bar
                          dataKey="count"
                          name="Flows"
                          radius={[0, 6, 6, 0]}
                          cursor="pointer"
                          onClick={(data: { url?: string }) => {
                            if (data?.url) {
                              window.open(data.url, '_blank', 'noopener,noreferrer');
                            }
                          }}
                        >
                          {analytics.mitreTechniqueCounts.map((t) => (
                            <Cell key={t.id} fill={t.color ?? '#a371f7'} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                    {/* Tactic legend — derives from mitreTacticCounts so each
                        swatch matches its bar color exactly. */}
                    <div className="space-y-1.5 text-[11px]">
                      <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Tactics</div>
                      {(analytics.mitreTacticCounts ?? []).map((t) => (
                        <div key={t.tactic} className="flex items-center gap-2">
                          <span
                            className="inline-block w-3 h-3 rounded-sm shrink-0"
                            style={{ backgroundColor: t.color ?? '#a371f7' }}
                          />
                          <span className="text-foreground truncate" title={t.tactic}>{t.tactic}</span>
                          <span className="text-muted-foreground ml-auto font-mono">{t.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <Card className="bg-panel/70 border-line backdrop-blur">
                <CardHeader>
                  <CardTitle className="text-foreground flex items-center gap-2">
                    <Globe className="w-5 h-5 text-chart-5" />
                    MITRE ATT&amp;CK Technique Distribution
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-center py-12 text-muted-foreground text-sm">
                    No MITRE-mapped attacks in this window.
                  </div>
                </CardContent>
              </Card>
            )}

            <Card className="bg-panel/70 border-line backdrop-blur">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <Wifi className="w-5 h-5 text-sev-low" />
                  Protocol Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                {protocolData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={protocolData} barCategoryGap="30%">
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
                      <XAxis dataKey="name" stroke="#9ca3af" style={{ fontSize: '12px' }} tickLine={false} axisLine={{ stroke: 'var(--line)' }} />
                      <YAxis stroke="#9ca3af" style={{ fontSize: '12px' }} tickLine={false} axisLine={{ stroke: 'var(--line)' }} />
                      <Tooltip content={<DarkTooltip />} cursor={{ fill: 'rgba(242,169,59,0.06)' }} />
                      <Bar dataKey="count" name="Packets" fill="#00FFA6" radius={[8, 8, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-center py-12 text-muted-foreground text-sm">No protocol data.</div>
                )}
              </CardContent>
            </Card>
          </div>

        </motion.div>
      </div>
    </div>
  );
}
