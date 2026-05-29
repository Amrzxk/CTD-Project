import { useState, useEffect, useCallback, useRef } from 'react';
import { useSearchParams } from 'react-router';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Clock,
  RefreshCw,
  Copy,
  Download,
  Inbox,
  CheckCircle2,
  Flag,
  XCircle,
  Eye,
  Gauge,
  Globe,
  ExternalLink,
  CheckSquare,
  Square,
  X as XIcon,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { toast } from 'sonner';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { RiskBadge, severityToRisk } from '../components/RiskBadge';
import { ConfidenceQuality } from '../components/ConfidenceQuality';
import { StageProbBars } from '../components/StageProbBars';
import { VerdictBadge } from '../components/VerdictBadge';
import { AlertFilterBar, loadFilters, saveFilters, type AlertFilters } from '../components/AlertFilterBar';
import { useKeyboardShortcuts, type Shortcut } from '../hooks/useKeyboardShortcuts';
import { ShortcutsCheatsheet } from '../components/ShortcutsCheatsheet';
import { threatService } from '../services/threatDetectionService';
import { downloadFile } from '../utils/helpers';
import type { ThreatPrediction, ThreatPredictionSummary, ThreatPredictionGroup, AckState, PredictionCounts, ThreatSource } from '../types/threat';

// Type guard: was this row returned by the grouped view? Drives extra UI
// (count badge, group-ack path) without forcing a separate render branch.
function isGroup(r: ThreatPredictionSummary | ThreatPredictionGroup): r is ThreatPredictionGroup {
  return typeof (r as ThreatPredictionGroup).count === 'number'
    && Array.isArray((r as ThreatPredictionGroup).sampleIds);
}

const ACK_TABS: { key: AckState; label: string; icon: typeof Inbox; cls: string }[] = [
  { key: 'new',        label: 'New',        icon: Inbox,         cls: 'text-[#ff3366]' },
  { key: 'reviewed',   label: 'Reviewed',   icon: Eye,           cls: 'text-[#00ccff]' },
  { key: 'escalated',  label: 'Escalated',  icon: Flag,          cls: 'text-[#ffaa00]' },
  { key: 'dismissed',  label: 'Dismissed',  icon: XCircle,       cls: 'text-gray-500' },
];

// Verdict sub-tabs ordered by SOC priority. Analysts should burn down
// Confirmed first (both detectors agreed), then Sig-only (deterministic
// rule fired), and finally ML-only (Suspicious — calibration FPs live here).
type VerdictTab = 'all' | ThreatSource;
const VERDICT_TABS: { key: VerdictTab; label: string; cls: string }[] = [
  { key: 'all',            label: 'All',         cls: 'text-gray-300' },
  { key: 'confirmed',      label: 'Confirmed',   cls: 'text-[#ff3366]' },
  { key: 'signature_only', label: 'Sig-only',    cls: 'text-orange-400' },
  { key: 'ml_only',        label: 'ML-only',     cls: 'text-yellow-400' },
  { key: 'benign',         label: 'Benign',      cls: 'text-gray-500' },
];
const VERDICT_TAB_STORAGE_KEY = 'hids.alerts.verdictTab';
const GROUP_MODE_STORAGE_KEY = 'hids.alerts.grouping';
const FILTERS_STORAGE_KEY = 'hids.alerts.filters';

function formatAge(iso?: string): string {
  if (!iso) return '-';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '-';
  const seconds = Math.floor((Date.now() - t) / 1000);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

/** SLA aging buckets — colour rows that have been sitting in `new` for too
 *  long so analysts can spot stale work at a glance. Thresholds chosen to
 *  match typical SOC SLA windows (5m fresh, 30m aging, 4h stale). */
type AgeBucket = 'fresh' | 'aging' | 'stale' | 'overdue';
function ageBucket(iso?: string): AgeBucket {
  if (!iso) return 'fresh';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return 'fresh';
  const seconds = (Date.now() - t) / 1000;
  if (seconds < 5 * 60) return 'fresh';
  if (seconds < 30 * 60) return 'aging';
  if (seconds < 4 * 3600) return 'stale';
  return 'overdue';
}
const AGE_BORDER: Record<AgeBucket, string> = {
  fresh:   'border-l-transparent',
  aging:   'border-l-yellow-400/70',
  stale:   'border-l-[#ffaa00]',
  overdue: 'border-l-[#ff3366]',
};
const AGE_TEXT: Record<AgeBucket, string> = {
  fresh:   'text-gray-500',
  aging:   'text-yellow-400',
  stale:   'text-[#ffaa00]',
  overdue: 'text-[#ff3366]',
};
const LIVE_STORAGE_KEY = 'hids.alerts.live';

/** True if `ip` is an RFC1918 / loopback / link-local address. Used to
 *  grey out external-threat-intel buttons that would return nothing
 *  useful for internal traffic. */
function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('127.')) return true;
  if (ip.startsWith('169.254.')) return true;
  if (ip.startsWith('::1') || ip.startsWith('fe80')) return true;
  // 172.16.0.0 – 172.31.255.255
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) return true;
  return false;
}

function buildFlowKey(p: ThreatPrediction): string {
  return `${p.sourceIp}:${p.sourcePort}-${p.destinationIp}:${p.destinationPort}-${p.protocol}`;
}

async function copyToClipboard(text: string, label: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(`Copied ${label}`);
  } catch {
    toast.error('Clipboard write failed');
  }
}

function buildIncidentReport(p: ThreatPrediction): string {
  const lines: string[] = [];
  lines.push(`# Incident Report — ${p.attack_type ?? p.prediction}`);
  lines.push('');
  lines.push(`- **Prediction ID:** \`${p.id}\``);
  lines.push(`- **Timestamp:** ${p.timestamp}`);
  lines.push(`- **Verdict:** \`${p.source ?? 'unknown'}\``);
  lines.push(`- **ML prediction:** ${p.prediction}`);
  lines.push(`- **Attack family:** ${p.family ?? '-'}`);
  lines.push(`- **Attack leaf:** ${p.attack_type ?? '-'}`);
  lines.push(`- **Severity:** ${p.severity ?? '-'}`);
  lines.push('');
  lines.push('## Flow');
  lines.push('');
  lines.push(`- **Source:** \`${p.sourceIp}:${p.sourcePort}\``);
  lines.push(`- **Destination:** \`${p.destinationIp}:${p.destinationPort}\``);
  lines.push(`- **Protocol:** ${p.protocol}`);
  lines.push(`- **Flow key:** \`${buildFlowKey(p)}\``);
  lines.push(`- **Packet size:** ${p.packetSize} bytes`);
  lines.push(`- **Duration:** ${p.duration}s`);
  lines.push('');
  lines.push('## Model output');
  lines.push('');
  if (typeof p.stage1_p === 'number') lines.push(`- **Stage 1 p(attack):** ${(p.stage1_p * 100).toFixed(4)}% _(routing only)_`);
  if (typeof p.stage2_p === 'number') lines.push(`- **Stage 2 family p:** ${(p.stage2_p * 100).toFixed(2)}%`);
  if (typeof p.stage3_p === 'number') lines.push(`- **Stage 3 leaf p:** ${(p.stage3_p * 100).toFixed(2)}%`);
  if (p.model_version) lines.push(`- **Model version:** \`${p.model_version}\``);
  if (p.snort_msg) {
    lines.push('');
    lines.push('## Snort signature');
    lines.push('');
    lines.push(`- **Message:** ${p.snort_msg}`);
    if (p.snort_sid) lines.push(`- **SID:** ${p.snort_sid}`);
    if (p.snort_classtype) lines.push(`- **Classtype:** ${p.snort_classtype}`);
    if (p.snort_priority) lines.push(`- **Priority:** ${p.snort_priority}`);
  }
  if (p.mitre) {
    lines.push('');
    lines.push('## MITRE ATT&CK');
    lines.push('');
    if (p.mitre.tactics?.length) {
      lines.push('**Tactics:**');
      for (const t of p.mitre.tactics) lines.push(`- ${t.name} (${t.id})`);
    }
    if (p.mitre.techniques?.length) {
      lines.push('');
      lines.push('**Techniques:**');
      for (const t of p.mitre.techniques) lines.push(`- [${t.id}] ${t.name} — ${t.url}`);
    }
  }
  lines.push('');
  lines.push(`## Acknowledgement`);
  lines.push('');
  lines.push(`- **State:** ${p.ack_state ?? 'new'}`);
  if (p.ack_at) lines.push(`- **Acknowledged at:** ${p.ack_at}`);
  if (p.ack_note) lines.push(`- **Note:** ${p.ack_note}`);
  lines.push('');
  lines.push(`_Generated by Hybrid IDS Dashboard at ${new Date().toISOString()}._`);
  return lines.join('\n');
}

const ROWS_PER_PAGE = 50;

export default function AlertsPage() {
  // Server-paged queue — `pageRows` only holds the visible page (50
  // summaries ≈ 30 KB). Tab counts come from /predictions/counts so we
  // never have to download the full store to render tab badges.
  const [pageRows, setPageRows] = useState<(ThreatPredictionSummary | ThreatPredictionGroup)[]>([]);
  const [totalRows, setTotalRows] = useState(0);
  const [tabCounts, setTabCounts] = useState<PredictionCounts>({
    total: 0, new: 0, reviewed: 0, escalated: 0, dismissed: 0,
  });
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<AckState>('new');
  const [verdictTab, setVerdictTab] = useState<VerdictTab>(() => {
    if (typeof window === 'undefined') return 'all';
    const stored = window.localStorage.getItem(VERDICT_TAB_STORAGE_KEY) as VerdictTab | null;
    return stored ?? 'all';
  });
  const [currentPage, setCurrentPage] = useState(1);
  const [selected, setSelected] = useState<ThreatPredictionSummary | ThreatPredictionGroup | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<ThreatPrediction | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());
  const [note, setNote] = useState('');
  // Bulk selection state. Cleared whenever the analyst changes tabs so a
  // hidden cross-tab selection can't accidentally get acked. Persists across
  // page navigation within the same tab so multi-page selection works.
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  // Group-by-campaign toggle, persisted so an analyst's working preference
  // survives refreshes. Folds rows sharing (src, dst, family) server-side.
  const [groupMode, setGroupMode] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem(GROUP_MODE_STORAGE_KEY) === '1';
  });
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(GROUP_MODE_STORAGE_KEY, groupMode ? '1' : '0');
  }, [groupMode]);

  // Filter state — search/severity/CIDR/port-range/sort. URL params take
  // precedence on first mount so chart drilldowns from Analytics
  // (`/alerts?source=confirmed&q=192.168.10.50`) populate the bar without
  // the analyst having to re-type. After mount the state owns itself; we
  // persist to localStorage so a refresh keeps the working set.
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = useState<AlertFilters>(() => {
    const urlInit: AlertFilters = {};
    const urlQ = searchParams.get('q');
    if (urlQ) urlInit.q = urlQ;
    const urlSev = searchParams.get('severity');
    if (urlSev === 'high' || urlSev === 'medium' || urlSev === 'low') urlInit.severity = urlSev;
    const urlSrc = searchParams.get('src_cidr');
    if (urlSrc) urlInit.src_cidr = urlSrc;
    const urlDst = searchParams.get('dst_cidr');
    if (urlDst) urlInit.dst_cidr = urlDst;
    if (Object.keys(urlInit).length > 0) return urlInit;
    return loadFilters(FILTERS_STORAGE_KEY);
  });
  useEffect(() => {
    saveFilters(FILTERS_STORAGE_KEY, filters);
  }, [filters]);
  // After applying URL params on first mount, strip them so refreshing
  // the page doesn't keep re-applying stale deep-links over the analyst's
  // subsequent edits. Only runs once.
  const didConsumeUrl = useRef(false);
  useEffect(() => {
    if (didConsumeUrl.current) return;
    didConsumeUrl.current = true;
    if (searchParams.toString()) {
      setSearchParams({}, { replace: true });
    }
  }, [searchParams, setSearchParams]);
  // Forward `?source=` from URL into the verdict tab on first mount.
  useEffect(() => {
    const urlSource = searchParams.get('source');
    if (urlSource === 'confirmed' || urlSource === 'signature_only' || urlSource === 'ml_only' || urlSource === 'benign') {
      setVerdictTab(urlSource);
    }
    const urlAck = searchParams.get('ack_state');
    if (urlAck === 'new' || urlAck === 'reviewed' || urlAck === 'escalated' || urlAck === 'dismissed') {
      setActiveTab(urlAck);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Ref the filter bar's search input so the `/` shortcut can focus it.
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  // Keyboard navigation — `focusedId` tracks j/k highlight independently
  // of `selected` (which controls the drawer). Falls back to the first
  // row when the page changes.
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [cheatsheetOpen, setCheatsheetOpen] = useState(false);

  // Live auto-refresh — polls every 5s when ON, tab=new, and the document
  // is visible. Persisted to localStorage so an analyst's preference
  // survives refreshes; we never poll while backgrounded so DevTools won't
  // light up with requests in the background.
  const [live, setLive] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem(LIVE_STORAGE_KEY) === '1';
  });
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(LIVE_STORAGE_KEY, live ? '1' : '0');
  }, [live]);
  // Track previous new-count so the "N new since you opened" banner is
  // honest — we increment only on the delta, not the running total.
  const baselineNewRef = useRef<number>(0);
  const [newSinceOpened, setNewSinceOpened] = useState(0);
  useEffect(() => {
    // Reset the baseline when the tab or filter set changes.
    baselineNewRef.current = tabCounts.new;
    setNewSinceOpened(0);
  }, [activeTab, verdictTab, groupMode, filters]);
  useEffect(() => {
    if (activeTab !== 'new') return;
    const delta = tabCounts.new - baselineNewRef.current;
    setNewSinceOpened(delta > 0 ? delta : 0);
  }, [tabCounts.new, activeTab]);
  // Re-render every 30s so the age strings + buckets stay current without
  // a full refetch. Cheap — only the visible page's rows recompute.
  const [, setAgeTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setAgeTick((n) => n + 1), 30 * 1000);
    return () => clearInterval(t);
  }, []);
  // Related-alerts pane state — fetched on drawer open. Up to 10 rows
  // sharing the same flow key, excluding the selected row itself.
  const [related, setRelated] = useState<ThreatPredictionSummary[]>([]);
  const [relatedLoading, setRelatedLoading] = useState(false);
  useEffect(() => {
    if (!selected) {
      setRelated([]);
      return;
    }
    const flowKey = `${selected.sourceIp}:${selected.sourcePort}-${selected.destinationIp}:${selected.destinationPort}-${selected.protocol}`;
    let cancelled = false;
    setRelatedLoading(true);
    threatService
      .getPredictionsPage({ q: flowKey, limit: 11 })
      .then((page) => {
        if (cancelled) return;
        const items = (page.items as ThreatPredictionSummary[]).filter((r) => r.id !== selected.id).slice(0, 10);
        setRelated(items);
      })
      .catch(() => {
        if (!cancelled) setRelated([]);
      })
      .finally(() => {
        if (!cancelled) setRelatedLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  // Persist the analyst's verdict sub-tab choice so refreshes don't reset.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(VERDICT_TAB_STORAGE_KEY, verdictTab);
  }, [verdictTab]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [page, counts] = await Promise.all([
        threatService.getPredictionsPage({
          limit: ROWS_PER_PAGE,
          offset: (currentPage - 1) * ROWS_PER_PAGE,
          ack_state: activeTab,
          // Server-side verdict filter — the /predictions endpoint already
          // supports ?source=… so we don't pull then drop on the client.
          source: verdictTab === 'all' ? undefined : verdictTab,
          group: groupMode ? 'campaign' : undefined,
          q: filters.q,
          severity: filters.severity,
          src_cidr: filters.src_cidr,
          dst_cidr: filters.dst_cidr,
          port_min: filters.port_min,
          port_max: filters.port_max,
          sort: filters.sort,
          dir: filters.dir,
        }),
        threatService.getPredictionsCounts(),
      ]);
      setPageRows(page.items);
      setTotalRows(page.total);
      setTabCounts(counts);
    } catch (err) {
      console.error(err);
      toast.error('Failed to load predictions');
    } finally {
      setLoading(false);
    }
  }, [activeTab, currentPage, verdictTab, groupMode, filters]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Live poll interval. Bails on hidden tabs via visibilitychange.
  // Lives below `refresh` so the useCallback is initialized before this
  // effect captures it (avoids a temporal-dead-zone error on first render).
  useEffect(() => {
    if (!live || activeTab !== 'new') return;
    let active = document.visibilityState === 'visible';
    const onVis = () => {
      active = document.visibilityState === 'visible';
    };
    document.addEventListener('visibilitychange', onVis);
    const t = setInterval(() => {
      if (active) void refresh();
    }, 5000);
    return () => {
      document.removeEventListener('visibilitychange', onVis);
      clearInterval(t);
    };
  }, [live, activeTab, refresh]);

  // Reset to page 1 + clear bulk selection when switching tabs. Cross-tab
  // selection would let an analyst accidentally ack rows they can no longer
  // see, which is exactly the kind of mistake bulk actions amplify.
  useEffect(() => {
    setCurrentPage(1);
    setSelected(null);
    setSelectedDetail(null);
    setSelectedIds(new Set());
  }, [activeTab, verdictTab, groupMode, filters]);

  // Lazy-fetch the full record (with heavy fields) for the open drawer.
  useEffect(() => {
    if (!selected) {
      setSelectedDetail(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    threatService
      .getPredictionDetail(selected.id)
      .then((full) => {
        if (!cancelled) setSelectedDetail(full);
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedDetail(null);
          toast.error('Failed to load alert detail');
        }
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  const totalPages = Math.max(1, Math.ceil(totalRows / ROWS_PER_PAGE));
  const visibleRows = pageRows;

  // Keep `focusedId` valid against the current page. When the page reloads
  // and the focused row is gone, snap to the first row so j/k keep working.
  useEffect(() => {
    if (!visibleRows.length) {
      setFocusedId(null);
      return;
    }
    if (!focusedId || !visibleRows.some((r) => r.id === focusedId)) {
      setFocusedId(visibleRows[0].id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageRows]);

  const handleAck = async (p: ThreatPredictionSummary | ThreatPredictionGroup, state: AckState) => {
    setBusyIds((prev) => new Set(prev).add(p.id));
    try {
      let okMessage = `Marked ${state}`;
      if (isGroup(p)) {
        // Campaign row — ack every child via the match endpoint so we cover
        // children beyond the sampleIds cap (groups can be 10k+ flows).
        const r = await threatService.ackPredictionsByMatch({
          sourceIp: p.sourceIp,
          destinationIp: p.destinationIp,
          family: p.family ?? null,
          state,
          note: note || null,
        });
        okMessage = `Marked ${r.updated} flows as ${state}`;
      } else {
        const updated = await threatService.ackPrediction(p.id, state, note || null);
        if (selected?.id === p.id) {
          setSelected({ ...selected, ack_state: state, ack_at: updated.ack_at, ack_note: updated.ack_note });
        }
      }
      setNote('');
      toast.success(okMessage);
      await refresh();
    } catch (err) {
      console.error(err);
      toast.error('Acknowledgement failed');
    } finally {
      setBusyIds((prev) => {
        const next = new Set(prev);
        next.delete(p.id);
        return next;
      });
    }
  };

  // Bulk-ack helpers --------------------------------------------------------

  const toggleRowSelected = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const togglePageSelected = () => {
    const pageIds = visibleRows.map((r) => r.id);
    const allSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id));
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allSelected) {
        for (const id of pageIds) next.delete(id);
      } else {
        for (const id of pageIds) next.add(id);
      }
      return next;
    });
  };

  const handleBulkAck = async (state: AckState) => {
    if (selectedIds.size === 0) return;
    setBulkBusy(true);
    try {
      // In group mode, each "selected id" is the rep row's id but stands for
      // every child of the group. Run one ack-by-match call per selected
      // group (cheap — the backend pass is O(N) regardless), so a select-all
      // of a 1789-flow campaign actually acks all 1789, not just the rep.
      let totalUpdated = 0;
      if (groupMode) {
        const selectedRows = pageRows.filter((r) => selectedIds.has(r.id));
        const results = await Promise.all(
          selectedRows.map((r) =>
            isGroup(r)
              ? threatService.ackPredictionsByMatch({
                  sourceIp: r.sourceIp,
                  destinationIp: r.destinationIp,
                  family: r.family ?? null,
                  state,
                  note: note || null,
                })
              : threatService.ackPrediction(r.id, state, note || null).then(() => ({ updated: 1 })),
          ),
        );
        totalUpdated = results.reduce((s, r) => s + r.updated, 0);
        toast.success(`Marked ${totalUpdated} flows as ${state}`);
      } else {
        const ids = Array.from(selectedIds);
        const result = await threatService.ackPredictionsBulk(ids, state, note || null);
        totalUpdated = result.updated;
        toast.success(
          result.missing.length > 0
            ? `Marked ${result.updated} as ${state} (${result.missing.length} not found)`
            : `Marked ${result.updated} as ${state}`,
        );
      }
      setNote('');
      setSelectedIds(new Set());
      await refresh();
    } catch (err) {
      console.error(err);
      toast.error('Bulk acknowledgement failed');
    } finally {
      setBulkBusy(false);
    }
  };

  // Move keyboard focus up/down in the queue, wrapping at edges.
  const moveFocus = (delta: 1 | -1) => {
    if (!visibleRows.length) return;
    const idx = Math.max(0, visibleRows.findIndex((r) => r.id === focusedId));
    const nextIdx = (idx + delta + visibleRows.length) % visibleRows.length;
    setFocusedId(visibleRows[nextIdx].id);
  };

  // Run an ack against the currently focused row (or `selected` if drawer
  // is open and no row is focused). Used by the `r`/`e`/`d` shortcuts.
  const ackFocused = (state: AckState) => {
    const target = visibleRows.find((r) => r.id === focusedId) ?? selected;
    if (target) void handleAck(target, state);
  };

  // Bulk-export selected rows. Uses the slim summary shape (already in
  // `pageRows`) so we don't refetch — the rows the analyst sees are the
  // rows they get. For groups, sampleIds[0]'s summary stands in.
  const handleBulkExport = (fmt: 'csv' | 'json') => {
    if (selectedIds.size === 0) return;
    const summaries = pageRows.filter((r) => selectedIds.has(r.id)) as ThreatPredictionSummary[];
    const content = fmt === 'csv'
      ? threatService.exportToCSV(summaries)
      : threatService.exportToJSON(summaries);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    downloadFile(content, `alerts_${stamp}.${fmt}`, fmt === 'csv' ? 'text/csv' : 'application/json');
    toast.success(`Exported ${summaries.length} alerts to ${fmt.toUpperCase()}`);
  };

  // Drop a suppression rule. Same flow for SID/src_ip/src_cidr/flow_key —
  // `value` and `kind` come from the dropdown choice in the drawer.
  const handleSuppress = async (kind: 'sid' | 'src_ip' | 'flow_key', value: string, label: string, hours?: number) => {
    if (!value) {
      toast.error('Nothing to suppress');
      return;
    }
    try {
      const expires_at = hours
        ? new Date(Date.now() + hours * 3600 * 1000).toISOString()
        : null;
      await threatService.createSuppression({ kind, value, expires_at });
      toast.success(`Suppressed ${label}${hours ? ` for ${hours}h` : ' (no expiry)'}`);
    } catch (err) {
      console.error(err);
      toast.error('Failed to add suppression rule');
    }
  };

  const handleExport = async (p: ThreatPredictionSummary) => {
    try {
      // Fetch the full record on click — the queue rows only carry the
      // slim summary, so we need stage probs / mitre techniques / ml
      // features for the incident report.
      const full = selectedDetail?.id === p.id
        ? selectedDetail
        : await threatService.getPredictionDetail(p.id);
      const md = buildIncidentReport(full);
      const safeId = p.id.replace(/[^A-Za-z0-9_-]/g, '_');
      downloadFile(md, `incident_${safeId}.md`, 'text/markdown');
      toast.success('Incident report downloaded');
    } catch (err) {
      console.error(err);
      toast.error('Failed to build incident report');
    }
  };

  // Shortcut bindings. The array reference is intentionally new on every
  // render — the hook rebinds cheaply, and the handlers close over fresh
  // state (focusedId, selected, visibleRows) without us having to thread
  // refs through each one.
  const shortcuts: Shortcut[] = [
    { key: 'j',      group: 'Navigation', description: 'Next alert',     handler: () => moveFocus(1) },
    { key: 'k',      group: 'Navigation', description: 'Previous alert', handler: () => moveFocus(-1) },
    { key: 'ArrowDown', group: 'Navigation', description: 'Next alert',  handler: () => moveFocus(1) },
    { key: 'ArrowUp',   group: 'Navigation', description: 'Previous alert', handler: () => moveFocus(-1) },
    { key: 'Enter',  group: 'Navigation', description: 'Open drawer',
      handler: () => {
        const t = visibleRows.find((r) => r.id === focusedId);
        if (t) setSelected(t);
      } },
    { key: 'Escape', allowInInput: true, group: 'Navigation', description: 'Close drawer / clear selection',
      handler: () => {
        if (cheatsheetOpen) { setCheatsheetOpen(false); return; }
        if (selected) { setSelected(null); return; }
        if (selectedIds.size > 0) setSelectedIds(new Set());
      } },
    { key: 'gg',     group: 'Navigation', description: 'Jump to top',    handler: () => setCurrentPage(1) },
    { key: 'G',  shift: true, group: 'Navigation', description: 'Jump to bottom', handler: () => setCurrentPage(totalPages) },
    { key: 'r',      group: 'Triage', description: 'Mark reviewed',
      handler: () => (selectedIds.size > 0 ? handleBulkAck('reviewed') : ackFocused('reviewed')) },
    { key: 'e',      group: 'Triage', description: 'Escalate',
      handler: () => (selectedIds.size > 0 ? handleBulkAck('escalated') : ackFocused('escalated')) },
    { key: 'd',      group: 'Triage', description: 'Dismiss',
      handler: () => (selectedIds.size > 0 ? handleBulkAck('dismissed') : ackFocused('dismissed')) },
    { key: 'x',      group: 'Selection', description: 'Toggle selection on focused row',
      handler: () => { if (focusedId) toggleRowSelected(focusedId); } },
    { key: 'X', shift: true, group: 'Selection', description: 'Toggle select-all on page',
      handler: () => togglePageSelected() },
    { key: '/',      group: 'Filter',   description: 'Focus search',
      handler: () => searchInputRef.current?.focus() },
    { key: '?', shift: true, group: 'Help', description: 'Show this cheatsheet',
      handler: () => setCheatsheetOpen(true) },
  ];
  useKeyboardShortcuts(shortcuts);

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] py-12">
      <div className="container mx-auto px-4">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
          <div className="mb-6 flex items-start justify-between flex-wrap gap-4">
            <div>
              <h1 className="text-4xl font-bold text-white mb-2 flex items-center gap-3">
                <ShieldAlert className="w-8 h-8 text-[#ff3366]" />
                Alerts Queue
              </h1>
              <p className="text-gray-400">
                Analyst-facing queue of stored hybrid-IDS predictions. The <em>New</em> tab is filtered to
                actionable alerts (non-benign, medium/high severity); other tabs show every prediction in
                that state.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setLive((v) => !v)}
                className={`px-2 py-1 rounded border text-[11px] inline-flex items-center gap-2 transition-colors ${
                  live
                    ? 'bg-[#00ff88]/10 border-[#00ff88]/50 text-[#00ff88]'
                    : 'border-[#1a2540] text-gray-400 hover:text-white hover:bg-[#1a2540]/60'
                }`}
                title={
                  live
                    ? 'Live: polling every 5s while New tab is visible'
                    : 'Live: paused. Click to enable 5s auto-refresh.'
                }
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    live ? 'bg-[#00ff88] animate-pulse' : 'bg-gray-600'
                  }`}
                />
                Live
              </button>
              <button
                type="button"
                onClick={() => setCheatsheetOpen(true)}
                className="px-2 py-1 rounded border border-[#1a2540] text-gray-400 hover:text-white hover:bg-[#1a2540]/60 text-[11px] inline-flex items-center gap-1"
                title="Show keyboard shortcuts (Shift+?)"
              >
                <span className="font-mono">?</span>
                Shortcuts
              </button>
              <Button
                onClick={refresh}
                variant="outline"
                className="border-[#00ccff] text-[#00ccff] hover:bg-[#00ccff]/10"
              >
                <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </div>
          </div>

          {/* Verdict sub-tabs — SOC hierarchy. Burn down Confirmed first
              (both detectors agreed), then Sig-only (deterministic rule
              fired), then ML-only Suspicious (most are calibration FPs). */}
          <div className="mb-3">
            <div className="text-[10px] uppercase tracking-wide text-gray-500 mb-1.5 ml-1">
              Verdict
            </div>
            <div className="flex flex-wrap gap-2">
              {VERDICT_TABS.map((t) => {
                const active = verdictTab === t.key;
                return (
                  <button
                    key={t.key}
                    type="button"
                    onClick={() => {
                      setVerdictTab(t.key);
                      setSelected(null);
                    }}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs transition-colors ${
                      active
                        ? 'bg-[#1a2540]/80 border-[#00ccff]/50 text-white'
                        : 'bg-[#0f1825]/40 border-[#1a2540] text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    <span className={`font-semibold ${t.cls}`}>{t.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Group-by-campaign pill — folds rows sharing (src, dst, family).
              Sits between the verdict tabs and ack tabs so it reads as a
              modifier on the listing, not a filter. */}
          <div className="mb-3 flex items-center gap-3">
            <button
              type="button"
              onClick={() => setGroupMode((v) => !v)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs transition-colors ${
                groupMode
                  ? 'bg-[#00ccff]/10 border-[#00ccff]/50 text-[#00ccff]'
                  : 'bg-[#0f1825]/40 border-[#1a2540] text-gray-400 hover:text-gray-200'
              }`}
              title="Fold rows sharing source IP, destination IP, and family"
            >
              <Square className={`w-3.5 h-3.5 ${groupMode ? 'fill-current' : ''}`} />
              Group by campaign
            </button>
            {groupMode && (
              <span className="text-[10px] text-gray-500 italic">
                Each row represents many flows. Acking a row acks every child.
              </span>
            )}
          </div>

          {/* Ack-state tabs */}
          <div className="flex flex-wrap gap-2 mb-6">
            {ACK_TABS.map((t) => {
              const active = activeTab === t.key;
              return (
                <button
                  key={t.key}
                  type="button"
                  onClick={() => {
                    setActiveTab(t.key);
                    setSelected(null);
                  }}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm transition-colors ${
                    active
                      ? 'bg-[#1a2540]/80 border-[#00ccff]/50 text-white'
                      : 'bg-[#0f1825]/50 border-[#1a2540] text-gray-400 hover:text-gray-200 hover:border-[#1a2540]'
                  }`}
                >
                  <t.icon className={`w-4 h-4 ${t.cls}`} />
                  {t.label}
                  <span className="ml-1 font-mono text-xs opacity-80">({tabCounts[t.key]})</span>
                </button>
              );
            })}
          </div>

          {/* "N new since you opened" banner — only fires on the New tab
              with Live on. Clicking refreshes and resets the baseline. */}
          {newSinceOpened > 0 && live && activeTab === 'new' && (
            <button
              type="button"
              onClick={() => {
                baselineNewRef.current = tabCounts.new;
                setNewSinceOpened(0);
                void refresh();
              }}
              className="mb-3 w-full text-left px-3 py-2 rounded-md border border-[#00ff88]/40 bg-[#00ff88]/5 text-[#00ff88] text-xs inline-flex items-center gap-2 hover:bg-[#00ff88]/10"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse" />
              <span className="font-semibold">{newSinceOpened}</span>
              <span className="text-gray-400">new alert{newSinceOpened === 1 ? '' : 's'} since you opened this — click to refresh</span>
            </button>
          )}

          {/* Filter bar — search/severity/CIDR/port-range/sort. Drives
              server-side filtering via the extended /predictions params. */}
          <AlertFilterBar
            value={filters}
            onChange={setFilters}
            searchInputRef={searchInputRef}
          />

          {/* Bulk-action toolbar — sticky so it stays visible while the
              analyst scrolls a long queue. Renders only when at least one
              row is selected; the "Clear" button is the only way to drop a
              selection besides switching tabs or acking. */}
          <AnimatePresence>
            {selectedIds.size > 0 && (
              <motion.div
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.15 }}
                className="sticky top-2 z-30 mb-3"
              >
                <div className="bg-[#1a2540]/95 border border-[#00ccff]/40 rounded-lg shadow-lg backdrop-blur px-4 py-2 flex items-center gap-3 flex-wrap">
                  <span className="text-sm text-white">
                    <span className="font-mono font-bold text-[#00ccff]">{selectedIds.size}</span>
                    <span className="text-gray-400 ml-1">selected</span>
                  </span>
                  <div className="h-5 w-px bg-[#1a2540]" />
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={bulkBusy}
                    onClick={() => handleBulkAck('reviewed')}
                    className="h-7 border-[#00ccff]/40 text-[#00ccff] hover:bg-[#00ccff]/10 text-xs"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                    Mark Reviewed
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={bulkBusy}
                    onClick={() => handleBulkAck('escalated')}
                    className="h-7 border-[#ffaa00]/40 text-[#ffaa00] hover:bg-[#ffaa00]/10 text-xs"
                  >
                    <Flag className="w-3.5 h-3.5 mr-1" />
                    Escalate
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={bulkBusy}
                    onClick={() => handleBulkAck('dismissed')}
                    className="h-7 border-gray-600 text-gray-400 hover:bg-gray-600/10 text-xs"
                  >
                    <XCircle className="w-3.5 h-3.5 mr-1" />
                    Dismiss
                  </Button>
                  {activeTab !== 'new' && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={bulkBusy}
                      onClick={() => handleBulkAck('new')}
                      className="h-7 border-[#1a2540] text-gray-400 hover:bg-[#1a2540] text-xs"
                    >
                      Reopen
                    </Button>
                  )}
                  <div className="h-5 w-px bg-[#1a2540]" />
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={bulkBusy}
                    onClick={() => handleBulkExport('csv')}
                    className="h-7 border-[#00ff88]/40 text-[#00ff88] hover:bg-[#00ff88]/10 text-xs"
                  >
                    <Download className="w-3.5 h-3.5 mr-1" />
                    CSV
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={bulkBusy}
                    onClick={() => handleBulkExport('json')}
                    className="h-7 border-[#00ff88]/40 text-[#00ff88] hover:bg-[#00ff88]/10 text-xs"
                  >
                    <Download className="w-3.5 h-3.5 mr-1" />
                    JSON
                  </Button>
                  <div className="flex-1" />
                  <button
                    type="button"
                    onClick={() => setSelectedIds(new Set())}
                    className="text-xs text-gray-400 hover:text-white inline-flex items-center gap-1"
                  >
                    <XIcon className="w-3.5 h-3.5" />
                    Clear selection
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="grid lg:grid-cols-3 gap-6">
            {/* Queue table */}
            <div className="lg:col-span-2">
              <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                <CardContent className="p-0">
                  {visibleRows.length === 0 ? (
                    <div className="p-16 text-center">
                      <motion.div
                        animate={{ scale: [1, 1.05, 1], opacity: [0.4, 0.7, 0.4] }}
                        transition={{ duration: 2.5, repeat: Infinity }}
                        className="inline-flex w-20 h-20 items-center justify-center rounded-full bg-[#00ff88]/10 border border-[#00ff88]/30 mb-4"
                      >
                        <ShieldCheck className="w-10 h-10 text-[#00ff88]" />
                      </motion.div>
                      <h3 className="text-lg font-semibold text-white mb-1">
                        {activeTab === 'new' ? 'All clear' : 'No alerts here'}
                      </h3>
                      <p className="text-sm text-gray-500">
                        {activeTab === 'new'
                          ? 'No new high-severity alerts. New detections will appear here automatically.'
                          : `No alerts in the ${activeTab} state.`}
                      </p>
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead className="border-b border-[#1a2540] text-xs text-gray-500 uppercase tracking-wide">
                          <tr>
                            <th className="p-3 w-8">
                              {(() => {
                                const pageIds = visibleRows.map((r) => r.id);
                                const allSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id));
                                const someSelected = !allSelected && pageIds.some((id) => selectedIds.has(id));
                                const Icon = allSelected ? CheckSquare : someSelected ? CheckSquare : Square;
                                const cls = allSelected || someSelected ? 'text-[#00ccff]' : 'text-gray-500 hover:text-gray-300';
                                return (
                                  <button
                                    type="button"
                                    onClick={togglePageSelected}
                                    className={`flex items-center transition-colors ${cls}`}
                                    title={allSelected ? 'Deselect page' : 'Select all on page'}
                                    aria-label="Toggle page selection"
                                  >
                                    <Icon className={`w-4 h-4 ${someSelected ? 'opacity-60' : ''}`} />
                                  </button>
                                );
                              })()}
                            </th>
                            <th className="text-left p-3">Time</th>
                            <th className="text-left p-3">Source → Destination</th>
                            <th className="text-left p-3">Verdict</th>
                            <th className="text-left p-3">Family · Leaf</th>
                            <th className="text-left p-3">Risk</th>
                            <th className="text-right p-3">Age</th>
                            <th className="text-right p-3">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {visibleRows.map((p) => {
                            const bucket = ageBucket(p.timestamp);
                            // Only show aging stripe for unacknowledged work.
                            const showAge = (p.ack_state ?? 'new') === 'new';
                            return (
                            <tr
                              key={p.id}
                              onClick={() => setSelected(p)}
                              className={`border-b border-[#1a2540]/40 cursor-pointer transition-colors border-l-2 ${
                                showAge ? AGE_BORDER[bucket] : 'border-l-transparent'
                              } ${
                                selectedIds.has(p.id)
                                  ? 'bg-[#00ccff]/10'
                                  : selected?.id === p.id
                                  ? 'bg-[#00ccff]/5 ring-1 ring-inset ring-[#00ccff]/40'
                                  : focusedId === p.id
                                  ? 'bg-[#1a2540]/30 ring-1 ring-inset ring-[#1a2540]'
                                  : 'hover:bg-[#1a2540]/40'
                              }`}
                            >
                              <td className="p-3 w-8" onClick={(e) => e.stopPropagation()}>
                                {(() => {
                                  const checked = selectedIds.has(p.id);
                                  const Icon = checked ? CheckSquare : Square;
                                  return (
                                    <button
                                      type="button"
                                      onClick={() => toggleRowSelected(p.id)}
                                      className={`flex items-center transition-colors ${
                                        checked ? 'text-[#00ccff]' : 'text-gray-600 hover:text-gray-300'
                                      }`}
                                      aria-label={checked ? 'Deselect row' : 'Select row'}
                                    >
                                      <Icon className="w-4 h-4" />
                                    </button>
                                  );
                                })()}
                              </td>
                              <td className="p-3 text-gray-400 font-mono whitespace-nowrap">
                                {new Date(p.timestamp).toLocaleTimeString()}
                              </td>
                              <td className="p-3 text-gray-300 font-mono whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                                <button
                                  type="button"
                                  onClick={() => setFilters({ ...filters, q: p.sourceIp })}
                                  className="text-gray-200 hover:text-[#00ccff] hover:underline underline-offset-2"
                                  title={`Filter by source ${p.sourceIp}`}
                                >
                                  {p.sourceIp}
                                </button>
                                <span className="text-gray-600 mx-1">→</span>
                                <button
                                  type="button"
                                  onClick={() => setFilters({ ...filters, q: p.destinationIp })}
                                  className="text-gray-200 hover:text-[#00ccff] hover:underline underline-offset-2"
                                  title={`Filter by destination ${p.destinationIp}`}
                                >
                                  {p.destinationIp}
                                </button>
                                <span className="text-gray-500 ml-1 text-xs">:{p.destinationPort}</span>
                              </td>
                              <td className="p-3">
                                <VerdictBadge source={p.source} size="text-[10px] py-0" title={p.snort_msg || ''} />
                              </td>
                              <td className="p-3 text-xs">
                                <div className="text-gray-300 font-mono flex items-center gap-2">
                                  {p.family ?? '-'}
                                  {isGroup(p) && (
                                    <span
                                      className="px-1.5 py-0.5 rounded bg-[#00ccff]/15 text-[#00ccff] font-mono text-[10px] border border-[#00ccff]/30"
                                      title={`Campaign of ${p.count.toLocaleString()} flows · first seen ${p.firstSeen} · last ${p.lastSeen}`}
                                    >
                                      ×{p.count.toLocaleString()}
                                    </span>
                                  )}
                                </div>
                                <div className="text-gray-500 font-mono">{p.attack_type ?? '-'}</div>
                              </td>
                              <td className="p-3">
                                <RiskBadge risk={severityToRisk(p.severity)} size="text-[10px] py-0" />
                              </td>
                              <td className={`p-3 text-right text-xs font-mono ${
                                showAge ? AGE_TEXT[bucket] : 'text-gray-500'
                              }`}>
                                <div className="flex items-center justify-end gap-1">
                                  <Clock className="w-3 h-3" />
                                  {formatAge(p.timestamp)}
                                </div>
                              </td>
                              <td className="p-3 text-right whitespace-nowrap">
                                {activeTab === 'new' ? (
                                  <div className="inline-flex gap-1" onClick={(e) => e.stopPropagation()}>
                                    <Button
                                      size="sm"
                                      variant="ghost"
                                      disabled={busyIds.has(p.id)}
                                      className="h-7 px-2 text-[#00ccff] hover:bg-[#00ccff]/10"
                                      onClick={() => handleAck(p, 'reviewed')}
                                    >
                                      <Eye className="w-3.5 h-3.5" />
                                    </Button>
                                    <Button
                                      size="sm"
                                      variant="ghost"
                                      disabled={busyIds.has(p.id)}
                                      className="h-7 px-2 text-[#ffaa00] hover:bg-[#ffaa00]/10"
                                      onClick={() => handleAck(p, 'escalated')}
                                    >
                                      <Flag className="w-3.5 h-3.5" />
                                    </Button>
                                    <Button
                                      size="sm"
                                      variant="ghost"
                                      disabled={busyIds.has(p.id)}
                                      className="h-7 px-2 text-gray-500 hover:bg-gray-600/10"
                                      onClick={() => handleAck(p, 'dismissed')}
                                    >
                                      <XCircle className="w-3.5 h-3.5" />
                                    </Button>
                                  </div>
                                ) : (
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    disabled={busyIds.has(p.id)}
                                    className="h-7 px-2 text-gray-400 hover:bg-[#1a2540]"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleAck(p, 'new');
                                    }}
                                  >
                                    Reopen
                                  </Button>
                                )}
                              </td>
                            </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                  {totalPages > 1 && (
                    <div className="flex items-center justify-between gap-3 px-3 py-2 border-t border-[#1a2540] text-xs bg-[#0f1825]/70">
                      <span className="text-gray-500">
                        Page <span className="font-mono text-gray-300">{currentPage}</span> of{' '}
                        <span className="font-mono text-gray-300">{totalPages.toLocaleString()}</span>{' '}
                        <span className="text-gray-600">({totalRows.toLocaleString()} alerts in this tab)</span>
                      </span>
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          onClick={() => setCurrentPage(1)}
                          disabled={currentPage === 1 || loading}
                          className="px-2 py-1 rounded border border-[#1a2540] text-gray-400 hover:text-white hover:bg-[#1a2540]/60 disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          «
                        </button>
                        <button
                          type="button"
                          onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                          disabled={currentPage === 1 || loading}
                          className="px-2 py-1 rounded border border-[#1a2540] text-gray-400 hover:text-white hover:bg-[#1a2540]/60 disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          Prev
                        </button>
                        <button
                          type="button"
                          onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                          disabled={currentPage === totalPages || loading}
                          className="px-2 py-1 rounded border border-[#1a2540] text-gray-400 hover:text-white hover:bg-[#1a2540]/60 disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          Next
                        </button>
                        <button
                          type="button"
                          onClick={() => setCurrentPage(totalPages)}
                          disabled={currentPage === totalPages || loading}
                          className="px-2 py-1 rounded border border-[#1a2540] text-gray-400 hover:text-white hover:bg-[#1a2540]/60 disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          »
                        </button>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Detail drawer */}
            <div className="lg:col-span-1">
              <AnimatePresence mode="wait">
                {selected ? (
                  <motion.div
                    key={selected.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.2 }}
                  >
                    <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                      <CardContent className="p-4 space-y-4">
                        {/* Header */}
                        <div className="flex items-center justify-between gap-2">
                          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                            <Eye className="w-4 h-4 text-[#00ccff]" />
                            Alert Detail
                          </h3>
                          <VerdictBadge source={selected.source} size="text-[10px] py-0" />
                        </div>

                        {/* Attack classification — colour follows the
                            prediction so Suspicious doesn't read as
                            Confirmed-Malicious. */}
                        {selected.attack_type && (() => {
                          const isSusp = selected.prediction === 'Suspicious';
                          const bg = isSusp
                            ? 'bg-yellow-400/5 border-yellow-400/30'
                            : 'bg-[#ff3366]/5 border-[#ff3366]/20';
                          const txt = isSusp ? 'text-yellow-400' : 'text-[#ff3366]';
                          return (
                            <div className={`p-3 rounded-lg border space-y-1 ${bg}`}>
                              <div className="text-[10px] uppercase tracking-wide text-gray-500">
                                Classification {isSusp && <span className="text-yellow-400/70">· ML-only, analyst review</span>}
                              </div>
                              <div className={`text-sm font-bold ${txt}`}>{selected.attack_type}</div>
                              {selected.family && (
                                <div className="text-[11px] text-gray-400">
                                  <span className="text-gray-500">Family:</span>{' '}
                                  <span className="font-mono">{selected.family}</span>
                                </div>
                              )}
                              <div className="flex items-center gap-2 pt-1">
                                <RiskBadge risk={severityToRisk(selected.severity)} />
                                <ConfidenceQuality stage2_p={selected.stage2_p ?? null} />
                              </div>
                            </div>
                          );
                        })()}

                        {/* Model Confidence — headline gauge so analysts can
                            triage at a glance without scanning the per-stage
                            block. Matches the DashboardPage live-detail layout
                            so the visual treatment is consistent across pages. */}
                        {(() => {
                          const conf = typeof selected.confidence === 'number' ? selected.confidence : 0;
                          const pct = Math.max(0, Math.min(1, conf)) * 100;
                          const isSusp = selected.prediction === 'Suspicious';
                          const isMal = selected.prediction === 'Malicious';
                          const barColor = isSusp
                            ? '#facc15'
                            : isMal
                            ? '#ff3366'
                            : '#00ff88';
                          const textColor = isSusp
                            ? 'text-yellow-400'
                            : isMal
                            ? 'text-[#ff3366]'
                            : 'text-[#00ff88]';
                          return (
                            <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540] space-y-2">
                              <div className="flex items-center gap-2">
                                <Gauge className="w-4 h-4 text-[#00ccff]" />
                                <span className="text-[10px] uppercase tracking-wide text-gray-500">
                                  Model Confidence
                                </span>
                              </div>
                              <div className="flex items-center gap-3">
                                <span className={`text-2xl font-bold ${textColor}`}>
                                  {pct.toFixed(1)}%
                                </span>
                                <div className="flex-1 h-2 bg-[#1a2540]/60 rounded-full overflow-hidden">
                                  <div
                                    className="h-full rounded-full transition-all duration-500"
                                    style={{ width: `${pct}%`, backgroundColor: barColor }}
                                  />
                                </div>
                              </div>
                              <p className="text-[10px] text-gray-500 italic">
                                Stage 2 × Stage 3 — the routing-confirmed leaf probability.
                                Stage 1 (calibration-shifted) is intentionally excluded.
                                {isSusp && ' ML-only — Snort did not corroborate, treat as suspicious.'}
                              </p>
                            </div>
                          );
                        })()}

                        {/* Flow — IPs are clickable (drilldown via filters)
                            and SID/flow-key get copy buttons. */}
                        <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540] space-y-2">
                          <div className="text-[10px] uppercase tracking-wide text-gray-500">Flow</div>
                          {(() => {
                            const flowKey = buildFlowKey(selected);
                            const rows: { label: string; value: string; copy?: string; filterQ?: string; mono?: boolean }[] = [
                              { label: 'Source IP', value: selected.sourceIp, copy: selected.sourceIp, filterQ: selected.sourceIp },
                              { label: 'Destination IP', value: selected.destinationIp, copy: selected.destinationIp, filterQ: selected.destinationIp },
                              { label: 'Source Port', value: String(selected.sourcePort) },
                              { label: 'Destination Port', value: String(selected.destinationPort) },
                              { label: 'Protocol', value: selected.protocol },
                              { label: 'Flow Key', value: flowKey, copy: flowKey, mono: true },
                            ];
                            return rows.map((row) => {
                              const isIp = row.label === 'Source IP' || row.label === 'Destination IP';
                              const ipForLinks = isIp ? row.value : '';
                              const priv = isIp && isPrivateIp(ipForLinks);
                              return (
                              <div key={row.label} className="flex items-center justify-between gap-2 text-[11px]">
                                <span className="text-gray-500">{row.label}</span>
                                <div className="flex items-center gap-1">
                                  {row.filterQ ? (
                                    <button
                                      type="button"
                                      onClick={() => setFilters({ ...filters, q: row.filterQ })}
                                      className="font-mono text-gray-300 hover:text-[#00ccff] hover:underline underline-offset-2"
                                      title={`Filter queue by ${row.label}`}
                                    >
                                      {row.value}
                                    </button>
                                  ) : (
                                    <span className={`text-gray-300 ${row.mono ? 'font-mono text-[10px]' : 'font-mono'}`}>
                                      {row.value}
                                    </span>
                                  )}
                                  {row.copy && (
                                    <button
                                      onClick={() => copyToClipboard(row.copy!, row.label)}
                                      className="text-gray-600 hover:text-[#00ccff] p-0.5 transition-colors"
                                      title={`Copy ${row.label}`}
                                    >
                                      <Copy className="w-3 h-3" />
                                    </button>
                                  )}
                                  {/* External enrichment links — skip for
                                      RFC1918 / loopback. We render them as
                                      one-letter chips so they fit inline
                                      next to the IP without crowding. */}
                                  {isIp && (
                                    <div className="flex items-center gap-0.5 ml-1" title={priv ? 'Internal IP — external enrichment unavailable' : ''}>
                                      {[
                                        { label: 'A', name: 'AbuseIPDB', href: `https://www.abuseipdb.com/check/${ipForLinks}` },
                                        { label: 'V', name: 'VirusTotal', href: `https://www.virustotal.com/gui/ip-address/${ipForLinks}` },
                                        { label: 'S', name: 'Shodan',   href: `https://www.shodan.io/host/${ipForLinks}` },
                                      ].map((b) => priv ? (
                                        <span
                                          key={b.label}
                                          className="inline-block w-4 h-4 rounded text-center font-mono text-[9px] leading-4 text-gray-700 bg-[#1a2540]/30 cursor-not-allowed"
                                          title={`${b.name} — internal IP, lookup unavailable`}
                                        >
                                          {b.label}
                                        </span>
                                      ) : (
                                        <a
                                          key={b.label}
                                          href={b.href}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="inline-block w-4 h-4 rounded text-center font-mono text-[9px] leading-4 text-[#00ccff] bg-[#00ccff]/10 hover:bg-[#00ccff]/25 transition-colors"
                                          title={`Look up on ${b.name}`}
                                        >
                                          {b.label}
                                        </a>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </div>
                              );
                            });
                          })()}
                        </div>

                        {/* Per-stage probabilities */}
                        {(typeof selected.stage2_p === 'number' || typeof selected.stage3_p === 'number') && (
                          <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540] space-y-2">
                            <div className="text-[10px] uppercase tracking-wide text-gray-500">Per-stage probabilities</div>
                            {typeof selected.stage1_p === 'number' && (
                              <div className="flex items-center justify-between text-[11px]">
                                <span className="text-gray-500">Stage 1 (routing only)</span>
                                <span className="font-mono text-gray-400">{(selected.stage1_p * 100).toFixed(3)}%</span>
                              </div>
                            )}
                            {typeof selected.stage2_p === 'number' && (
                              <div className="flex items-center justify-between text-[11px]">
                                <span className="text-gray-500">Stage 2 (family)</span>
                                <span className="font-mono text-[#00ccff]">{(selected.stage2_p * 100).toFixed(1)}%</span>
                              </div>
                            )}
                            {typeof selected.stage3_p === 'number' && (
                              <div className="flex items-center justify-between text-[11px]">
                                <span className="text-gray-500">Stage 3 (leaf)</span>
                                <span className="font-mono text-[#00ff88]">{(selected.stage3_p * 100).toFixed(1)}%</span>
                              </div>
                            )}
                            {selectedDetail?.stage2_probs || selectedDetail?.stage3_probs ? (
                              <>
                                <StageProbBars
                                  probs={selectedDetail.stage2_probs ?? null}
                                  label="Stage-2 family vector"
                                  highlight={selected.family ?? null}
                                />
                                <StageProbBars
                                  probs={selectedDetail.stage3_probs ?? null}
                                  label="Stage-3 leaf vector"
                                  highlight={selected.attack_type ?? null}
                                />
                              </>
                            ) : (
                              <div className="text-[10px] text-gray-500 italic">
                                {detailLoading ? 'Loading probability vectors…' : 'Probability vectors not available'}
                              </div>
                            )}
                          </div>
                        )}

                        {/* MITRE ATT&CK mapping — technique links gated by
                            stage3_p >= 0.80. Below that we still show tactic
                            chips so the section is self-documenting. */}
                        {selectedDetail?.mitre && selected.prediction === 'Malicious' && (() => {
                          const mitre = selectedDetail.mitre!;
                          const s3 = typeof selected.stage3_p === 'number' ? selected.stage3_p : 0;
                          const linksUnlocked = s3 >= 0.8;
                          const isUnmapped = (mitre as { unmapped?: boolean }).unmapped === true;
                          const tactics = mitre.tactics ?? [];
                          const techniques = mitre.techniques ?? [];
                          if (isUnmapped) {
                            return (
                              <div className="p-3 rounded-lg bg-[#ffaa00]/5 border border-[#ffaa00]/20 space-y-1">
                                <div className="text-[10px] uppercase tracking-wide text-gray-500 flex items-center gap-1.5">
                                  <Globe className="w-3 h-3 text-[#ffaa00]" />
                                  MITRE ATT&amp;CK
                                </div>
                                <div className="text-[11px] text-gray-300">
                                  No MITRE mapping for <span className="font-mono text-[#ffaa00]">{(mitre as { attack_type?: string }).attack_type ?? selected.attack_type}</span>.
                                </div>
                                <div className="text-[10px] text-gray-500 italic">
                                  Update app/data/mitre_mapping.json to add this leaf.
                                </div>
                              </div>
                            );
                          }
                          return (
                            <div className="p-3 rounded-lg bg-[#cc66ff]/5 border border-[#cc66ff]/20 space-y-2">
                              <div className="flex items-center justify-between gap-2">
                                <div className="text-[10px] uppercase tracking-wide text-gray-500 flex items-center gap-1.5">
                                  <Globe className="w-3 h-3 text-[#cc66ff]" />
                                  MITRE ATT&amp;CK
                                </div>
                                {mitre.confidence_band && (
                                  <Badge variant="outline" className="text-[10px] py-0 capitalize border-[#cc66ff]/40 text-[#cc66ff]">
                                    {mitre.confidence_band.replace('_', ' ')}
                                  </Badge>
                                )}
                              </div>
                              {tactics.length > 0 && (
                                <div className="flex flex-wrap gap-1.5">
                                  {tactics.map((t) => (
                                    <Badge
                                      key={t.id}
                                      variant="outline"
                                      className="text-[10px] py-0 border-[#cc66ff]/40 text-[#cc66ff] font-mono"
                                      title={t.id}
                                    >
                                      {t.name}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                              {linksUnlocked ? (
                                techniques.length > 0 ? (
                                  <div className="space-y-1">
                                    {techniques.map((tech) => (
                                      <a
                                        key={tech.id}
                                        href={tech.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center gap-2 text-[11px] text-gray-300 hover:text-[#cc66ff] hover:bg-[#cc66ff]/10 rounded px-1.5 py-1 transition-colors group"
                                      >
                                        <span className="font-mono text-[#cc66ff]/80 group-hover:text-[#cc66ff]">{tech.id}</span>
                                        <span className="text-gray-500">·</span>
                                        <span className="truncate">{tech.name}</span>
                                        <ExternalLink className="w-3 h-3 ml-auto text-gray-600 group-hover:text-[#cc66ff] shrink-0" />
                                      </a>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-[10px] text-gray-500 italic">
                                    {detailLoading ? 'Loading technique list…' : 'No techniques listed for this tactic.'}
                                  </div>
                                )
                              ) : (
                                <div className="text-[10px] text-gray-500 italic border-l-2 border-[#cc66ff]/30 pl-2">
                                  Technique links withheld — Stage 3 confidence {(s3 * 100).toFixed(1)}% (threshold 80%).
                                </div>
                              )}
                            </div>
                          );
                        })()}

                        {/* Snort signature */}
                        {selected.snort_msg && (
                          <div className="p-3 rounded-lg bg-[#ffaa00]/5 border border-[#ffaa00]/20 space-y-1">
                            <div className="flex items-center justify-between gap-2">
                              <div className="text-[10px] uppercase tracking-wide text-gray-500 flex items-center gap-1.5">
                                <AlertTriangle className="w-3 h-3 text-[#ffaa00]" />
                                Snort signature
                              </div>
                              {selected.snort_sid ? (
                                <button
                                  onClick={() => copyToClipboard(String(selected.snort_sid), 'Snort SID')}
                                  className="text-gray-600 hover:text-[#00ccff] p-0.5"
                                  title="Copy SID"
                                >
                                  <Copy className="w-3 h-3" />
                                </button>
                              ) : null}
                            </div>
                            <div className="text-[11px] font-mono text-gray-300">{selected.snort_msg}</div>
                            <div className="text-[10px] text-gray-500 font-mono">
                              SID{' '}
                              {selected.snort_sid ? (
                                <button
                                  type="button"
                                  onClick={() => setFilters({ ...filters, q: String(selected.snort_sid) })}
                                  className="hover:text-[#00ccff] hover:underline underline-offset-2"
                                  title="Filter queue by this Snort SID"
                                >
                                  {selected.snort_sid}
                                </button>
                              ) : (
                                <span>{selected.snort_sid}</span>
                              )}{' '}
                              · {selected.snort_classtype} · pri {selected.snort_priority}
                            </div>
                          </div>
                        )}

                        {/* Related alerts — same flow key, last 10 rows. */}
                        {(related.length > 0 || relatedLoading) && (
                          <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540] space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="text-[10px] uppercase tracking-wide text-gray-500">
                                Related alerts (same flow key)
                              </div>
                              <button
                                type="button"
                                onClick={() =>
                                  setFilters({
                                    ...filters,
                                    q: buildFlowKey(selected),
                                  })
                                }
                                className="text-[10px] text-[#00ccff] hover:underline underline-offset-2"
                              >
                                Jump to filter
                              </button>
                            </div>
                            {relatedLoading && related.length === 0 ? (
                              <div className="text-[10px] text-gray-500 italic">Loading…</div>
                            ) : (
                              <div className="space-y-1">
                                {related.map((r) => (
                                  <button
                                    key={r.id}
                                    type="button"
                                    onClick={() => setSelected(r)}
                                    className="w-full text-left flex items-center gap-2 text-[10px] font-mono px-1.5 py-1 rounded hover:bg-[#1a2540]/60 transition-colors"
                                    title={r.attack_type ?? r.prediction}
                                  >
                                    <span className="text-gray-500">
                                      {new Date(r.timestamp).toLocaleTimeString()}
                                    </span>
                                    <VerdictBadge source={r.source} size="text-[9px] py-0" />
                                    <span className="text-gray-300 truncate flex-1">
                                      {r.attack_type ?? r.prediction}
                                    </span>
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Suppression — server-side rules that DROP matched
                            future flows. Less granular than ack (which only
                            re-labels a single row). The shape lives in
                            app/core/suppression.py. */}
                        <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540] space-y-2">
                          <div className="text-[10px] uppercase tracking-wide text-gray-500">
                            Suppress future flows
                          </div>
                          <div className="text-[10px] text-gray-600 italic mb-1">
                            Drops matched flows before they hit the queue.
                          </div>
                          <div className="grid grid-cols-2 gap-1">
                            {selected.snort_sid ? (
                              <button
                                type="button"
                                onClick={() => handleSuppress('sid', String(selected.snort_sid), `SID ${selected.snort_sid}`, 1)}
                                className="text-[10px] px-2 py-1 rounded border border-[#1a2540] text-gray-300 hover:bg-[#1a2540] text-left"
                              >
                                SID {selected.snort_sid} · 1h
                              </button>
                            ) : (
                              <span className="text-[10px] px-2 py-1 rounded border border-[#1a2540] text-gray-700 italic text-left">
                                No SID
                              </span>
                            )}
                            <button
                              type="button"
                              onClick={() => handleSuppress('src_ip', selected.sourceIp, selected.sourceIp, 1)}
                              className="text-[10px] px-2 py-1 rounded border border-[#1a2540] text-gray-300 hover:bg-[#1a2540] text-left font-mono truncate"
                              title={`Suppress source IP ${selected.sourceIp} for 1h`}
                            >
                              {selected.sourceIp} · 1h
                            </button>
                            <button
                              type="button"
                              onClick={() => handleSuppress('src_ip', selected.sourceIp, selected.sourceIp)}
                              className="text-[10px] px-2 py-1 rounded border border-[#1a2540] text-gray-300 hover:bg-[#1a2540] text-left font-mono truncate"
                              title={`Suppress source IP ${selected.sourceIp} indefinitely`}
                            >
                              {selected.sourceIp} · ∞
                            </button>
                            <button
                              type="button"
                              onClick={() => handleSuppress('flow_key', buildFlowKey(selected), 'flow key', 1)}
                              className="text-[10px] px-2 py-1 rounded border border-[#1a2540] text-gray-300 hover:bg-[#1a2540] text-left"
                            >
                              Flow key · 1h
                            </button>
                          </div>
                        </div>

                        {/* Ack workflow */}
                        <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540] space-y-2">
                          <div className="text-[10px] uppercase tracking-wide text-gray-500">Acknowledgement</div>
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="text-gray-500">Current state</span>
                            <Badge variant="outline" className="text-[10px] py-0 capitalize">
                              {selected.ack_state ?? 'new'}
                            </Badge>
                          </div>
                          {selected.ack_at && (
                            <div className="flex items-center justify-between text-[10px]">
                              <span className="text-gray-500">Acked at</span>
                              <span className="font-mono text-gray-400">
                                {new Date(selected.ack_at).toLocaleString()}
                              </span>
                            </div>
                          )}
                          {selected.ack_note && (
                            <div className="text-[10px] text-gray-400 italic border-l-2 border-[#1a2540] pl-2">
                              {selected.ack_note}
                            </div>
                          )}
                          <textarea
                            placeholder="Optional note for this acknowledgement…"
                            value={note}
                            onChange={(e) => setNote(e.target.value)}
                            className="w-full bg-[#1a2540]/40 border border-[#253352] rounded p-2 text-[11px] text-gray-200 placeholder-gray-600 focus:outline-none focus:border-[#00ccff]/60"
                            rows={2}
                          />
                          <div className="grid grid-cols-3 gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busyIds.has(selected.id)}
                              className="border-[#00ccff]/40 text-[#00ccff] hover:bg-[#00ccff]/10 text-[11px] h-8"
                              onClick={() => handleAck(selected, 'reviewed')}
                            >
                              <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                              Review
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busyIds.has(selected.id)}
                              className="border-[#ffaa00]/40 text-[#ffaa00] hover:bg-[#ffaa00]/10 text-[11px] h-8"
                              onClick={() => handleAck(selected, 'escalated')}
                            >
                              <Flag className="w-3.5 h-3.5 mr-1" />
                              Escalate
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busyIds.has(selected.id)}
                              className="border-gray-600 text-gray-400 hover:bg-gray-600/10 text-[11px] h-8"
                              onClick={() => handleAck(selected, 'dismissed')}
                            >
                              <XCircle className="w-3.5 h-3.5 mr-1" />
                              Dismiss
                            </Button>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            className="w-full border-[#00ff88]/40 text-[#00ff88] hover:bg-[#00ff88]/10 text-[11px] h-8 mt-1"
                            onClick={() => handleExport(selected)}
                          >
                            <Download className="w-3.5 h-3.5 mr-1" />
                            Export incident report
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                ) : (
                  <motion.div
                    key="empty"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                  >
                    <Card className="bg-[#0f1825]/40 border-[#1a2540]/60 backdrop-blur">
                      <CardContent className="p-8 text-center text-sm text-gray-500">
                        <Inbox className="w-10 h-10 mx-auto mb-2 text-gray-600" />
                        Select an alert from the queue to view details and take action.
                      </CardContent>
                    </Card>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </motion.div>
      </div>
      <ShortcutsCheatsheet open={cheatsheetOpen} onClose={() => setCheatsheetOpen(false)} shortcuts={shortcuts} />
    </div>
  );
}
