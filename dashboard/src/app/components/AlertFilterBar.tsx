import { useEffect, useRef, useState } from 'react';
import { Search, X, SlidersHorizontal, ArrowDownUp } from 'lucide-react';

/** Filter state shared between the AlertFilterBar UI and the parent page.
 *  Everything is optional so the parent can serialize/deserialize from
 *  localStorage or URL params without dealing with absent-but-valid cases. */
export interface AlertFilters {
  q?: string;
  severity?: 'high' | 'medium' | 'low';
  src_cidr?: string;
  dst_cidr?: string;
  port_min?: number;
  port_max?: number;
  sort?: 'time' | 'severity' | 'family' | 'source';
  dir?: 'asc' | 'desc';
}

interface Props {
  value: AlertFilters;
  onChange: (next: AlertFilters) => void;
  /** Exposed so the parent's keyboard-shortcut hook can focus the search box. */
  searchInputRef?: React.RefObject<HTMLInputElement | null>;
}

const SEVERITY_OPTS: { label: string; key: AlertFilters['severity']; cls: string }[] = [
  { label: 'High',   key: 'high',   cls: 'text-sev-high border-sev-high/40' },
  { label: 'Medium', key: 'medium', cls: 'text-sev-med border-sev-med/40' },
  { label: 'Low',    key: 'low',    cls: 'text-sev-low border-sev-low/40' },
];

const SORT_OPTS: { label: string; sort: AlertFilters['sort']; dir: AlertFilters['dir'] }[] = [
  { label: 'Newest first',      sort: 'time',     dir: 'desc' },
  { label: 'Oldest first',      sort: 'time',     dir: 'asc' },
  { label: 'Severity ↓',        sort: 'severity', dir: 'desc' },
  { label: 'Severity ↑',        sort: 'severity', dir: 'asc' },
  { label: 'Family A→Z',        sort: 'family',   dir: 'asc' },
  { label: 'Family Z→A',        sort: 'family',   dir: 'desc' },
  { label: 'Verdict A→Z',       sort: 'source',   dir: 'asc' },
];

export function AlertFilterBar({ value, onChange, searchInputRef }: Props) {
  // Debounced q so typing doesn't fire a request per keystroke. 250ms matches
  // the inter-keystroke gap for a comfortably-typing analyst.
  const [qLocal, setQLocal] = useState<string>(value.q ?? '');
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Sync local q back when the parent resets/sets it (e.g. drilldown nav).
  useEffect(() => {
    setQLocal(value.q ?? '');
  }, [value.q]);

  const flushQ = (next: string) => {
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    debounceTimer.current = setTimeout(() => {
      onChange({ ...value, q: next || undefined });
    }, 250);
  };

  const [expanded, setExpanded] = useState<boolean>(
    !!(value.src_cidr || value.dst_cidr || value.port_min || value.port_max),
  );

  const hasAny =
    !!value.q ||
    !!value.severity ||
    !!value.src_cidr ||
    !!value.dst_cidr ||
    value.port_min !== undefined ||
    value.port_max !== undefined ||
    (value.sort && value.sort !== 'time') ||
    (value.dir && value.dir !== 'desc');

  const clearAll = () => {
    setQLocal('');
    onChange({});
  };

  const sortIdx = SORT_OPTS.findIndex(
    (o) => o.sort === (value.sort ?? 'time') && o.dir === (value.dir ?? 'desc'),
  );

  return (
    <div className="mb-4 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input
            ref={searchInputRef}
            type="text"
            value={qLocal}
            onChange={(e) => {
              setQLocal(e.target.value);
              flushQ(e.target.value);
            }}
            placeholder="Search IP, port, SID, family, leaf, flow key…"
            className="w-full bg-panel/80 border border-line rounded-md pl-8 pr-7 py-1.5 text-xs text-foreground placeholder-gray-600 focus:outline-none focus:border-sev-low/60 font-mono"
            spellCheck={false}
          />
          {qLocal && (
            <button
              type="button"
              onClick={() => {
                setQLocal('');
                onChange({ ...value, q: undefined });
              }}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              title="Clear search"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity pills */}
        <div className="flex gap-1">
          {SEVERITY_OPTS.map((s) => {
            const active = value.severity === s.key;
            return (
              <button
                key={s.key}
                type="button"
                onClick={() => onChange({ ...value, severity: active ? undefined : s.key })}
                className={`px-2 py-1 rounded border text-[11px] uppercase tracking-wide font-semibold transition-colors ${
                  active ? `${s.cls} bg-panel/80` : 'border-line text-muted-foreground hover:text-foreground'
                }`}
              >
                {s.label}
              </button>
            );
          })}
        </div>

        {/* Sort */}
        <label className="flex items-center gap-1 text-[11px] text-muted-foreground">
          <ArrowDownUp className="w-3 h-3" />
          <select
            value={sortIdx >= 0 ? sortIdx : 0}
            onChange={(e) => {
              const opt = SORT_OPTS[Number(e.target.value)];
              onChange({ ...value, sort: opt.sort, dir: opt.dir });
            }}
            className="bg-panel/80 border border-line rounded-md py-1 px-1.5 text-[11px] text-foreground focus:outline-none focus:border-sev-low/60"
          >
            {SORT_OPTS.map((o, i) => (
              <option key={i} value={i}>
                {o.label}
              </option>
            ))}
          </select>
        </label>

        {/* Expand / advanced */}
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className={`px-2 py-1 rounded border text-[11px] inline-flex items-center gap-1 ${
            expanded
              ? 'bg-line/60 border-line text-foreground'
              : 'border-line text-muted-foreground hover:text-foreground'
          }`}
          title="Advanced filters"
        >
          <SlidersHorizontal className="w-3 h-3" />
          Advanced
        </button>

        {hasAny && (
          <button
            type="button"
            onClick={clearAll}
            className="px-2 py-1 rounded text-[11px] text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
            title="Clear all filters"
          >
            <X className="w-3 h-3" />
            Clear
          </button>
        )}
      </div>

      {expanded && (
        <div className="flex items-center gap-2 flex-wrap text-[11px] text-muted-foreground pl-1">
          <span className="text-[10px] uppercase tracking-wide text-faint">CIDR</span>
          <input
            type="text"
            placeholder="src e.g. 10.0.0.0/8"
            value={value.src_cidr ?? ''}
            onChange={(e) =>
              onChange({ ...value, src_cidr: e.target.value.trim() || undefined })
            }
            className="bg-panel/80 border border-line rounded px-2 py-1 text-[11px] font-mono text-foreground focus:outline-none focus:border-sev-low/60 w-44"
            spellCheck={false}
          />
          <input
            type="text"
            placeholder="dst e.g. 192.168.10.0/24"
            value={value.dst_cidr ?? ''}
            onChange={(e) =>
              onChange({ ...value, dst_cidr: e.target.value.trim() || undefined })
            }
            className="bg-panel/80 border border-line rounded px-2 py-1 text-[11px] font-mono text-foreground focus:outline-none focus:border-sev-low/60 w-52"
            spellCheck={false}
          />
          <span className="text-[10px] uppercase tracking-wide text-faint ml-2">Dst port</span>
          <input
            type="number"
            min={0}
            max={65535}
            placeholder="min"
            value={value.port_min ?? ''}
            onChange={(e) => {
              const n = e.target.value === '' ? undefined : Number(e.target.value);
              onChange({ ...value, port_min: Number.isFinite(n as number) ? (n as number) : undefined });
            }}
            className="bg-panel/80 border border-line rounded px-2 py-1 text-[11px] font-mono text-foreground focus:outline-none focus:border-sev-low/60 w-20"
          />
          <span className="text-faint">–</span>
          <input
            type="number"
            min={0}
            max={65535}
            placeholder="max"
            value={value.port_max ?? ''}
            onChange={(e) => {
              const n = e.target.value === '' ? undefined : Number(e.target.value);
              onChange({ ...value, port_max: Number.isFinite(n as number) ? (n as number) : undefined });
            }}
            className="bg-panel/80 border border-line rounded px-2 py-1 text-[11px] font-mono text-foreground focus:outline-none focus:border-sev-low/60 w-20"
          />
        </div>
      )}
    </div>
  );
}

/** localStorage helpers — keep AlertsPage tidy. */
export function loadFilters(key: string): AlertFilters {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return {};
    return JSON.parse(raw) as AlertFilters;
  } catch {
    return {};
  }
}

export function saveFilters(key: string, value: AlertFilters): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* ignore quota errors */
  }
}
