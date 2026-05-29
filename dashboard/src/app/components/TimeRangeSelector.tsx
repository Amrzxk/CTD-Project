import type { AnalyticsRange } from '../types/threat';

const RANGES: { key: AnalyticsRange; label: string }[] = [
  { key: '1h',  label: '1h' },
  { key: '24h', label: '24h' },
  { key: '7d',  label: '7d' },
  { key: '30d', label: '30d' },
  { key: 'all', label: 'All' },
];

interface Props {
  value: AnalyticsRange;
  onChange: (next: AnalyticsRange) => void;
  /** Optional storage key — if provided, the selection is persisted to localStorage. */
  storageKey?: string;
}

export function TimeRangeSelector({ value, onChange, storageKey }: Props) {
  const set = (next: AnalyticsRange) => {
    if (storageKey && typeof window !== 'undefined') {
      window.localStorage.setItem(storageKey, next);
    }
    onChange(next);
  };
  return (
    <div className="inline-flex items-center rounded-md border border-[#1a2540] bg-[#0f1825]/70 overflow-hidden text-xs">
      {RANGES.map((r, i) => {
        const active = value === r.key;
        return (
          <button
            key={r.key}
            type="button"
            onClick={() => set(r.key)}
            className={`px-3 py-1.5 transition-colors ${
              active
                ? 'bg-[#00ccff]/15 text-[#00ccff]'
                : 'text-gray-400 hover:bg-[#1a2540]/60 hover:text-gray-200'
            } ${i > 0 ? 'border-l border-[#1a2540]' : ''}`}
          >
            {r.label}
          </button>
        );
      })}
    </div>
  );
}

/** Read the persisted range from localStorage. Defaults to 'all'. */
export function loadRange(storageKey: string): AnalyticsRange {
  if (typeof window === 'undefined') return 'all';
  const stored = window.localStorage.getItem(storageKey) as AnalyticsRange | null;
  if (stored && ['1h', '24h', '7d', '30d', 'all'].includes(stored)) return stored;
  return 'all';
}
