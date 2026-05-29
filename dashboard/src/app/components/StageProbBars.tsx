interface Props {
  /** Probability dict keyed by class name (e.g. {Probe: 0.99, DoS: 0.005, ...}). */
  probs?: Record<string, number> | null;
  /** Section label rendered above the bars. */
  label: string;
  /** Highlight the class with the top probability. */
  highlight?: string | null;
  /** Maximum rows to render — sorted by probability descending. */
  maxRows?: number;
}

function barColor(p: number): string {
  if (p >= 0.9) return 'bg-[#00ff88]';
  if (p >= 0.5) return 'bg-[#00ccff]';
  if (p >= 0.2) return 'bg-[#ffaa00]';
  return 'bg-[#1a2540]';
}

/**
 * Horizontal probability bars for a per-class probability dict.
 *
 * Used in the detail drawer to show the full Stage-2 family vector and
 * Stage-3 leaf vector so an analyst can see *why* a flow was routed to
 * a particular leaf (e.g. Stage 2 split 0.30 Probe / 0.24 BotnetInfiltration
 * / 0.22 BruteForce — meaning the routing decision was barely confident).
 */
export function StageProbBars({ probs, label, highlight, maxRows = 6 }: Props) {
  if (!probs || Object.keys(probs).length === 0) return null;

  const entries = Object.entries(probs)
    .filter(([, p]) => typeof p === 'number' && !Number.isNaN(p))
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxRows);

  return (
    <div className="space-y-1">
      <div className="text-[10px] text-gray-500 uppercase tracking-wide">{label}</div>
      <div className="space-y-1">
        {entries.map(([name, p]) => {
          const isTop = highlight ? name === highlight : false;
          const pct = Math.max(0, Math.min(1, p)) * 100;
          return (
            <div key={name} className="flex items-center gap-2">
              <span
                className={`text-[11px] font-mono shrink-0 w-32 truncate ${
                  isTop ? 'text-white font-bold' : 'text-gray-400'
                }`}
                title={name}
              >
                {name}
              </span>
              <div className="flex-1 h-1.5 bg-[#1a2540]/60 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${barColor(p)}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className="text-[10px] font-mono text-gray-500 shrink-0 w-12 text-right">
                {(p * 100).toFixed(1)}%
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
