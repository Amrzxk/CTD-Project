import { useNavigate } from 'react-router';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { ShieldAlert } from 'lucide-react';
import type { VerdictBreakdownEntry, ThreatSource } from '../types/threat';

/** Render a 2×2 confusion-style matrix of ML × Snort verdicts. Cells are
 *  clickable and deep-link into the Alerts queue pre-filtered by the cell's
 *  source. Counts come straight from `analytics.verdictBreakdown` so no
 *  extra backend call is needed.
 *
 *  Layout: rows = ML (fired / clear), columns = Snort (fired / clear).
 *  Top-left = confirmed (both fired). Top-right = ml_only. Bottom-left =
 *  signature_only. Bottom-right = benign.
 */
export function DetectorAgreementMatrix({
  verdictBreakdown,
}: {
  verdictBreakdown: VerdictBreakdownEntry[] | undefined;
}) {
  const navigate = useNavigate();
  const get = (src: ThreatSource): VerdictBreakdownEntry | undefined =>
    verdictBreakdown?.find((v) => v.source === src);
  const confirmed     = get('confirmed');
  const ml_only       = get('ml_only');
  const signature     = get('signature_only');
  const benign        = get('benign');
  const total = (verdictBreakdown ?? []).reduce((s, v) => s + v.count, 0);

  const Cell = ({
    label,
    entry,
    src,
    intent,
    description,
  }: {
    label: string;
    entry?: VerdictBreakdownEntry;
    src?: ThreatSource;
    intent: 'bad' | 'warn' | 'ok' | 'neutral';
    description: string;
  }) => {
    const count = entry?.count ?? 0;
    const color = entry?.color ?? (intent === 'bad' ? '#ff3366'
      : intent === 'warn' ? '#ffaa00'
      : intent === 'ok' ? '#00ff88'
      : '#aaaaaa');
    const pct = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
    const clickable = !!src && count > 0;
    return (
      <button
        type="button"
        disabled={!clickable}
        onClick={() => clickable && navigate(`/alerts?source=${src}`)}
        className={`relative flex flex-col items-start gap-1 p-4 rounded-lg border transition-all text-left ${
          clickable ? 'hover:scale-[1.02] hover:shadow-lg cursor-pointer' : 'opacity-70 cursor-default'
        }`}
        style={{
          backgroundColor: `${color}10`,
          borderColor: `${color}55`,
        }}
      >
        <div className="text-[10px] uppercase tracking-wide" style={{ color }}>
          {label}
        </div>
        <div className="text-2xl font-bold text-white">
          {count.toLocaleString()}
        </div>
        <div className="text-[10px] text-gray-400 font-mono">{pct}% of flows</div>
        <div className="text-[10px] text-gray-500 mt-1">{description}</div>
      </button>
    );
  };

  return (
    <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
      <CardHeader>
        <CardTitle className="text-white flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-[#00ccff]" />
          Detector Agreement
        </CardTitle>
        <p className="text-xs text-gray-500 mt-1">
          Rows = ML model · Columns = Snort signatures. Click a cell to drill into Alerts.
        </p>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-[auto_1fr_1fr] gap-2 items-center text-[10px] text-gray-500">
          <div />
          <div className="text-center pb-1 uppercase tracking-wide">Snort fired</div>
          <div className="text-center pb-1 uppercase tracking-wide">Snort clear</div>

          <div className="text-right pr-2 uppercase tracking-wide">ML fired</div>
          <Cell
            label="Confirmed"
            entry={confirmed}
            src="confirmed"
            intent="bad"
            description="Highest-confidence detection — both engines agreed."
          />
          <Cell
            label="ML-only"
            entry={ml_only}
            src="ml_only"
            intent="warn"
            description="Suspicious; ml_only precision ~0.48 — most are FPs."
          />

          <div className="text-right pr-2 uppercase tracking-wide">ML clear</div>
          <Cell
            label="Signature-only"
            entry={signature}
            src="signature_only"
            intent="warn"
            description="Snort caught it but ML didn't — known-bad pattern."
          />
          <Cell
            label="Benign"
            entry={benign}
            src="benign"
            intent="ok"
            description="Neither engine flagged — likely normal traffic."
          />
        </div>
      </CardContent>
    </Card>
  );
}
