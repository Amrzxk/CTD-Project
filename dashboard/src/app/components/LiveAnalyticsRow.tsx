import { useMemo } from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import type { LivePacket, ThreatSource } from '../types/threat';

interface Props {
  packets: LivePacket[];
}

const SOURCE_COLOR: Record<ThreatSource, string> = {
  confirmed: '#ff3366',
  signature_only: '#f97316',
  ml_only: '#eab308',
  benign: '#6b7280',
};

const SOURCE_LABEL: Record<ThreatSource, string> = {
  confirmed: 'Confirmed',
  signature_only: 'Sig-only',
  ml_only: 'ML-only',
  benign: 'Benign',
};

interface Bucket {
  key: string;
  count: number;
}

function topN<T extends Bucket>(arr: T[], n: number): T[] {
  return arr.slice().sort((a, b) => b.count - a.count).slice(0, n);
}

/** Rolling mini-analytics: verdict donut, family bar, top-5 src IPs, top-5 leaves.
 *  All four are pure projections of the ring-buffer — no separate state. */
export function LiveAnalyticsRow({ packets }: Props) {
  const { verdictData, familyData, topSrc, topLeaves } = useMemo(() => {
    const verdicts: Record<string, number> = {};
    const families: Record<string, number> = {};
    const srcs: Record<string, number> = {};
    const leaves: Record<string, number> = {};
    for (const p of packets) {
      if (p.source) verdicts[p.source] = (verdicts[p.source] ?? 0) + 1;
      if (p.family && p.family !== 'Signature') families[p.family] = (families[p.family] ?? 0) + 1;
      if (p.src_ip) srcs[p.src_ip] = (srcs[p.src_ip] ?? 0) + 1;
      const leaf = p.subtype || p.attack_type;
      if (leaf) leaves[leaf] = (leaves[leaf] ?? 0) + 1;
    }
    return {
      verdictData: Object.entries(verdicts).map(([k, v]) => ({
        key: k,
        count: v,
        color: SOURCE_COLOR[k as ThreatSource] || '#6b7280',
        label: SOURCE_LABEL[k as ThreatSource] || k,
      })),
      familyData: topN(
        Object.entries(families).map(([k, v]) => ({ key: k, count: v })),
        6,
      ),
      topSrc: topN(
        Object.entries(srcs).map(([k, v]) => ({ key: k, count: v })),
        5,
      ),
      topLeaves: topN(
        Object.entries(leaves).map(([k, v]) => ({ key: k, count: v })),
        5,
      ),
    };
  }, [packets]);

  const verdictTotal = verdictData.reduce((s, e) => s + e.count, 0);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
      {/* Verdict donut */}
      <div className="p-3 rounded-lg border border-[#1a2540] bg-[#0f1825]/70 backdrop-blur min-h-[160px]">
        <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Verdict mix</div>
        {verdictTotal === 0 ? (
          <EmptyHint label="No events yet" />
        ) : (
          <ResponsiveContainer width="100%" height={140}>
            <PieChart>
              <Pie
                data={verdictData}
                dataKey="count"
                nameKey="label"
                innerRadius={32}
                outerRadius={52}
                paddingAngle={2}
              >
                {verdictData.map((entry) => (
                  <Cell key={entry.key} fill={entry.color} stroke="#0f1825" />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: '#080c14',
                  border: '1px solid #1a2540',
                  fontSize: 11,
                }}
                formatter={(v: number, n: string) => [`${v}`, n]}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Family horizontal bars */}
      <div className="p-3 rounded-lg border border-[#1a2540] bg-[#0f1825]/70 backdrop-blur min-h-[160px]">
        <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Top families</div>
        {familyData.length === 0 ? (
          <EmptyHint label="Awaiting attacks" />
        ) : (
          <HorizontalBars rows={familyData} color="#ff3366" />
        )}
      </div>

      {/* Top src IPs */}
      <div className="p-3 rounded-lg border border-[#1a2540] bg-[#0f1825]/70 backdrop-blur min-h-[160px]">
        <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Top src IPs</div>
        {topSrc.length === 0 ? (
          <EmptyHint label="No traffic yet" />
        ) : (
          <HorizontalBars rows={topSrc} color="#00ccff" mono />
        )}
      </div>

      {/* Top leaves */}
      <div className="p-3 rounded-lg border border-[#1a2540] bg-[#0f1825]/70 backdrop-blur min-h-[160px]">
        <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Top attack leaves</div>
        {topLeaves.length === 0 ? (
          <EmptyHint label="No attacks yet" />
        ) : (
          <HorizontalBars rows={topLeaves} color="#00ff88" />
        )}
      </div>
    </div>
  );
}

function EmptyHint({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center h-[100px] text-gray-600 text-xs">
      {label}
    </div>
  );
}

interface BarsProps {
  rows: Bucket[];
  color: string;
  mono?: boolean;
}

function HorizontalBars({ rows, color, mono }: BarsProps) {
  const max = rows.reduce((m, r) => Math.max(m, r.count), 1);
  return (
    <div className="space-y-1.5 mt-1">
      {rows.map((r) => {
        const pct = (r.count / max) * 100;
        return (
          <div key={r.key} className="flex items-center gap-2">
            <span
              className={`text-[11px] shrink-0 w-28 truncate ${
                mono ? 'font-mono text-gray-300' : 'text-gray-400'
              }`}
              title={r.key}
            >
              {r.key}
            </span>
            <div className="flex-1 h-1.5 bg-[#1a2540]/60 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-300"
                style={{ width: `${pct}%`, backgroundColor: color }}
              />
            </div>
            <span className="text-[10px] font-mono text-gray-500 shrink-0 w-9 text-right">
              {r.count}
            </span>
          </div>
        );
      })}
    </div>
  );
}
