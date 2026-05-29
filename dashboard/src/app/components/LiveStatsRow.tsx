import { useMemo } from 'react';
import type { LivePacket } from '../types/threat';

interface Props {
  packets: LivePacket[];
  totalReceived: number;
  rateEps: number;
}

interface VerdictCounts {
  confirmed: number;
  signature_only: number;
  ml_only: number;
  benign: number;
}

function tallyVerdicts(packets: LivePacket[]): VerdictCounts {
  const t: VerdictCounts = { confirmed: 0, signature_only: 0, ml_only: 0, benign: 0 };
  for (const p of packets) {
    switch (p.source) {
      case 'confirmed':
        t.confirmed++;
        break;
      case 'signature_only':
        t.signature_only++;
        break;
      case 'ml_only':
        t.ml_only++;
        break;
      case 'benign':
        t.benign++;
        break;
    }
  }
  return t;
}

/** Stat tiles row. Recomputed from the ring buffer only — no separate state. */
export function LiveStatsRow({ packets, totalReceived, rateEps }: Props) {
  const counts = useMemo(() => tallyVerdicts(packets), [packets]);

  const tiles = [
    {
      label: 'EPS',
      value: rateEps.toFixed(1),
      hint: 'events/sec',
      color: 'text-white',
    },
    {
      label: 'TOTAL',
      value: totalReceived.toLocaleString(),
      hint: 'session total',
      color: 'text-white',
    },
    {
      label: 'CONFIRMED',
      value: counts.confirmed.toLocaleString(),
      hint: 'ML + Snort agree',
      color: 'text-[#ff3366]',
    },
    {
      label: 'SIG-ONLY',
      value: counts.signature_only.toLocaleString(),
      hint: 'Snort only',
      color: 'text-orange-400',
    },
    {
      label: 'ML-ONLY',
      value: counts.ml_only.toLocaleString(),
      hint: 'ML only',
      color: 'text-yellow-400',
    },
    {
      label: 'BENIGN',
      value: counts.benign.toLocaleString(),
      hint: 'neither alert',
      color: 'text-gray-400',
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
      {tiles.map((t) => (
        <div
          key={t.label}
          className="p-3 rounded-lg border border-[#1a2540] bg-[#0f1825]/70 backdrop-blur"
        >
          <div className="text-[10px] uppercase tracking-wider text-gray-500">{t.label}</div>
          <div className={`text-xl font-bold font-mono ${t.color}`}>{t.value}</div>
          <div className="text-[10px] text-gray-600">{t.hint}</div>
        </div>
      ))}
    </div>
  );
}
