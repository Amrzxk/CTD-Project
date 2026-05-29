import { Badge } from './ui/badge';

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'None';

const RISK_CLASS: Record<RiskLevel, string> = {
  Critical: 'bg-[#ff3366]/20 text-[#ff3366] border-[#ff3366]/50',
  High: 'bg-red-500/15 text-red-400 border-red-500/40',
  Medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
  Low: 'bg-[#00ccff]/15 text-[#00ccff] border-[#00ccff]/40',
  None: 'bg-gray-700/30 text-gray-400 border-gray-600/40',
};

interface Props {
  risk: RiskLevel;
  /** Optional prefix shown before the level, e.g. "Risk: High". */
  prefix?: string;
  /** Tailwind text size override (e.g. "text-[10px] py-0"). */
  size?: string;
}

export function RiskBadge({ risk, prefix, size = '' }: Props) {
  const safeRisk: RiskLevel = (risk && RISK_CLASS[risk]) ? risk : 'None';
  return (
    <Badge variant="outline" className={`${size} ${RISK_CLASS[safeRisk]}`}>
      {prefix ? `${prefix}: ${safeRisk}` : safeRisk}
    </Badge>
  );
}

/**
 * Map an ML prediction's severity onto the display risk level.
 * Severity 'High' → 'Critical' (most-urgent display), 'Medium' → 'High',
 * 'Low' → 'Medium'.  Used by the live dashboard to distinguish raw
 * model confidence from the SOC-facing escalation tier.
 */
export function severityToRisk(severity: string | null | undefined): RiskLevel {
  if (severity === 'High') return 'Critical';
  if (severity === 'Medium') return 'High';
  if (severity === 'Low') return 'Medium';
  return 'None';
}
