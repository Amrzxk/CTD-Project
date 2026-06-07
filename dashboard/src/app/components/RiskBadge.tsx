import { Badge } from './ui/badge';

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'None';

// Severity scale on the reserved sev-* tokens. Critical is a solid fill (loud,
// rare); High/Medium/Low are soft chips so dense tables stay calm.
const RISK_CLASS: Record<RiskLevel, string> = {
  Critical: 'bg-sev-high text-white border-transparent',
  High: 'bg-sev-high/10 text-sev-high border-sev-high/30',
  Medium: 'bg-sev-med/10 text-sev-med border-sev-med/30',
  Low: 'bg-sev-low/10 text-sev-low border-sev-low/30',
  None: 'bg-panel-raised text-neutral border-line-strong',
};

interface Props {
  risk: RiskLevel;
  /** Optional prefix shown before the level, e.g. "Risk: High". */
  prefix?: string;
  /** Tailwind text size override (e.g. "text-[10px] py-0"). */
  size?: string;
}

export function RiskBadge({ risk, prefix, size = '' }: Props) {
  const safeRisk: RiskLevel = risk && RISK_CLASS[risk] ? risk : 'None';
  return (
    <Badge variant="outline" className={`${size} ${RISK_CLASS[safeRisk]}`}>
      {prefix ? `${prefix}: ${safeRisk}` : safeRisk}
    </Badge>
  );
}

/**
 * Map an ML prediction's severity onto the display risk level.
 * Severity 'High' → 'Critical' (most-urgent display), 'Medium' → 'High',
 * 'Low' → 'Medium'. Used by the live dashboard to distinguish raw model
 * confidence from the SOC-facing escalation tier.
 */
export function severityToRisk(severity: string | null | undefined): RiskLevel {
  if (severity === 'High') return 'Critical';
  if (severity === 'Medium') return 'High';
  if (severity === 'Low') return 'Medium';
  return 'None';
}
