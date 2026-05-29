import { Badge } from './ui/badge';
import type { ThreatSource } from '../types/threat';

/**
 * Visual styling and short labels for the four hybrid-IDS verdict cells.
 * Shared by DashboardPage, UploadPage, AlertsPage so the verdict palette
 * stays consistent.
 */
const SOURCE_META: Record<ThreatSource, { label: string; cls: string }> = {
  confirmed: {
    label: 'CONFIRMED',
    cls: 'bg-[#ff3366]/20 text-[#ff3366] border-[#ff3366]/50',
  },
  signature_only: {
    label: 'SIG-ONLY',
    cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  },
  ml_only: {
    label: 'ML-ONLY',
    cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
  },
  benign: {
    label: 'BENIGN',
    cls: 'bg-gray-700/30 text-gray-400 border-gray-600/40',
  },
};

const UNKNOWN_META = { label: '-', cls: 'bg-gray-700/20 text-gray-500 border-gray-700/40' };

export function sourceMeta(source?: string | null): { label: string; cls: string } {
  const v = (source || '').toLowerCase() as ThreatSource;
  return SOURCE_META[v] ?? UNKNOWN_META;
}

interface Props {
  source?: ThreatSource | string | null;
  /** Tailwind sizing override, e.g. "text-[10px] py-0". */
  size?: string;
  /** Optional tooltip — typically the Snort msg when source != ml_only. */
  title?: string;
}

export function VerdictBadge({ source, size = '', title }: Props) {
  const meta = sourceMeta(source ?? undefined);
  return (
    <Badge variant="outline" className={`${size} ${meta.cls}`} title={title || ''}>
      {meta.label}
    </Badge>
  );
}
