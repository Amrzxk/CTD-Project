import { Badge } from './ui/badge';
import { TONE, verdictTone } from './ui/primitives';
import type { ThreatSource } from '../types/threat';

/**
 * Visual styling + short labels for the four hybrid-IDS verdict cells.
 * Colour comes from the shared `verdictTone` map (confirmed=red, sig-only=amber,
 * ml-only=blue, benign=green) so verdict semantics live in exactly one place.
 * Shared by DashboardPage, UploadPage, AlertsPage.
 */
const LABEL: Record<string, string> = {
  confirmed: 'CONFIRMED',
  signature_only: 'SIG-ONLY',
  ml_only: 'ML-ONLY',
  benign: 'BENIGN',
};

function meta(source?: string | null): { label: string; cls: string } {
  const v = (source || '').toLowerCase();
  const t = TONE[verdictTone(v)];
  return { label: LABEL[v] ?? '—', cls: `${t.softBg} ${t.text} ${t.border}` };
}

export function sourceMeta(source?: string | null): { label: string; cls: string } {
  return meta(source);
}

interface Props {
  source?: ThreatSource | string | null;
  /** Tailwind sizing override, e.g. "text-[10px] py-0". */
  size?: string;
  /** Optional tooltip — typically the Snort msg when source != ml_only. */
  title?: string;
}

export function VerdictBadge({ source, size = '', title }: Props) {
  const m = meta(source ?? undefined);
  return (
    <Badge variant="outline" className={`${size} ${m.cls}`} title={title || ''}>
      {m.label}
    </Badge>
  );
}
