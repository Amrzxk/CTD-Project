import { Badge } from './ui/badge';

interface Props {
  /** Top Stage-2 family probability from the hierarchical model. */
  stage2_p?: number | null;
  size?: string;
}

/**
 * One-glance triage cue derived from Stage-2 family-classifier confidence.
 *
 * Stage 1's probability is calibration-shifted by the FPR<=1% threshold
 * (see Docs/ReportAI.md §6 and CLAUDE.md "Calibration caveat" note), so the
 * meaningful "does the model really believe this routing?" signal is the
 * family-level probability from Stage 2.  This pill collapses it to three
 * triage states an analyst can scan in under a second:
 *
 *   stage2_p >= 0.9   "Corroborated"
 *   0.7 <= s2p < 0.9  "Likely"
 *   stage2_p <  0.7   "Uncertain"
 *
 * Renders nothing if stage2_p is undefined (legacy single-model path).
 */
export function ConfidenceQuality({ stage2_p, size = 'text-[10px] py-0' }: Props) {
  if (stage2_p == null) return null;
  if (stage2_p >= 0.9) {
    return (
      <Badge variant="outline" className={`${size} bg-brand/15 text-brand border-brand/40`}>
        Corroborated
      </Badge>
    );
  }
  if (stage2_p >= 0.7) {
    return (
      <Badge variant="outline" className={`${size} bg-sev-low/10 text-sev-low border-sev-low/40`}>
        Likely
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className={`${size} bg-sev-med/10 text-sev-med border-sev-med/40`}>
      Uncertain
    </Badge>
  );
}
