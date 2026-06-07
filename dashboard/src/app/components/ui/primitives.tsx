import * as React from 'react';
import { cn } from './utils';

/*
 * H-IDS shared primitives — the building blocks pages compose so the
 * "Operator Console" look stays consistent without re-deriving card markup
 * or re-deciding severity colours per page.
 *
 *   Panel           refined surface (replaces ad-hoc bg-[#0f1825] cards)
 *   SectionEyebrow  mono uppercase label above a section/panel title
 *   StatTile        KPI tile (eyebrow + big mono value + optional spine)
 *   SeveritySpine   left-border accent wrapper for rows/cards
 *   TONE / *Tone()  the ONE place severity↔colour mapping lives
 */

export type Tone = 'high' | 'med' | 'low' | 'ok' | 'brand' | 'neutral';

/** Literal class strings (Tailwind must see them statically). */
export const TONE: Record<
  Tone,
  { text: string; border: string; softBg: string; spine: string; dot: string }
> = {
  high: { text: 'text-sev-high', border: 'border-sev-high/40', softBg: 'bg-sev-high/10', spine: 'border-l-sev-high', dot: 'bg-sev-high' },
  med: { text: 'text-sev-med', border: 'border-sev-med/40', softBg: 'bg-sev-med/10', spine: 'border-l-sev-med', dot: 'bg-sev-med' },
  low: { text: 'text-sev-low', border: 'border-sev-low/40', softBg: 'bg-sev-low/10', spine: 'border-l-sev-low', dot: 'bg-sev-low' },
  ok: { text: 'text-ok', border: 'border-ok/40', softBg: 'bg-ok/10', spine: 'border-l-ok', dot: 'bg-ok' },
  brand: { text: 'text-brand-text', border: 'border-brand/40', softBg: 'bg-brand/10', spine: 'border-l-brand', dot: 'bg-brand' },
  neutral: { text: 'text-neutral', border: 'border-line-strong', softBg: 'bg-panel-raised', spine: 'border-l-line-strong', dot: 'bg-neutral' },
};

/** Map an ML severity ('High'|'Medium'|'Low') onto a tone. */
export function severityTone(severity?: string | null): Tone {
  const s = (severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'medium') return 'med';
  if (s === 'low') return 'low';
  return 'neutral';
}

/** Map a hybrid verdict onto a tone (confirmed=red, sig=amber, ml=blue, benign=green). */
export function verdictTone(verdict?: string | null): Tone {
  const v = (verdict || '').toLowerCase();
  if (v === 'confirmed') return 'high';
  if (v === 'signature_only') return 'med';
  if (v === 'ml_only') return 'low';
  if (v === 'benign') return 'ok';
  return 'neutral';
}

type IconType = React.ComponentType<{ className?: string }>;

/** Refined surface. `raised` uses the elevated panel colour. */
export function Panel({
  className,
  raised = false,
  ...props
}: React.ComponentProps<'div'> & { raised?: boolean }) {
  return (
    <div
      data-slot="panel"
      className={cn('rounded-lg border border-line', raised ? 'bg-panel-raised' : 'bg-panel', className)}
      {...props}
    />
  );
}

/** Mono uppercase eyebrow label, optionally with a leading icon. */
export function SectionEyebrow({
  icon: Icon,
  children,
  className,
}: {
  icon?: IconType;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('eyebrow flex items-center gap-1.5', className)}>
      {Icon ? <Icon className="size-3.5 opacity-80" /> : null}
      <span>{children}</span>
    </div>
  );
}

/** KPI tile: eyebrow label, big mono value, optional sub line + severity spine. */
export function StatTile({
  label,
  value,
  sub,
  icon: Icon,
  tone,
  accentValue = false,
  className,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon?: IconType;
  tone?: Tone;
  /** Tint the big number with the tone colour (use for severity counts). */
  accentValue?: boolean;
  className?: string;
}) {
  const t = tone ? TONE[tone] : null;
  return (
    <Panel
      className={cn(
        'relative overflow-hidden p-4 transition-colors duration-150 hover:border-line-strong',
        t ? cn('border-l-2', t.spine) : null,
        className,
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="eyebrow">{label}</span>
        {Icon ? <Icon className={cn('size-4 shrink-0', t ? t.text : 'text-faint')} /> : null}
      </div>
      <div
        className={cn(
          'mt-2 font-mono text-2xl font-semibold tabular-nums leading-none',
          accentValue && t ? t.text : 'text-foreground',
        )}
      >
        {value}
      </div>
      {sub ? <div className="mt-1.5 text-xs text-muted-foreground">{sub}</div> : null}
    </Panel>
  );
}

/** Left-border severity accent wrapper for list rows / cards. */
export function SeveritySpine({
  tone = 'neutral',
  className,
  children,
  ...props
}: React.ComponentProps<'div'> & { tone?: Tone }) {
  return (
    <div className={cn('border-l-2 pl-3', TONE[tone].spine, className)} {...props}>
      {children}
    </div>
  );
}
