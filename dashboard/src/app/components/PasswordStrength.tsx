import { Check, X } from 'lucide-react';
import { cn } from './ui/utils';
import {
  scorePassword,
  PASSWORD_REQUIREMENTS,
  type PasswordStrength as Strength,
} from '../lib/password';

// Four-segment meter. Each strength fills more bars in a hotter colour.
const METER: Record<Strength, { bars: number; label: string; color: string }> = {
  empty: { bars: 0, label: '', color: 'var(--color-line-strong)' },
  weak: { bars: 1, label: 'Weak', color: 'var(--color-sev-high)' },
  fair: { bars: 2, label: 'Fair', color: 'var(--color-sev-med)' },
  good: { bars: 3, label: 'Good', color: 'var(--color-brand)' },
  strong: { bars: 4, label: 'Strong', color: 'var(--color-ok)' },
};

/** Live password strength meter + requirement checklist. Mirrors the server
 *  policy so the analyst sees exactly what's missing before submitting. */
export function PasswordStrength({ password }: { password: string }) {
  const { checks, strength } = scorePassword(password);
  const meter = METER[strength];

  return (
    <div className="mt-2 space-y-2">
      {/* Meter */}
      <div className="flex items-center gap-2">
        <div className="flex flex-1 gap-1">
          {[0, 1, 2, 3].map((i) => (
            <span
              key={i}
              className="h-1 flex-1 rounded-full transition-colors duration-200"
              style={{
                backgroundColor: i < meter.bars ? meter.color : 'var(--color-line)',
              }}
            />
          ))}
        </div>
        {meter.label && (
          <span
            className="eyebrow shrink-0 text-[0.6rem]"
            style={{ color: meter.color }}
          >
            {meter.label}
          </span>
        )}
      </div>

      {/* Requirement checklist */}
      <ul className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
        {PASSWORD_REQUIREMENTS.map((req) => {
          const ok = checks[req.key];
          return (
            <li
              key={req.key}
              className={cn(
                'flex items-center gap-1.5 text-xs transition-colors',
                ok ? 'text-ok' : 'text-faint',
              )}
            >
              {ok ? (
                <Check className="size-3.5 shrink-0" />
              ) : (
                <X className="size-3.5 shrink-0" />
              )}
              <span>{req.label}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
