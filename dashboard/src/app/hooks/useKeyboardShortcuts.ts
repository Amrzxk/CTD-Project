import { useEffect, useRef } from 'react';

/** One keyboard binding. `key` is matched against `event.key`
 *  (case-insensitive for letters). Modifier flags default to false —
 *  set to undefined to ignore the modifier entirely. `when` lets the
 *  caller disable a binding without removing it (e.g. modal is open).
 */
export interface Shortcut {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  meta?: boolean;
  handler: (e: KeyboardEvent) => void;
  /** Predicate evaluated at fire time; binding skipped when false. */
  when?: () => boolean;
  /** When true, fire even if focus is inside an <input>/<textarea>.
   *  Default false — typing in the search box shouldn't trigger `e`. */
  allowInInput?: boolean;
  /** Optional human label for the cheatsheet. Falls back to key. */
  label?: string;
  /** Optional grouping for the cheatsheet. */
  group?: string;
  /** Optional description for the cheatsheet. */
  description?: string;
}

const CHORD_WINDOW_MS = 500;

/** Install keyboard shortcuts on the document. Supports `g g` style
 *  chords via two-letter `key`s (e.g. `key: 'gg'` fires when the user
 *  taps `g` twice within 500ms).
 *
 *  Returns nothing — purely side-effectful. Re-runs (and rebinds) when
 *  the `shortcuts` array reference changes, so callers should memoize
 *  the array or accept the re-bind cost (cheap — one document listener).
 */
export function useKeyboardShortcuts(shortcuts: Shortcut[]) {
  // Track last key + time for chord matching. Refs so re-binds don't
  // reset the in-progress chord.
  const lastKey = useRef<{ key: string; at: number } | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Always allow Escape, even in text inputs.
      const tag = (e.target as HTMLElement | null)?.tagName?.toLowerCase() ?? '';
      const inField = tag === 'input' || tag === 'textarea' || tag === 'select'
        || (e.target as HTMLElement | null)?.isContentEditable === true;

      // Try chord match first.
      const lower = e.key.toLowerCase();
      const now = Date.now();
      const prev = lastKey.current;
      if (prev && now - prev.at < CHORD_WINDOW_MS) {
        const chord = prev.key + lower;
        for (const s of shortcuts) {
          if (s.key.length === 2 && s.key.toLowerCase() === chord) {
            if (!s.allowInInput && inField && e.key !== 'Escape') continue;
            if (s.when && !s.when()) continue;
            if ((s.ctrl ?? false) !== e.ctrlKey) continue;
            if ((s.shift ?? false) !== e.shiftKey) continue;
            if ((s.alt ?? false) !== e.altKey) continue;
            if ((s.meta ?? false) !== e.metaKey) continue;
            e.preventDefault();
            lastKey.current = null;
            s.handler(e);
            return;
          }
        }
      }
      lastKey.current = { key: lower, at: now };

      // Single-key match.
      for (const s of shortcuts) {
        if (s.key.length === 2) continue; // chord only
        // Case-insensitive for letters; exact for special keys.
        const wantKey = s.key.length === 1 ? s.key.toLowerCase() : s.key;
        const gotKey = e.key.length === 1 ? e.key.toLowerCase() : e.key;
        if (wantKey !== gotKey) continue;
        if (!s.allowInInput && inField && e.key !== 'Escape') continue;
        if (s.when && !s.when()) continue;
        if ((s.ctrl ?? false) !== e.ctrlKey) continue;
        if ((s.shift ?? false) !== e.shiftKey) continue;
        if ((s.alt ?? false) !== e.altKey) continue;
        if ((s.meta ?? false) !== e.metaKey) continue;
        e.preventDefault();
        s.handler(e);
        return;
      }
    };

    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [shortcuts]);
}

/** Format a Shortcut as a compact label for the cheatsheet. */
export function formatShortcut(s: Shortcut): string {
  const parts: string[] = [];
  if (s.ctrl) parts.push('Ctrl');
  if (s.shift) parts.push('Shift');
  if (s.alt) parts.push('Alt');
  if (s.meta) parts.push('Meta');
  const k = s.key.length === 2
    ? `${s.key[0]} ${s.key[1]}`
    : s.key === ' '
    ? 'Space'
    : s.key;
  parts.push(k);
  return parts.join(' + ');
}
