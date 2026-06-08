/**
 * Password utilities — strength scoring, strong generation, and an AWS-IAM
 * style credentials CSV. All dependency-free (Web Crypto + a Blob download).
 *
 * The strength policy mirrors the server (`app/auth/schemas.py`): ≥12 chars
 * plus at least one upper, lower, digit, and symbol. The UI gates submit on
 * `met`; the server is still the source of truth and rejects weak passwords.
 */

export const PASSWORD_MIN_LENGTH = 12;

export interface PasswordChecks {
  length: boolean;
  upper: boolean;
  lower: boolean;
  digit: boolean;
  symbol: boolean;
}

export type PasswordStrength = 'empty' | 'weak' | 'fair' | 'good' | 'strong';

export interface PasswordScore {
  checks: PasswordChecks;
  /** All policy requirements satisfied — submit is allowed. */
  met: boolean;
  strength: PasswordStrength;
}

/** The five requirement labels, in display order. Keyed to PasswordChecks. */
export const PASSWORD_REQUIREMENTS: { key: keyof PasswordChecks; label: string }[] = [
  { key: 'length', label: `At least ${PASSWORD_MIN_LENGTH} characters` },
  { key: 'upper', label: 'An uppercase letter' },
  { key: 'lower', label: 'A lowercase letter' },
  { key: 'digit', label: 'A number' },
  { key: 'symbol', label: 'A symbol' },
];

export function scorePassword(pw: string): PasswordScore {
  const checks: PasswordChecks = {
    length: pw.length >= PASSWORD_MIN_LENGTH,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    digit: /[0-9]/.test(pw),
    symbol: /[^A-Za-z0-9]/.test(pw),
  };
  const metCount = Object.values(checks).filter(Boolean).length;
  const met = metCount === 5;

  let strength: PasswordStrength;
  if (pw.length === 0) strength = 'empty';
  else if (metCount <= 2) strength = 'weak';
  else if (metCount === 3) strength = 'fair';
  else if (metCount === 4) strength = 'good';
  else strength = pw.length >= 16 ? 'strong' : 'good';

  return { checks, met, strength };
}

const _UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // no I/O — avoid look-alikes
const _LOWER = 'abcdefghijkmnopqrstuvwxyz'; // no l
const _DIGIT = '23456789'; // no 0/1
const _SYMBOL = '!@#$%^&*-_=+?';
const _ALL = _UPPER + _LOWER + _DIGIT + _SYMBOL;

function _pick(charset: string): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return charset[buf[0] % charset.length];
}

/** Cryptographically strong password guaranteed to satisfy the policy. */
export function generateStrongPassword(length = 16): string {
  const len = Math.max(PASSWORD_MIN_LENGTH, length);
  // Seed one of each required class, then fill the rest from the full set.
  const chars = [_pick(_UPPER), _pick(_LOWER), _pick(_DIGIT), _pick(_SYMBOL)];
  while (chars.length < len) chars.push(_pick(_ALL));
  // Fisher-Yates shuffle with crypto randomness so the seeded chars aren't
  // always in the first four positions.
  for (let i = chars.length - 1; i > 0; i--) {
    const r = new Uint32Array(1);
    crypto.getRandomValues(r);
    const j = r[0] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

function _csvCell(v: string): string {
  // Quote when the value contains a comma, quote, or newline; double inner quotes.
  return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

/** Build an AWS-IAM-style credentials CSV for a freshly created/reset account.
 *  The plaintext password lives only in the browser at this moment — it is
 *  never returned by the API, so this is a download-now-or-lose-it artifact. */
export function accountCredentialsCsv(params: {
  username: string;
  password: string;
  loginUrl: string;
}): string {
  const header = ['Username', 'Temporary password', 'Login URL', 'Created at', 'Note'];
  const row = [
    params.username,
    params.password,
    params.loginUrl,
    new Date().toISOString(),
    'User must change this password at first login.',
  ];
  return [header.map(_csvCell).join(','), row.map(_csvCell).join(',')].join('\n') + '\n';
}

/** Trigger a client-side file download for arbitrary text. */
export function downloadTextFile(filename: string, text: string, mime = 'text/csv'): void {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
