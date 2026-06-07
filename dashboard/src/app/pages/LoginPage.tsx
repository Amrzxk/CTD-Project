import { useState, type FormEvent } from 'react';
import { useNavigate, useLocation } from 'react-router';
import { Lock, User, ShieldCheck, AlertCircle } from 'lucide-react';
import { motion } from 'motion/react';
import { useAuth } from '../contexts/AuthContext';

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Where to send the user after successful login — set by RequireAuth when
  // it punts an unauthenticated visit. Defaults to the alerts queue.
  const redirectTo = (location.state as { from?: string } | null)?.from ?? '/alerts';

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
      navigate(redirectTo, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, ease: 'easeOut' }}
        className="w-full max-w-sm"
      >
        <div className="overflow-hidden rounded-xl border border-line bg-panel shadow-2xl shadow-black/30">
          {/* Signature top accent rule */}
          <div className="h-0.5 bg-gradient-to-r from-transparent via-brand to-transparent" />

          <div className="space-y-6 p-7">
            <div className="space-y-3 text-center">
              <span className="mx-auto grid size-12 place-items-center rounded-lg border border-brand/30 bg-brand/10">
                <ShieldCheck className="size-6 text-brand" />
              </span>
              <div>
                <h1 className="font-mono text-xl font-semibold tracking-tight text-foreground">H-IDS</h1>
                <p className="eyebrow mt-1.5 justify-center">Hybrid Intrusion Detection</p>
              </div>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <label className="block">
                <span className="eyebrow">Username</span>
                <div className="relative mt-1.5">
                  <User className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
                  <input
                    type="text"
                    autoFocus
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                    spellCheck={false}
                    className="w-full rounded-md border border-line bg-bg py-2 pl-9 pr-3 font-mono text-sm text-foreground transition-colors placeholder:text-faint focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/25"
                    required
                  />
                </div>
              </label>

              <label className="block">
                <span className="eyebrow">Password</span>
                <div className="relative mt-1.5">
                  <Lock className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    className="w-full rounded-md border border-line bg-bg py-2 pl-9 pr-3 font-mono text-sm text-foreground transition-colors placeholder:text-faint focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/25"
                    required
                  />
                </div>
              </label>

              {error && (
                <div className="flex items-center gap-2 rounded-md border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-xs text-sev-high">
                  <AlertCircle className="size-3.5 shrink-0" />
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full rounded-md bg-brand py-2.5 text-sm font-semibold text-[var(--on-brand)] transition-colors hover:bg-brand-bright disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? 'Signing in…' : 'Sign in'}
              </button>
            </form>
          </div>
        </div>

        <p className="mt-4 text-center font-mono text-[0.7rem] text-faint">
          Authorized access only · sessions are audit-logged
        </p>
      </motion.div>
    </div>
  );
}
