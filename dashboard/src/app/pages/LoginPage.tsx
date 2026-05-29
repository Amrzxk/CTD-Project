import { useState, type FormEvent } from 'react';
import { useNavigate, useLocation } from 'react-router';
import { Lock, ShieldCheck, AlertCircle } from 'lucide-react';
import { motion } from 'motion/react';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { useAuth } from '../contexts/AuthContext';

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Where to send the user after successful login — set by RequireAuth
  // when it punts an unauthenticated visit. Defaults to the alerts queue
  // so analysts land somewhere useful.
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
    <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="w-full max-w-sm"
      >
        <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
          <CardContent className="p-6 space-y-5">
            <div className="text-center space-y-2">
              <div className="inline-flex w-12 h-12 items-center justify-center rounded-full bg-[#00ccff]/10 border border-[#00ccff]/40">
                <ShieldCheck className="w-6 h-6 text-[#00ccff]" />
              </div>
              <h1 className="text-xl font-bold text-white">Hybrid IDS</h1>
              <p className="text-xs text-gray-500">Sign in to continue</p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3">
              <label className="block">
                <span className="text-[10px] uppercase tracking-wide text-gray-500">Username</span>
                <input
                  type="text"
                  autoFocus
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  spellCheck={false}
                  className="w-full mt-1 bg-[#1a2540]/40 border border-[#253352] rounded px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-[#00ccff]/60"
                  required
                />
              </label>
              <label className="block">
                <span className="text-[10px] uppercase tracking-wide text-gray-500">Password</span>
                <div className="relative mt-1">
                  <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    className="w-full bg-[#1a2540]/40 border border-[#253352] rounded pl-8 pr-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-[#00ccff]/60"
                    required
                  />
                </div>
              </label>

              {error && (
                <div className="flex items-center gap-2 px-3 py-2 rounded border border-[#ff3366]/40 bg-[#ff3366]/5 text-[11px] text-[#ff3366]">
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  {error}
                </div>
              )}

              <Button
                type="submit"
                disabled={submitting}
                className="w-full bg-[#00ccff] hover:bg-[#00ccff]/80 text-black font-semibold disabled:opacity-50"
              >
                {submitting ? 'Signing in…' : 'Sign in'}
              </Button>
            </form>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
