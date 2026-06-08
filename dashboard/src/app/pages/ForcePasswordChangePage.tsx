import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { KeyRound, Lock, ShieldAlert, AlertCircle } from 'lucide-react';
import { motion } from 'motion/react';
import { useAuth } from '../contexts/AuthContext';
import { changePassword } from '../services/threatDetectionService';
import { PasswordStrength } from '../components/PasswordStrength';
import { scorePassword } from '../lib/password';
import { toast } from 'sonner';

const INPUT_CLASS =
  'w-full rounded-md border border-line bg-bg py-2 pl-9 pr-3 font-mono text-sm text-foreground transition-colors placeholder:text-faint focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/25';

/** Forced first-login password change. A SOC account created (or reset) with
 *  an admin-set temporary password is routed here by RequireAuth and can't
 *  reach the rest of the app until it picks its own compliant password. */
export default function ForcePasswordChangePage() {
  const navigate = useNavigate();
  const { user, refresh } = useAuth();

  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const strongEnough = scorePassword(newPassword).met;
  const matches = newPassword.length > 0 && newPassword === confirm;
  const reused = newPassword.length > 0 && newPassword === oldPassword;
  const canSubmit = oldPassword.length > 0 && strongEnough && matches && !reused && !submitting;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      await changePassword(oldPassword, newPassword);
      await refresh(); // clears must_change_password → guard lets us through
      toast.success('Password updated. Welcome aboard.');
      navigate('/alerts', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change password');
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
        className="w-full max-w-md"
      >
        <div className="overflow-hidden rounded-xl border border-line bg-panel shadow-2xl shadow-black/30">
          {/* Signature top accent rule */}
          <div className="h-0.5 bg-gradient-to-r from-transparent via-brand to-transparent" />

          <div className="space-y-6 p-7">
            <div className="space-y-3 text-center">
              <span className="mx-auto grid size-12 place-items-center rounded-lg border border-brand/30 bg-brand/10">
                <ShieldAlert className="size-6 text-brand" />
              </span>
              <div>
                <h1 className="font-mono text-xl font-semibold tracking-tight text-foreground">
                  Set your password
                </h1>
                <p className="eyebrow mt-1.5 justify-center">First sign-in · required</p>
              </div>
              <p className="text-sm text-muted-foreground">
                {user ? (
                  <>
                    You're signed in as{' '}
                    <span className="font-mono text-foreground">{user.username}</span> with a
                    temporary password. Choose a new one to continue.
                  </>
                ) : (
                  'Choose a new password to continue.'
                )}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <label className="block">
                <span className="eyebrow">Temporary password</span>
                <div className="relative mt-1.5">
                  <KeyRound className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
                  <input
                    type="password"
                    autoFocus
                    value={oldPassword}
                    onChange={(e) => setOldPassword(e.target.value)}
                    autoComplete="current-password"
                    className={INPUT_CLASS}
                    required
                  />
                </div>
              </label>

              <label className="block">
                <span className="eyebrow">New password</span>
                <div className="relative mt-1.5">
                  <Lock className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    autoComplete="new-password"
                    className={INPUT_CLASS}
                    required
                  />
                </div>
                <PasswordStrength password={newPassword} />
              </label>

              <label className="block">
                <span className="eyebrow">Confirm new password</span>
                <div className="relative mt-1.5">
                  <Lock className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
                  <input
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    autoComplete="new-password"
                    className={INPUT_CLASS}
                    required
                  />
                </div>
                {confirm.length > 0 && !matches && (
                  <p className="mt-1.5 text-xs text-sev-high">Passwords don't match.</p>
                )}
                {reused && (
                  <p className="mt-1.5 text-xs text-sev-high">
                    New password must differ from the temporary one.
                  </p>
                )}
              </label>

              {error && (
                <div className="flex items-center gap-2 rounded-md border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-xs text-sev-high">
                  <AlertCircle className="size-3.5 shrink-0" />
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={!canSubmit}
                className="w-full rounded-md bg-brand py-2.5 text-sm font-semibold text-[var(--on-brand)] transition-colors hover:bg-brand-bright disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? 'Saving…' : 'Set password & continue'}
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
