import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { motion } from 'motion/react';
import {
  UserCog, UserPlus, RefreshCw, Eye, EyeOff, Download, Copy, Check,
  Power, KeyRound, Loader2, ShieldCheck, AlertCircle, Users,
} from 'lucide-react';
import { toast } from 'sonner';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Label } from '../components/ui/label';
import { Badge } from '../components/ui/badge';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '../components/ui/dialog';
import { PasswordStrength } from '../components/PasswordStrength';
import { cn } from '../components/ui/utils';
import { useAuth } from '../contexts/AuthContext';
import {
  listUsers, createUser, setUserActive, resetUserPassword, type ManagedUser,
} from '../services/threatDetectionService';
import {
  generateStrongPassword, scorePassword, accountCredentialsCsv, downloadTextFile,
} from '../lib/password';

const INPUT_CLASS =
  'w-full rounded-md border border-line bg-bg py-2 pl-9 pr-20 font-mono text-sm text-foreground transition-colors placeholder:text-faint focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/25';

const LOGIN_URL = `${window.location.origin}/login`;

interface Credentials {
  username: string;
  password: string;
}

/** Username + password field with reveal toggle + "generate strong" action,
 *  and the live strength meter underneath. Shared by the create form and the
 *  reset dialog. */
function PasswordField({
  id,
  value,
  onChange,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
}) {
  const [reveal, setReveal] = useState(false);
  return (
    <div>
      <div className="relative mt-1.5">
        <KeyRound className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
        <input
          id={id}
          type={reveal ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete="new-password"
          spellCheck={false}
          placeholder="Set or generate a strong password"
          className={INPUT_CLASS}
        />
        <div className="absolute right-2 top-1/2 flex -translate-y-1/2 items-center gap-1">
          <button
            type="button"
            onClick={() => setReveal((r) => !r)}
            title={reveal ? 'Hide' : 'Reveal'}
            className="rounded p-1 text-faint transition-colors hover:text-foreground"
          >
            {reveal ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
          </button>
          <button
            type="button"
            onClick={() => { onChange(generateStrongPassword(16)); setReveal(true); }}
            title="Generate a strong password"
            className="rounded p-1 text-brand-text transition-colors hover:text-brand-bright"
          >
            <RefreshCw className="size-4" />
          </button>
        </div>
      </div>
      <PasswordStrength password={value} />
    </div>
  );
}

function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-md border border-line bg-panel-raised px-3 py-2">
      <div className="eyebrow text-[0.6rem]">{label}</div>
      <div className="mt-0.5 font-mono text-lg text-foreground">{value}</div>
    </div>
  );
}

export default function UserManagementPage() {
  const { user: me } = useAuth();

  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(true);

  // Create form
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [creating, setCreating] = useState(false);

  // Per-row pending action (id being toggled) so we can disable its buttons.
  const [pendingId, setPendingId] = useState<number | null>(null);

  // Reset-password dialog
  const [resetTarget, setResetTarget] = useState<ManagedUser | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const [resetting, setResetting] = useState(false);

  // Credentials hand-off modal (shown once after create/reset)
  const [credentials, setCredentials] = useState<Credentials | null>(null);
  const [copied, setCopied] = useState(false);

  const usernameValid = /^[A-Za-z0-9_-]{3,64}$/.test(username);
  const canCreate = usernameValid && scorePassword(password).met && !creating;

  const loadUsers = useCallback(async () => {
    try {
      setUsers(await listUsers());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoadingUsers(false);
    }
  }, []);

  useEffect(() => { void loadUsers(); }, [loadUsers]);

  const stats = useMemo(() => {
    const analysts = users.filter((u) => u.role === 'analyst');
    return {
      total: users.length,
      analysts: analysts.length,
      active: analysts.filter((u) => u.is_active).length,
      pending: analysts.filter((u) => u.must_change_password).length,
    };
  }, [users]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canCreate) return;
    setCreating(true);
    try {
      const created = await createUser(username, password);
      toast.success(`SOC account "${created.username}" created.`);
      setCredentials({ username: created.username, password }); // plaintext only lives here
      setUsername('');
      setPassword('');
      await loadUsers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create user');
    } finally {
      setCreating(false);
    }
  };

  const handleToggleActive = async (u: ManagedUser) => {
    setPendingId(u.id);
    try {
      await setUserActive(u.id, !u.is_active);
      toast.success(`${u.username} ${u.is_active ? 'disabled' : 'enabled'}.`);
      await loadUsers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to update account');
    } finally {
      setPendingId(null);
    }
  };

  const handleReset = async () => {
    if (!resetTarget || !scorePassword(resetPassword).met) return;
    setResetting(true);
    try {
      await resetUserPassword(resetTarget.id, resetPassword);
      toast.success(`Password reset for ${resetTarget.username}.`);
      setCredentials({ username: resetTarget.username, password: resetPassword });
      setResetTarget(null);
      setResetPassword('');
      await loadUsers();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to reset password');
    } finally {
      setResetting(false);
    }
  };

  const downloadCreds = () => {
    if (!credentials) return;
    const csv = accountCredentialsCsv({ ...credentials, loginUrl: LOGIN_URL });
    downloadTextFile(`hids-credentials-${credentials.username}.csv`, csv);
  };

  const copyCreds = async () => {
    if (!credentials) return;
    await navigator.clipboard.writeText(
      `Username: ${credentials.username}\nPassword: ${credentials.password}\nLogin: ${LOGIN_URL}`,
    );
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-bg via-bg to-bg py-12">
      <div className="container mx-auto max-w-6xl px-4">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          {/* Header */}
          <div className="mb-8">
            <h1 className="mb-2 flex items-center gap-3 text-4xl font-bold text-foreground">
              <UserCog className="size-8 text-brand" />
              User Management
            </h1>
            <p className="text-muted-foreground">
              Create and manage SOC analyst accounts. Analysts can access the Alerts and
              Analytics queues only.
            </p>
          </div>

          {/* Stat tiles */}
          <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Total accounts" value={stats.total} />
            <Stat label="SOC analysts" value={stats.analysts} />
            <Stat label="Active" value={stats.active} />
            <Stat label="Pending first login" value={stats.pending} />
          </div>

          <div className="grid gap-8 lg:grid-cols-[minmax(0,22rem)_1fr]">
            {/* ── Create form ── */}
            <Card className="bg-panel/70 backdrop-blur self-start border-line">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-foreground">
                  <UserPlus className="size-5 text-brand" />
                  Create SOC account
                </CardTitle>
                <CardDescription className="text-muted-foreground">
                  Role is fixed to <span className="font-mono text-brand-text">analyst</span>. The
                  user must change this password at first login.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleCreate} className="space-y-5">
                  <div>
                    <Label htmlFor="new-username" className="text-foreground">Username</Label>
                    <div className="relative mt-1.5">
                      <Users className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
                      <input
                        id="new-username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        autoComplete="off"
                        spellCheck={false}
                        placeholder="soc-analyst"
                        className="w-full rounded-md border border-line bg-bg py-2 pl-9 pr-3 font-mono text-sm text-foreground transition-colors placeholder:text-faint focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/25"
                      />
                    </div>
                    {username.length > 0 && !usernameValid && (
                      <p className="mt-1.5 text-xs text-sev-high">
                        3–64 chars · letters, numbers, dash, underscore only.
                      </p>
                    )}
                  </div>

                  <div>
                    <Label htmlFor="new-password" className="text-foreground">Temporary password</Label>
                    <PasswordField id="new-password" value={password} onChange={setPassword} />
                  </div>

                  <Button
                    type="submit"
                    disabled={!canCreate}
                    className="w-full bg-brand font-semibold text-[var(--on-brand)] hover:bg-brand-bright disabled:opacity-50"
                  >
                    {creating ? (
                      <><Loader2 className="mr-2 size-4 animate-spin" />Creating…</>
                    ) : (
                      <><UserPlus className="mr-2 size-4" />Create account</>
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>

            {/* ── Accounts table ── */}
            <Card className="bg-panel/70 backdrop-blur border-line">
              <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
                <div>
                  <CardTitle className="text-foreground">Accounts</CardTitle>
                  <CardDescription className="text-muted-foreground">
                    {stats.total} account{stats.total === 1 ? '' : 's'}
                  </CardDescription>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => { setLoadingUsers(true); void loadUsers(); }}
                  className="border-line text-muted-foreground hover:text-foreground"
                >
                  <RefreshCw className={cn('mr-2 size-3.5', loadingUsers && 'animate-spin')} />
                  Refresh
                </Button>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="border-b border-line">
                      <tr className="text-left">
                        {['User', 'Role', 'Status', 'Created', 'Last login', 'Actions'].map((h) => (
                          <th key={h} className="eyebrow px-4 py-2.5 text-[0.6rem]">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {loadingUsers && users.length === 0 ? (
                        <tr><td colSpan={6} className="px-4 py-10 text-center text-muted-foreground">
                          <Loader2 className="mx-auto size-5 animate-spin" />
                        </td></tr>
                      ) : users.length === 0 ? (
                        <tr><td colSpan={6} className="px-4 py-10 text-center text-muted-foreground">
                          No accounts yet.
                        </td></tr>
                      ) : (
                        users.map((u) => {
                          const isAdmin = u.role === 'admin';
                          const isSelf = me?.id === u.id;
                          const busy = pendingId === u.id;
                          return (
                            <tr key={u.id} className="border-b border-line/40 transition-colors hover:bg-line/30">
                              <td className="px-4 py-3">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-foreground">{u.username}</span>
                                  {isSelf && <span className="eyebrow text-[0.55rem] text-faint">you</span>}
                                </div>
                                {u.must_change_password && (
                                  <span className="mt-0.5 inline-flex items-center gap-1 text-[0.7rem] text-sev-med">
                                    <KeyRound className="size-3" /> must change password
                                  </span>
                                )}
                              </td>
                              <td className="px-4 py-3">
                                <Badge
                                  className={cn(
                                    'border font-mono text-[0.7rem]',
                                    isAdmin
                                      ? 'border-brand/30 bg-brand/10 text-brand-text'
                                      : 'border-sev-low/30 bg-sev-low/10 text-sev-low',
                                  )}
                                >
                                  {u.role}
                                </Badge>
                              </td>
                              <td className="px-4 py-3">
                                <span className={cn(
                                  'inline-flex items-center gap-1.5 text-xs',
                                  u.is_active ? 'text-ok' : 'text-faint',
                                )}>
                                  <span className={cn(
                                    'size-1.5 rounded-full',
                                    u.is_active ? 'bg-ok' : 'bg-faint',
                                  )} />
                                  {u.is_active ? 'Active' : 'Disabled'}
                                </span>
                              </td>
                              <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                                {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                              </td>
                              <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                                {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'never'}
                              </td>
                              <td className="px-4 py-3">
                                {isAdmin ? (
                                  <span className="text-xs text-faint">—</span>
                                ) : (
                                  <div className="flex items-center gap-1.5">
                                    <Button
                                      size="sm" variant="ghost" disabled={busy}
                                      onClick={() => handleToggleActive(u)}
                                      className={cn(
                                        'h-7 px-2 text-xs',
                                        u.is_active
                                          ? 'text-sev-high hover:bg-sev-high/10'
                                          : 'text-ok hover:bg-ok/10',
                                      )}
                                    >
                                      <Power className="mr-1 size-3.5" />
                                      {u.is_active ? 'Disable' : 'Enable'}
                                    </Button>
                                    <Button
                                      size="sm" variant="ghost" disabled={busy}
                                      onClick={() => { setResetTarget(u); setResetPassword(''); }}
                                      className="h-7 px-2 text-xs text-muted-foreground hover:bg-line hover:text-foreground"
                                    >
                                      <KeyRound className="mr-1 size-3.5" />
                                      Reset
                                    </Button>
                                  </div>
                                )}
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </div>
        </motion.div>
      </div>

      {/* ── Reset-password dialog ── */}
      <Dialog open={resetTarget !== null} onOpenChange={(o) => { if (!o) { setResetTarget(null); setResetPassword(''); } }}>
        <DialogContent className="border-line bg-panel">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <KeyRound className="size-5 text-brand" />
              Reset password
            </DialogTitle>
            <DialogDescription className="text-muted-foreground">
              Set a new temporary password for{' '}
              <span className="font-mono text-foreground">{resetTarget?.username}</span>. They'll be
              forced to change it on next login, and their current sessions end immediately.
            </DialogDescription>
          </DialogHeader>
          <div>
            <Label htmlFor="reset-password" className="text-foreground">New temporary password</Label>
            <PasswordField id="reset-password" value={resetPassword} onChange={setResetPassword} />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => { setResetTarget(null); setResetPassword(''); }}
              className="border-line text-muted-foreground hover:text-foreground"
            >
              Cancel
            </Button>
            <Button
              disabled={!scorePassword(resetPassword).met || resetting}
              onClick={handleReset}
              className="bg-brand font-semibold text-[var(--on-brand)] hover:bg-brand-bright disabled:opacity-50"
            >
              {resetting ? <><Loader2 className="mr-2 size-4 animate-spin" />Resetting…</> : 'Reset password'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Credentials hand-off modal (shown once) ── */}
      <Dialog open={credentials !== null} onOpenChange={(o) => { if (!o) setCredentials(null); }}>
        <DialogContent className="border-line bg-panel">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <ShieldCheck className="size-5 text-ok" />
              Account credentials
            </DialogTitle>
            <DialogDescription className="text-muted-foreground">
              Share these with the user over a secure channel. For security, the password is shown
              only now — download or copy it before closing.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            <div className="flex items-start gap-2 rounded-md border border-sev-med/40 bg-sev-med/10 px-3 py-2 text-xs text-sev-med">
              <AlertCircle className="mt-0.5 size-3.5 shrink-0" />
              This password cannot be retrieved later. The user must change it at first login.
            </div>
            <div className="space-y-2 rounded-md border border-line bg-panel-raised p-3 font-mono text-sm">
              <div className="flex justify-between gap-3">
                <span className="text-faint">Username</span>
                <span className="text-foreground">{credentials?.username}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-faint">Password</span>
                <span className="break-all text-right text-foreground">{credentials?.password}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-faint">Login URL</span>
                <span className="break-all text-right text-brand-text">{LOGIN_URL}</span>
              </div>
            </div>
          </div>

          <DialogFooter className="sm:justify-between">
            <Button
              variant="outline"
              onClick={copyCreds}
              className="border-line text-muted-foreground hover:text-foreground"
            >
              {copied ? <><Check className="mr-2 size-4 text-ok" />Copied</> : <><Copy className="mr-2 size-4" />Copy</>}
            </Button>
            <Button
              onClick={downloadCreds}
              className="bg-brand font-semibold text-[var(--on-brand)] hover:bg-brand-bright"
            >
              <Download className="mr-2 size-4" />
              Download .csv
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
