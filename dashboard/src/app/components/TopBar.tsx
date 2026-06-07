import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router';
import { useTheme } from 'next-themes';
import { Radio, Bell, Sun, Moon } from 'lucide-react';
import { threatService } from '../services/threatDetectionService';
import { useLiveStream } from '../contexts/LiveStreamContext';
import { cn } from './ui/utils';

const PAGE_META: Record<string, { group: string; title: string }> = {
  '/live': { group: 'Monitor', title: 'Live Threat Stream' },
  '/dashboard': { group: 'Monitor', title: 'Results Dashboard' },
  '/alerts': { group: 'Monitor', title: 'Alerts Queue' },
  '/upload': { group: 'Analyze', title: 'Batch Analysis' },
  '/manual': { group: 'Analyze', title: 'Manual Flow Analysis' },
  '/analytics': { group: 'Intel', title: 'Analytics' },
  '/mitre': { group: 'Intel', title: 'MITRE ATT&CK' },
};

export function TopBar() {
  const location = useLocation();
  const { activeSession, eps, connected } = useLiveStream();
  const { resolvedTheme, setTheme } = useTheme();

  const [mounted, setMounted] = useState(false);
  const [health, setHealth] = useState<'healthy' | 'unhealthy' | 'unknown'>('unknown');
  const [alertCount, setAlertCount] = useState(0);

  useEffect(() => setMounted(true), []);

  useEffect(() => {
    let alive = true;
    const ping = async () => {
      try {
        const h = await threatService.checkHealth();
        if (alive) setHealth(h.status === 'healthy' ? 'healthy' : 'unhealthy');
      } catch {
        if (alive) setHealth('unhealthy');
      }
    };
    void ping();
    const id = window.setInterval(ping, 20000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, []);

  useEffect(() => {
    const tick = () =>
      setAlertCount(threatService.getAlerts().filter((a) => a.type === 'critical').length);
    tick();
    const id = window.setInterval(tick, 5000);
    return () => window.clearInterval(id);
  }, []);

  const meta = PAGE_META[location.pathname] ?? { group: 'Console', title: 'H-IDS' };
  const isDark = (mounted ? resolvedTheme : 'dark') === 'dark';

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-4 border-b border-line bg-bg/80 px-4 backdrop-blur-md">
      {/* Breadcrumb */}
      <div className="flex min-w-0 items-baseline gap-2">
        <span className="eyebrow shrink-0">{meta.group}</span>
        <span className="text-faint">/</span>
        <span className="truncate font-mono text-sm font-medium text-foreground">{meta.title}</span>
      </div>

      {/* Telemetry cluster */}
      <div className="flex items-center gap-3">
        {/* API health */}
        <div className="hidden items-center gap-1.5 sm:flex" title={`Backend API: ${health}`}>
          <span
            className={cn(
              'size-2 rounded-full',
              health === 'healthy' ? 'bg-ok' : health === 'unhealthy' ? 'bg-sev-high' : 'bg-neutral',
            )}
          />
          <span className="eyebrow">API</span>
        </div>

        <span className="hidden h-4 w-px bg-line sm:block" aria-hidden />

        {/* Session / EPS */}
        {activeSession ? (
          <div className="flex items-center gap-2">
            <span
              className={cn(
                'scanline inline-flex items-center gap-1.5 rounded-md border px-2 py-1',
                connected ? 'border-brand/40 bg-brand/10' : 'border-sev-med/40 bg-sev-med/10',
              )}
              title={connected ? 'Streaming' : 'Reconnecting…'}
            >
              <Radio className={cn('size-3', connected ? 'text-brand' : 'text-sev-med')} />
              <span className="font-mono text-[0.7rem] font-semibold uppercase tracking-wide text-brand-text">
                Live
              </span>
            </span>
            <span className="hidden font-mono text-xs text-muted-foreground md:inline">
              {activeSession.source}/{activeSession.detection_mode}
            </span>
            <span className="font-mono text-xs text-muted-foreground">
              <span className="tabular-nums text-foreground">{eps.toFixed(1)}</span> eps
            </span>
          </div>
        ) : (
          <span className="eyebrow">Session Idle</span>
        )}

        <span className="h-4 w-px bg-line" aria-hidden />

        {/* Alerts bell */}
        <Link
          to="/alerts"
          title="Alerts queue"
          className="relative rounded-md p-2 text-muted-foreground transition-colors hover:bg-panel-raised hover:text-foreground"
        >
          <Bell className="size-4" />
          {alertCount > 0 && (
            <span className="absolute -right-0.5 -top-0.5 grid size-4 place-items-center rounded-full bg-sev-high font-mono text-[0.6rem] font-bold text-white">
              {alertCount > 9 ? '9+' : alertCount}
            </span>
          )}
        </Link>

        {/* Theme toggle */}
        <button
          onClick={() => setTheme(isDark ? 'light' : 'dark')}
          title={isDark ? 'Switch to light' : 'Switch to dark'}
          className="rounded-md p-2 text-muted-foreground transition-colors hover:bg-panel-raised hover:text-foreground"
        >
          {isDark ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </button>
      </div>
    </header>
  );
}
