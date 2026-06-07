import { useState } from 'react';
import { Link, useLocation } from 'react-router';
import {
  Shield, Radio, LayoutDashboard, ShieldAlert, Upload, PenLine,
  BarChart3, Target, LogOut, PanelLeftClose, PanelLeft,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { cn } from './ui/utils';

const COLLAPSE_KEY = 'hids.sidebar.collapsed';

type NavItem = { to: string; label: string; icon: React.ComponentType<{ className?: string }> };

const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: 'Monitor',
    items: [
      { to: '/live', label: 'Live Stream', icon: Radio },
      { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
    ],
  },
  {
    label: 'Analyze',
    items: [
      { to: '/upload', label: 'Batch Upload', icon: Upload },
      { to: '/manual', label: 'Manual Flow', icon: PenLine },
    ],
  },
  {
    label: 'Intel',
    items: [
      { to: '/analytics', label: 'Analytics', icon: BarChart3 },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: Target },
    ],
  },
];

export function Sidebar({ onLogout }: { onLogout: () => void }) {
  const location = useLocation();
  const { user } = useAuth();
  const [collapsed, setCollapsed] = useState<boolean>(
    () => localStorage.getItem(COLLAPSE_KEY) === '1',
  );

  const toggle = () => {
    setCollapsed((c) => {
      const next = !c;
      localStorage.setItem(COLLAPSE_KEY, next ? '1' : '0');
      return next;
    });
  };

  return (
    <aside
      className={cn(
        'sticky top-0 z-40 flex h-screen shrink-0 flex-col border-r border-line bg-sidebar',
        'transition-[width] duration-200 ease-out',
        collapsed ? 'w-[4.25rem]' : 'w-60',
      )}
    >
      {/* Brand */}
      <Link
        to="/"
        className={cn(
          'flex items-center gap-2.5 border-b border-line px-4 py-4',
          collapsed && 'justify-center px-0',
        )}
        title="H-IDS — Hybrid Intrusion Detection"
      >
        <span className="grid size-9 shrink-0 place-items-center rounded-md border border-brand/30 bg-brand/10">
          <Shield className="size-5 text-brand" />
        </span>
        {!collapsed && (
          <span className="flex flex-col leading-none">
            <span className="font-mono text-sm font-semibold tracking-tight text-foreground">H-IDS</span>
            <span className="eyebrow mt-1 text-[0.6rem]">Hybrid IDS</span>
          </span>
        )}
      </Link>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-4 last:mb-0">
            {!collapsed && <div className="eyebrow px-2 pb-1.5">{group.label}</div>}
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const active = location.pathname === item.to;
                return (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      title={collapsed ? item.label : undefined}
                      className={cn(
                        'group relative flex items-center gap-3 rounded-md px-2.5 py-2 text-sm transition-colors duration-150',
                        collapsed && 'justify-center px-0',
                        active
                          ? 'bg-brand/10 font-medium text-brand-text'
                          : 'text-muted-foreground hover:bg-panel-raised hover:text-foreground',
                      )}
                    >
                      {active && (
                        <span className="absolute inset-y-1 left-0 w-0.5 rounded-full bg-brand" aria-hidden />
                      )}
                      <item.icon className="size-[1.15rem] shrink-0" />
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer: user + collapse */}
      <div className="border-t border-line p-2">
        {user && (
          <div
            className={cn(
              'mb-1 flex items-center gap-2.5 rounded-md px-2 py-2',
              collapsed && 'justify-center px-0',
            )}
          >
            <span className="grid size-8 shrink-0 place-items-center rounded-full border border-line bg-panel-raised font-mono text-xs font-semibold uppercase text-brand-text">
              {(user.username || '?').slice(0, 2)}
            </span>
            {!collapsed && (
              <div className="flex min-w-0 flex-1 flex-col leading-tight">
                <span className="truncate font-mono text-xs text-foreground">{user.username}</span>
                <span className="eyebrow text-[0.6rem]">{user.role}</span>
              </div>
            )}
            {!collapsed && (
              <button
                onClick={onLogout}
                title="Sign out"
                className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-panel-raised hover:text-sev-high"
              >
                <LogOut className="size-4" />
              </button>
            )}
          </div>
        )}
        <button
          onClick={toggle}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={cn(
            'flex w-full items-center gap-3 rounded-md px-2.5 py-2 text-sm text-muted-foreground transition-colors hover:bg-panel-raised hover:text-foreground',
            collapsed && 'justify-center px-0',
          )}
        >
          {collapsed ? <PanelLeft className="size-[1.15rem]" /> : <PanelLeftClose className="size-[1.15rem]" />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
