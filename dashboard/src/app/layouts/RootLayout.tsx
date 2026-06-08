import { Outlet, useLocation, useNavigate } from 'react-router';
import { useEffect, useState } from 'react';
import { Sidebar } from '../components/Sidebar';
import { TopBar } from '../components/TopBar';
import { AlertBanner } from '../components/AlertBanner';
import { QuickStartGuide } from '../components/QuickStartGuide';
import { Toaster } from '../components/ui/sonner';
import { threatService } from '../services/threatDetectionService';
import { useAuth } from '../contexts/AuthContext';
import type { AlertNotification } from '../types/threat';
import { LiveStreamProvider } from '../contexts/LiveStreamContext';

// Landing + login + the forced password-change screen render their own
// full-bleed layout (no sidebar/topbar). The forced-change screen is bare so
// a SOC account can't navigate around it before setting a real password.
const BARE_ROUTES = new Set(['/', '/login', '/force-password-change']);

export default function RootLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [alerts, setAlerts] = useState<AlertNotification[]>([]);

  const bare = BARE_ROUTES.has(location.pathname);

  useEffect(() => {
    setAlerts(threatService.getAlerts());
    const interval = setInterval(() => setAlerts(threatService.getAlerts()), 5000);
    return () => clearInterval(interval);
  }, []);

  // Global keyboard shortcuts (Ctrl/Cmd + U / M).
  useEffect(() => {
    const handleKeyPress = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey) {
        switch (e.key.toLowerCase()) {
          case 'u':
            e.preventDefault();
            window.location.href = '/upload';
            break;
          case 'm':
            e.preventDefault();
            window.location.href = '/manual';
            break;
        }
      }
    };
    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, []);

  const handleDismissAlert = (id: string) => {
    threatService.clearAlert(id);
    setAlerts(threatService.getAlerts());
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <LiveStreamProvider>
      <div className="relative min-h-screen bg-bg text-foreground">
        <div className="app-texture" aria-hidden />

        {bare ? (
          <div className="relative z-10">
            <Outlet />
          </div>
        ) : (
          <div className="relative z-10 flex">
            <Sidebar onLogout={handleLogout} />
            <div className="flex min-w-0 flex-1 flex-col">
              <TopBar />
              <AlertBanner alerts={alerts} onDismiss={handleDismissAlert} />
              <main className="flex-1">
                <Outlet />
              </main>
            </div>
          </div>
        )}

        <QuickStartGuide />
        <Toaster position="top-right" />
      </div>
    </LiveStreamProvider>
  );
}
