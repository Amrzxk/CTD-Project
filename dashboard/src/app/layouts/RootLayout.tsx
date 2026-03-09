import { Outlet } from 'react-router';
import { Navigation } from '../components/Navigation';
import { AlertBanner } from '../components/AlertBanner';
import { QuickStartGuide } from '../components/QuickStartGuide';
import { Toaster } from '../components/ui/sonner';
import { useEffect, useState } from 'react';
import { threatService } from '../services/threatDetectionService';
import type { AlertNotification } from '../types/threat';

export default function RootLayout() {
  const [alerts, setAlerts] = useState<AlertNotification[]>([]);

  useEffect(() => {
    // Load alerts on mount
    setAlerts(threatService.getAlerts());

    // Check for new alerts periodically
    const interval = setInterval(() => {
      setAlerts(threatService.getAlerts());
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const handleDismissAlert = (id: string) => {
    threatService.clearAlert(id);
    setAlerts(threatService.getAlerts());
  };

  // Keyboard shortcuts
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

  return (
    <div className="min-h-screen bg-[#080c14]">
      <Navigation />
      <AlertBanner alerts={alerts} onDismiss={handleDismissAlert} />
      <Outlet />
      <QuickStartGuide />
      <Toaster 
        position="top-right"
        toastOptions={{
          style: {
            background: '#0f1520',
            color: '#f0f2f5',
            border: '1px solid rgba(148, 180, 214, 0.15)',
          },
        }}
      />
    </div>
  );
}