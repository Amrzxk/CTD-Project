import { X, AlertTriangle } from 'lucide-react';
import { Button } from './ui/button';
import { motion, AnimatePresence } from 'motion/react';
import type { AlertNotification } from '../types/threat';

interface AlertBannerProps {
  alerts: AlertNotification[];
  onDismiss: (id: string) => void;
}

export function AlertBanner({ alerts, onDismiss }: AlertBannerProps) {
  const criticalAlerts = alerts.filter(a => a.type === 'critical');

  if (criticalAlerts.length === 0) return null;

  return (
    <AnimatePresence>
      {criticalAlerts.map((alert) => (
        <motion.div
          key={alert.id}
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          className="bg-sev-high/10 border-b border-sev-high/30 backdrop-blur"
        >
          <div className="container mx-auto px-4 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-sev-high animate-pulse" />
                <div>
                  <p className="text-sev-high font-semibold">{alert.message}</p>
                  {alert.sourceIp && (
                    <p className="text-xs text-sev-high/70 font-mono">Source: {alert.sourceIp}</p>
                  )}
                </div>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onDismiss(alert.id)}
                className="text-sev-high hover:bg-sev-high/20"
              >
                <X className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </motion.div>
      ))}
    </AnimatePresence>
  );
}