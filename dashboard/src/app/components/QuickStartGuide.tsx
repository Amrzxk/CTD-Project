import { useState, useEffect } from 'react';
import { X, Shield, Upload, PenLine, BarChart3, Keyboard } from 'lucide-react';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { motion, AnimatePresence } from 'motion/react';

export function QuickStartGuide() {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
<<<<<<< HEAD
    // Ensure popup is displayed automatically upon initial site load natively mapped without localStorage barriers
    setIsVisible(true);
  }, []);

  const handleClose = () => {
=======
    // Check if user has seen the guide before
    const hasSeenGuide = localStorage.getItem('hasSeenQuickStartGuide');
    if (!hasSeenGuide) {
      setIsVisible(true);
    }
  }, []);

  const handleClose = () => {
    localStorage.setItem('hasSeenQuickStartGuide', 'true');
>>>>>>> 260c5da33751fd3b387bc26d584989d6a0489685
    setIsVisible(false);
  };

  if (!isVisible) return null;

  const steps = [
    {
      icon: Upload,
      title: 'Upload CSV Data',
      description: 'Navigate to Upload page to analyze batch network traffic data',
      color: 'text-[#00ff88]'
    },
    {
      icon: PenLine,
      title: 'Manual Analysis',
      description: 'Use Manual Input for real-time single connection threat detection',
      color: 'text-[#00ccff]'
    },
    {
      icon: BarChart3,
      title: 'View Analytics',
      description: 'Check Dashboard and Analytics for comprehensive insights',
      color: 'text-[#00ccff]'
    },
    {
      icon: Keyboard,
      title: 'Keyboard Shortcuts',
      description: 'Press Ctrl+U for Upload, Ctrl+M for Manual Input',
      color: 'text-yellow-400'
    }
  ];

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={handleClose}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
            className="max-w-2xl w-full"
          >
            <Card className="bg-[#0b0f1a] border-[#00ff88]/40">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-3 rounded-lg bg-[#00ff88]/20">
                      <Shield className="w-8 h-8 text-[#00ff88]" />
                    </div>
                    <div>
                      <CardTitle className="text-2xl text-white">Welcome to Cyber Threat Detection</CardTitle>
                      <p className="text-sm text-gray-400 mt-1">Quick Start Guide</p>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleClose}
                    className="text-gray-400 hover:text-white"
                  >
                    <X className="w-5 h-5" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 mb-6">
                  {steps.map((step, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      className="flex items-start gap-4 p-4 bg-[#0f1825]/70 rounded-lg border border-[#1a2540]"
                    >
                      <div className="p-2 rounded-lg bg-gray-700/50">
                        <step.icon className={`w-6 h-6 ${step.color}`} />
                      </div>
                      <div>
                        <h3 className="text-white font-semibold mb-1">{step.title}</h3>
                        <p className="text-sm text-gray-400">{step.description}</p>
                      </div>
                    </motion.div>
                  ))}
                </div>

                <div className="p-4 bg-[#00ccff]/10 border border-[#00ccff]/30 rounded-lg mb-6">
                  <p className="text-sm text-[#00ccff]">
                    <strong>Development Mode:</strong> The dashboard is currently running with mock data. 
                    Configure your FastAPI backend URL in the environment variables to connect to a real API.
                  </p>
                </div>

                <Button
                  onClick={handleClose}
                  className="w-full bg-[#00ff88] hover:bg-[#00ff88]/80 text-gray-900 font-semibold"
                >
                  Get Started
                </Button>
              </CardContent>
            </Card>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}