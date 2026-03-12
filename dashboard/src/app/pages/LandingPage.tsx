import { Shield, Upload, PenLine, Activity } from 'lucide-react';
import { Link } from 'react-router';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { motion } from 'motion/react';
import { APIDocumentation } from '../components/APIDocumentation';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14]">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-16">
        <motion.div 
          className="text-center mb-16"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="flex justify-center mb-6">
            <motion.div
              animate={{ 
                boxShadow: [
                  '0 0 20px rgba(0, 255, 136, 0.5)',
                  '0 0 40px rgba(0, 255, 136, 0.8)',
                  '0 0 20px rgba(0, 255, 136, 0.5)',
                ]
              }}
              transition={{ duration: 2, repeat: Infinity }}
              className="rounded-full p-4 bg-[#0f1825]/80 backdrop-blur"
            >
              <Shield className="w-16 h-16 text-[#00ff88]" />
            </motion.div>
          </div>
          
          <h1 className="text-5xl md:text-7xl font-bold mb-4 bg-gradient-to-r from-[#00ff88] via-[#00ccff] to-[#00ff88] bg-clip-text text-transparent">
            Cyber Threat Detection Dashboard
          </h1>
          
          <p className="text-xl md:text-2xl text-gray-300 mb-8">
            AI-powered real-time network anomaly detection
          </p>

          <div className="flex justify-center gap-4 flex-wrap">
            <Link to="/analytics">
              <Button className="bg-[#00ff88] hover:bg-[#00ff88]/80 text-gray-900 font-semibold">
                <Activity className="mr-2 h-5 w-5" />
                View Dashboard
              </Button>
            </Link>
            <Link to="/manual">
              <Button variant="outline" className="border-[#00ccff] text-[#00ccff] hover:bg-[#00ccff]/10">
                Quick Analysis
              </Button>
            </Link>
          </div>
        </motion.div>

        {/* Action Cards */}
        <div className="grid md:grid-cols-2 gap-8 max-w-5xl mx-auto mt-20">
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            <Card className="bg-[#0f1825]/70 border-[#1a2540] hover:border-[#00ff88]/50 transition-all duration-300 h-full backdrop-blur">
              <CardHeader>
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-3 rounded-lg bg-[#00ff88]/20">
                    <Upload className="w-8 h-8 text-[#00ff88]" />
                  </div>
                  <CardTitle className="text-2xl text-white">Batch Analysis</CardTitle>
                </div>
                <CardDescription className="text-gray-400">
                  Upload files for comprehensive network traffic analysis
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 mb-6 text-gray-300">
                  <li className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88]"></span>
                    Process multiple records simultaneously
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88]"></span>
                    Support for CSV, PCAP, PCAPNG, JSON, LOG files up to 10MB
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88]"></span>
                    Preview data before processing
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88]"></span>
                    Export results in CSV format
                  </li>
                </ul>
                <Link to="/upload">
                  <Button className="w-full bg-[#00ff88]/20 hover:bg-[#00ff88]/30 text-[#00ff88] border border-[#00ff88]/50">
                    <Upload className="mr-2 h-4 w-4" />
                    Upload File
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
          >
            <Card className="bg-[#0f1825]/70 border-[#1a2540] hover:border-[#00ccff]/50 transition-all duration-300 h-full backdrop-blur">
              <CardHeader>
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-3 rounded-lg bg-[#00ccff]/20">
                    <PenLine className="w-8 h-8 text-[#00ccff]" />
                  </div>
                  <CardTitle className="text-2xl text-white">Manual Input</CardTitle>
                </div>
                <CardDescription className="text-gray-400">
                  Analyze individual network connections in real-time
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 mb-6 text-gray-300">
                  <li className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00ccff]"></span>
                    Instant threat prediction results
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00ccff]"></span>
                    Real-time validation and feedback
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00ccff]"></span>
                    Confidence score analysis
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00ccff]"></span>
                    Severity level classification
                  </li>
                </ul>
                <Link to="/manual">
                  <Button className="w-full bg-[#00ccff]/20 hover:bg-[#00ccff]/30 text-[#00ccff] border border-[#00ccff]/50">
                    <PenLine className="mr-2 h-4 w-4" />
                    Manual Entry Form
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </motion.div>
        </div>

        {/* Features Section */}
        <motion.div 
          className="mt-20 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.6 }}
        >
          <h2 className="text-3xl font-bold text-white mb-8">Key Features</h2>
          <div className="grid md:grid-cols-4 gap-6">
            {[
              { icon: Shield, title: 'AI Detection', description: 'Machine learning powered threat analysis' },
              { icon: Activity, title: 'Real-time Monitoring', description: 'Live network traffic analysis' },
              { icon: Upload, title: 'Batch Processing', description: 'Process large datasets efficiently' },
              { icon: PenLine, title: 'Custom Inputs', description: 'Manual entry for specific cases' }
            ].map((feature, idx) => (
              <motion.div
                key={idx}
                className="p-6 rounded-lg bg-[#0f1825]/50 border border-[#1a2540] hover:border-[#00ff88]/50 hover:bg-[#0f1825]/80 transition-all duration-300"
              >
                <feature.icon className="w-10 h-10 text-[#00ff88] mx-auto mb-3" />
                <h3 className="text-lg font-semibold text-white mb-2">{feature.title}</h3>
                <p className="text-sm text-gray-400">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* API Documentation Section */}
        <motion.div 
          className="mt-20 max-w-4xl mx-auto"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.8 }}
        >
          <APIDocumentation />
        </motion.div>

        {/* Footer Info */}
        <motion.div 
          className="mt-20 text-center pb-12"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 1 }}
        >
          <div className="inline-block p-6 bg-[#0f1825]/50 border border-[#1a2540] rounded-lg">
            <p className="text-gray-400 mb-2">
              <strong className="text-white">Keyboard Shortcuts:</strong>
            </p>
            <div className="flex gap-4 text-sm text-gray-500">
              <span><kbd className="px-2 py-1 bg-[#1a2540] rounded text-[#00ff88]">Ctrl+U</kbd> Upload</span>
              <span><kbd className="px-2 py-1 bg-[#1a2540] rounded text-[#00ff88]">Ctrl+M</kbd> Manual</span>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}