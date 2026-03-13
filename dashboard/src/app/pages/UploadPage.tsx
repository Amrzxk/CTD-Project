import { useState, useRef, useEffect, useCallback } from 'react';
import {
  Upload, File, X, CheckCircle, Download, CloudUpload, FileSearch,
  Shield, AlertTriangle, Info, ChevronRight, Cpu, Brain, Network, Search as SearchIcon
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Progress } from '../components/ui/progress';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'motion/react';
import { threatService } from '../services/threatDetectionService';
import { parseCSV, validateCSVStructure, downloadFile, generateSampleCSV } from '../utils/helpers';
import type { ThreatPrediction, AnalyzedPacket } from '../types/threat';
import { useNavigate } from 'react-router';

const SUPPORTED_EXTENSIONS = ['.pcap', '.pcapng', '.csv', '.xlsx', '.xls'];
const ACCEPT_STRING = SUPPORTED_EXTENSIONS.join(',');

// Processing step definitions
const PROCESSING_STEPS = [
  { id: 'parse', label: 'Parsing packet capture', icon: FileSearch },
  { id: 'extract', label: 'Extracting network flows', icon: Network },
  { id: 'features', label: 'Generating ML features', icon: Cpu },
  { id: 'detect', label: 'Running AI threat detection', icon: Brain },
];

export default function UploadPage() {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState(-1);
  const [preview, setPreview] = useState<string[][] | null>(null);
  const [results, setResults] = useState<ThreatPrediction[] | null>(null);
  const [analyzedPackets, setAnalyzedPackets] = useState<AnalyzedPacket[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<AnalyzedPacket | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    handleFileSelection(e.dataTransfer.files[0]);
  };

  const handleFileSelection = (selectedFile: File | undefined) => {
    if (!selectedFile) return;
    const fileName = selectedFile.name.toLowerCase();
    const isSupported = SUPPORTED_EXTENSIONS.some(ext => fileName.endsWith(ext));
    if (!isSupported) {
      toast.error(`Unsupported file type. Accepted: ${SUPPORTED_EXTENSIONS.join(', ')}`);
      return;
    }
    if (selectedFile.size > 10 * 1024 * 1024) {
      toast.error('File size exceeds 10MB limit.');
      return;
    }
    setFile(selectedFile);
    setResults(null);
    setAnalyzedPackets([]);
    setSelectedPacket(null);
    setCurrentStep(-1);

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      const rows = parseCSV(content);
      const validation = validateCSVStructure(rows);
      if (!validation.valid) {
        toast.error(validation.error || 'Invalid file structure');
        setFile(null);
        return;
      }
      setPreview(rows.slice(0, 6));
      toast.success('File loaded successfully. Ready for analysis.');
    };
    reader.readAsText(selectedFile);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    handleFileSelection(e.target.files?.[0]);
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setProgress(0);
    setCurrentStep(0);

    // Simulate step-by-step progress
    const stepDuration = 500;
    for (let i = 0; i < PROCESSING_STEPS.length; i++) {
      setCurrentStep(i);
      const targetProgress = ((i + 1) / PROCESSING_STEPS.length) * 90;
      const startProgress = (i / PROCESSING_STEPS.length) * 90;
      const steps = 5;
      for (let j = 1; j <= steps; j++) {
        await new Promise(r => setTimeout(r, stepDuration / steps));
        setProgress(Math.round(startProgress + ((targetProgress - startProgress) * j) / steps));
      }
    }

    try {
      const result = await threatService.predictBatch(file);
      setProgress(100);
      setCurrentStep(PROCESSING_STEPS.length);
      setResults(result.predictions);
      const packets = threatService.generateAnalyzedPackets(result.predictions);
      setAnalyzedPackets(packets);
      toast.success(`Successfully processed ${result.total} records!`);
      const maliciousCount = result.predictions.filter(p => p.prediction === 'Malicious').length;
      if (maliciousCount > 0) {
        toast.warning(`Detected ${maliciousCount} malicious connections!`, { duration: 5000 });
      }
    } catch (error) {
      toast.error('Failed to process file. Please try again.');
      console.error(error);
    } finally {
      setUploading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setPreview(null);
    setResults(null);
    setAnalyzedPackets([]);
    setSelectedPacket(null);
    setProgress(0);
    setCurrentStep(-1);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleExportResults = () => {
    if (!results) return;
    const csv = threatService.exportToCSV(results);
    const timestamp = new Date().toISOString().split('T')[0];
    downloadFile(csv, `threat-detection-results-${timestamp}.csv`);
    toast.success('Results exported successfully!');
  };

  const handleDownloadSample = () => {
    const sample = generateSampleCSV();
    downloadFile(sample, 'sample-network-data.csv');
    toast.success('Sample CSV downloaded!');
  };

  const getPredictionColor = (p: AnalyzedPacket['prediction']) => {
    if (p === 'Normal') return 'text-[#00ff88]';
    if (p === 'Malicious') return 'text-[#ff3366]';
    return 'text-yellow-400';
  };

  const getPredictionBg = (p: AnalyzedPacket['prediction']) => {
    if (p === 'Normal') return 'bg-[#00ff88]/5';
    if (p === 'Malicious') return 'bg-[#ff3366]/8';
    return 'bg-yellow-400/5';
  };

  const getPredictionBadge = (p: AnalyzedPacket['prediction']) => {
    if (p === 'Normal') return 'bg-[#00ff88]/15 text-[#00ff88] border-[#00ff88]/40';
    if (p === 'Malicious') return 'bg-[#ff3366]/15 text-[#ff3366] border-[#ff3366]/40';
    return 'bg-yellow-400/15 text-yellow-400 border-yellow-400/40';
  };

  const getRiskBadge = (r: AnalyzedPacket['risk_level']) => {
    const map: Record<string, string> = {
      Critical: 'bg-[#ff3366]/20 text-[#ff3366] border-[#ff3366]/50',
      High: 'bg-red-500/15 text-red-400 border-red-500/40',
      Medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
      Low: 'bg-[#00ccff]/15 text-[#00ccff] border-[#00ccff]/40',
      None: 'bg-gray-700/30 text-gray-400 border-gray-600/40',
    };
    return map[r] || map.None;
  };

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
        + '.' + d.getMilliseconds().toString().padStart(3, '0');
    } catch {
      return ts;
    }
  };

  // Whether to show the full-width packet analyzer
  const showAnalyzer = results && analyzedPackets.length > 0;

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] py-12">
      <div className="container mx-auto px-4">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          {/* Page Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-4xl font-bold text-white mb-2">Batch Analysis</h1>
              <p className="text-gray-400">Upload network packet files for comprehensive traffic analysis</p>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={handleDownloadSample}
                className="border-[#00ccff] text-[#00ccff] hover:bg-[#00ccff]/10"
              >
                <Download className="mr-2 h-4 w-4" />
                Download Sample CSV
              </Button>
            </div>
          </div>

          {/* Two-column layout */}
          <div className="grid lg:grid-cols-2 gap-8">
            {/* ─── LEFT: Upload Card ─── */}
            <Card
              className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur overflow-hidden"
            >
              <CardContent className="p-8">
                {/* Title */}
                <div className="text-center mb-6">
                  <motion.div
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.15, duration: 0.4 }}
                    className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-4"
                    style={{
                      background: 'linear-gradient(135deg, rgba(0,255,136,0.1), rgba(0,204,255,0.06))',
                      boxShadow: '0 0 20px rgba(0,255,136,0.06)',
                    }}
                  >
                    <CloudUpload className="w-7 h-7 text-[#00ff88]" />
                  </motion.div>
                  <h2 className="text-2xl font-bold text-white mb-1">Upload Network Packet File</h2>
                  <p className="text-sm text-gray-400">AI-powered threat detection analysis</p>
                </div>

                {/* Drop zone – no file */}
                {!file && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                  >
                    <div
                      onDragOver={handleDragOver}
                      onDragLeave={handleDragLeave}
                      onDrop={handleDrop}
                      onClick={() => fileInputRef.current?.click()}
                      className={`
                        relative border-2 border-dashed rounded-xl p-10 text-center
                        transition-all duration-300 cursor-pointer group
                        ${isDragging
                          ? 'border-[#00ff88]/70 bg-[#00ff88]/[0.04]'
                          : 'border-gray-600/50 hover:border-[#00ff88]/30 hover:bg-[#00ff88]/[0.015]'
                        }
                      `}
                      style={{
                        boxShadow: isDragging
                          ? '0 0 20px rgba(0,255,136,0.05) inset'
                          : 'none',
                      }}
                    >
                      <motion.div
                        animate={isDragging ? { scale: 1.08, y: -4 } : { scale: 1, y: 0 }}
                        transition={{ type: 'spring', stiffness: 300, damping: 20 }}
                      >
                        <Upload className={`w-12 h-12 mx-auto mb-4 transition-colors duration-300 ${isDragging ? 'text-[#00ff88]' : 'text-gray-500 group-hover:text-[#00ff88]/70'}`} />
                      </motion.div>
                      <p className="text-lg text-gray-200 mb-1.5">Drag & Drop your network packet file here</p>
                      <p className="text-gray-500 mb-5">or</p>
                      <Button
                        type="button"
                        className="bg-[#00ff88] hover:bg-[#00ff88]/85 text-gray-900 font-semibold px-8 py-2.5 rounded-lg"
                        style={{ boxShadow: '0 0 12px rgba(0,255,136,0.15)' }}
                        onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }}
                      >
                        <Upload className="mr-2 h-4 w-4" />
                        Browse Files
                      </Button>
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept={ACCEPT_STRING}
                        onChange={handleFileInputChange}
                        className="hidden"
                      />
                      <div className="mt-6 flex items-center justify-center gap-2 flex-wrap">
                        {SUPPORTED_EXTENSIONS.map((ext, i) => (
                          <span key={ext} className="flex items-center gap-2">
                            <span className="px-2.5 py-1 rounded-md text-xs font-mono bg-gray-700/60 text-[#00ccff] border border-gray-600/50">{ext}</span>
                            {i < SUPPORTED_EXTENSIONS.length - 1 && <span className="text-gray-600">•</span>}
                          </span>
                        ))}
                      </div>
                      <p className="text-xs text-gray-500 mt-3">Supports Wireshark packet captures and network traffic files.</p>
                      <p className="text-xs text-gray-600 mt-1">Maximum file size: 10MB</p>
                    </div>
                  </motion.div>
                )}

                {/* File selected state */}
                {file && (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
                    {/* File bar */}
                    <div className="flex items-center justify-between p-3.5 rounded-xl border border-gray-700/60" style={{ background: 'rgba(0,255,136,0.03)' }}>
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-[#00ff88]/10">
                          <File className="w-5 h-5 text-[#00ff88]" />
                        </div>
                        <div>
                          <p className="text-white font-medium text-sm">{file.name}</p>
                          <p className="text-xs text-gray-400">{(file.size / 1024).toFixed(2)} KB</p>
                        </div>
                      </div>
                      <Button variant="ghost" size="sm" onClick={handleReset} disabled={uploading} className="text-gray-400 hover:text-white hover:bg-gray-700/50">
                        <X className="w-4 h-4" />
                      </Button>
                    </div>

                    {/* Processing steps */}
                    {uploading && (
                      <div className="space-y-3">
                        <div className="flex justify-between text-sm">
                          <span className="text-gray-400">Processing...</span>
                          <span className="text-[#00ff88] font-mono">{progress}%</span>
                        </div>
                        <Progress value={progress} className="h-2" />
                        <div className="space-y-2 pt-1">
                          {PROCESSING_STEPS.map((step, i) => {
                            const StepIcon = step.icon;
                            const isActive = i === currentStep;
                            const isDone = i < currentStep;
                            return (
                              <motion.div
                                key={step.id}
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: i * 0.1 }}
                                className={`flex items-center gap-3 p-2.5 rounded-lg transition-colors ${
                                  isActive ? 'bg-[#00ff88]/10 border border-[#00ff88]/30' :
                                  isDone ? 'bg-gray-800/30' : 'opacity-40'
                                }`}
                              >
                                {isDone ? (
                                  <CheckCircle className="w-4 h-4 text-[#00ff88] shrink-0" />
                                ) : isActive ? (
                                  <StepIcon className="w-4 h-4 text-[#00ff88] shrink-0 animate-pulse" />
                                ) : (
                                  <StepIcon className="w-4 h-4 text-gray-600 shrink-0" />
                                )}
                                <span className={`text-sm ${isDone ? 'text-[#00ff88]' : isActive ? 'text-white' : 'text-gray-500'}`}>
                                  {step.label}
                                </span>
                                {isDone && <span className="text-xs text-[#00ff88]/60 ml-auto">Done</span>}
                              </motion.div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Results summary on left */}
                    {results && !uploading && (
                      <div className="space-y-4">
                        <div className="flex items-center gap-3 p-3 rounded-xl bg-[#00ff88]/10 border border-[#00ff88]/30">
                          <CheckCircle className="w-5 h-5 text-[#00ff88] shrink-0" />
                          <div>
                            <p className="text-[#00ff88] font-semibold text-sm">Analysis Complete</p>
                            <p className="text-xs text-gray-400">{results.length} packets analyzed</p>
                          </div>
                        </div>
                        <div className="grid grid-cols-3 gap-3">
                          <div className="p-3 rounded-xl bg-[#00ff88]/5 border border-[#00ff88]/20 text-center">
                            <p className="text-xl font-bold text-[#00ff88]">{analyzedPackets.filter(p => p.prediction === 'Normal').length}</p>
                            <p className="text-xs text-gray-400 mt-0.5">Normal</p>
                          </div>
                          <div className="p-3 rounded-xl bg-[#ff3366]/5 border border-[#ff3366]/20 text-center">
                            <p className="text-xl font-bold text-[#ff3366]">{analyzedPackets.filter(p => p.prediction === 'Malicious').length}</p>
                            <p className="text-xs text-gray-400 mt-0.5">Malicious</p>
                          </div>
                          <div className="p-3 rounded-xl bg-yellow-400/5 border border-yellow-400/20 text-center">
                            <p className="text-xl font-bold text-yellow-400">{analyzedPackets.filter(p => p.prediction === 'Suspicious').length}</p>
                            <p className="text-xs text-gray-400 mt-0.5">Suspicious</p>
                          </div>
                        </div>
<<<<<<< HEAD
                        <div className="grid grid-cols-2 gap-3 mb-3">
=======
                        <div className="grid grid-cols-2 gap-3">
>>>>>>> 260c5da33751fd3b387bc26d584989d6a0489685
                          <Button onClick={handleExportResults} className="bg-[#00ccff]/15 hover:bg-[#00ccff]/25 text-[#00ccff] border border-[#00ccff]/40">
                            <Download className="mr-2 h-4 w-4" />Export
                          </Button>
                          <Button onClick={() => navigate('/dashboard')} className="bg-[#00ff88]/15 hover:bg-[#00ff88]/25 text-[#00ff88] border border-[#00ff88]/40">
                            Dashboard
                          </Button>
                        </div>
<<<<<<< HEAD
                        <Button onClick={() => navigate('/analytics')} className="w-full bg-[#00ff88] hover:bg-[#00ff88]/85 text-gray-900 font-semibold mb-3">
                          View Analysis
                        </Button>
=======
>>>>>>> 260c5da33751fd3b387bc26d584989d6a0489685
                        <Button onClick={handleReset} variant="outline" className="w-full border-gray-600/70 text-gray-400 hover:text-white hover:bg-gray-700/30">
                          Upload Another File
                        </Button>
                      </div>
                    )}

                    {/* Analyze button */}
                    {!results && !uploading && (
                      <Button
                        onClick={handleUpload}
                        className="w-full bg-[#00ff88] hover:bg-[#00ff88]/85 text-gray-900 font-semibold py-3 rounded-lg"
                        style={{ boxShadow: '0 0 24px rgba(0,255,136,0.15)' }}
                      >
                        Analyze File
                      </Button>
                    )}
                  </motion.div>
                )}
              </CardContent>
            </Card>

            {/* ─── RIGHT: Data Preview / Packet Analyzer ─── */}
            <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur overflow-hidden">
              <CardHeader className="pb-3">
                <CardTitle className="text-white flex items-center gap-2">
                  {showAnalyzer ? (
                    <>
                      <Shield className="w-5 h-5 text-[#00ff88]" />
                      Packet Analyzer
                    </>
                  ) : (
                    <>
                      <FileSearch className="w-5 h-5 text-[#00ccff]" />
                      Data Preview
                    </>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                {/* Empty state */}
                {!preview && !showAnalyzer && (
                  <div className="text-center py-16">
                    <SearchIcon className="w-12 h-12 mx-auto mb-4 text-gray-700" />
                    <p className="text-gray-500">No file selected</p>
                    <p className="text-sm text-gray-600 mt-1">Upload a packet file to preview data</p>
                  </div>
                )}

                {/* CSV preview before analysis */}
                {preview && !showAnalyzer && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                    <div className="text-xs text-gray-500 mb-2">First 5 rows</div>
                    <div className="rounded-lg border border-gray-700/60 overflow-hidden">
                      <div className="overflow-x-auto max-h-[340px]">
                        <table className="w-full text-xs">
                          <thead className="sticky top-0 z-10">
                            <tr className="border-b border-gray-700/60 bg-gray-800/80">
                              {preview[0].map((header, idx) => (
                                <th key={idx} className="text-left p-2.5 text-[#00ff88] font-semibold whitespace-nowrap">{header}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {preview.slice(1).map((row, rowIdx) => (
                              <tr key={rowIdx} className="border-b border-gray-700/30 hover:bg-gray-700/20">
                                {row.map((cell, cellIdx) => (
                                  <td key={cellIdx} className="p-2.5 text-gray-300 whitespace-nowrap font-mono">{cell}</td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </motion.div>
                )}

                {/* Packet Analyzer */}
                {showAnalyzer && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
                    {/* Section 1: Packet List Table */}
                    <div className="rounded-lg border border-gray-700/60 overflow-hidden">
                      <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/60 border-b border-gray-700/60">
                        <Network className="w-3.5 h-3.5 text-[#00ccff]" />
                        <span className="text-xs font-semibold text-gray-300">Packet List</span>
                        <span className="text-xs text-gray-500 ml-auto">{analyzedPackets.length} packets</span>
                      </div>
                      <div className="overflow-x-auto max-h-[220px] overflow-y-auto">
                        <table className="w-full text-xs">
                          <thead className="sticky top-0 z-10">
                            <tr className="bg-gray-900/80 border-b border-gray-700/60">
                              {['Time', 'Source', 'Destination', 'Proto', 'SrcPort', 'DstPort', 'Length', 'Prediction', 'Risk'].map(h => (
                                <th key={h} className="text-left p-2 text-[#00ff88]/80 font-semibold whitespace-nowrap">{h}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {analyzedPackets.map((pkt) => (
                              <tr
                                key={pkt.id}
                                onClick={() => setSelectedPacket(pkt)}
                                className={`border-b border-gray-700/30 cursor-pointer transition-colors
                                  ${selectedPacket?.id === pkt.id ? 'ring-1 ring-inset ring-[#00ccff]/60 bg-[#00ccff]/5' : `${getPredictionBg(pkt.prediction)} hover:bg-gray-700/20`}
                                `}
                              >
                                <td className="p-2 text-gray-400 font-mono whitespace-nowrap">{formatTimestamp(pkt.timestamp)}</td>
                                <td className="p-2 text-gray-300 font-mono whitespace-nowrap">{pkt.src_ip}</td>
                                <td className="p-2 text-gray-300 font-mono whitespace-nowrap">{pkt.dst_ip}</td>
                                <td className="p-2 text-gray-300 whitespace-nowrap">{pkt.protocol}</td>
                                <td className="p-2 text-gray-400 whitespace-nowrap">{pkt.src_port}</td>
                                <td className="p-2 text-gray-400 whitespace-nowrap">{pkt.dst_port}</td>
                                <td className="p-2 text-gray-400 whitespace-nowrap">{pkt.packet_length}</td>
                                <td className="p-2 whitespace-nowrap">
                                  <Badge variant="outline" className={`text-[10px] py-0 ${getPredictionBadge(pkt.prediction)}`}>{pkt.prediction}</Badge>
                                </td>
                                <td className="p-2 whitespace-nowrap">
                                  <Badge variant="outline" className={`text-[10px] py-0 ${getRiskBadge(pkt.risk_level)}`}>{pkt.risk_level}</Badge>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {/* Section 2 & 3: Packet Details + AI Explanation */}
                    <AnimatePresence mode="wait">
                      {selectedPacket ? (
                        <motion.div
                          key={selectedPacket.id}
                          initial={{ opacity: 0, y: 8 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -8 }}
                          transition={{ duration: 0.2 }}
                          className="grid md:grid-cols-2 gap-4"
                        >
                          {/* Packet Details */}
                          <div className="rounded-lg border border-gray-700/60 overflow-hidden">
                            <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/60 border-b border-gray-700/60">
                              <Info className="w-3.5 h-3.5 text-[#00ccff]" />
                              <span className="text-xs font-semibold text-gray-300">Packet Details</span>
                            </div>
                            <div className="p-3 space-y-1.5 max-h-[240px] overflow-y-auto">
                              {[
                                { label: 'Source IP', value: selectedPacket.src_ip },
                                { label: 'Destination IP', value: selectedPacket.dst_ip },
                                { label: 'Source Port', value: selectedPacket.src_port },
                                { label: 'Destination Port', value: selectedPacket.dst_port },
                                { label: 'Protocol', value: selectedPacket.protocol },
                                { label: 'Packet Size', value: `${selectedPacket.packet_length} bytes` },
                                { label: 'TTL', value: selectedPacket.ttl },
                                { label: 'Flags', value: selectedPacket.flags },
                                { label: 'Duration', value: `${selectedPacket.duration}s` },
                              ].map(item => (
                                <div key={item.label} className="flex justify-between items-center py-1 border-b border-gray-700/30 last:border-0">
                                  <span className="text-xs text-gray-500">{item.label}</span>
                                  <span className={`text-xs font-mono ${getPredictionColor(selectedPacket.prediction)}`}>{item.value}</span>
                                </div>
                              ))}

                              {/* ML Features */}
                              <div className="pt-2">
                                <p className="text-xs text-[#00ccff] font-semibold mb-1.5 flex items-center gap-1">
                                  <Cpu className="w-3 h-3" /> ML Feature Values
                                </p>
                                <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                                  {Object.entries(selectedPacket.mlFeatures).map(([key, val]) => (
                                    <div key={key} className="flex justify-between items-center">
                                      <span className="text-[10px] text-gray-500 font-mono">{key}</span>
                                      <span className="text-[10px] text-gray-300 font-mono">{typeof val === 'number' ? val.toLocaleString() : val}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* AI Feature Explanation */}
                          <div className="rounded-lg border border-gray-700/60 overflow-hidden">
                            <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/60 border-b border-gray-700/60">
                              <Brain className="w-3.5 h-3.5 text-[#00ccff]" />
                              <span className="text-xs font-semibold text-gray-300">AI Explanation</span>
                            </div>
                            <div className="p-3 space-y-2 max-h-[240px] overflow-y-auto">
                              <div className="flex items-center gap-2 mb-2">
                                <Badge variant="outline" className={getPredictionBadge(selectedPacket.prediction)}>
                                  {selectedPacket.prediction}
                                </Badge>
                                <Badge variant="outline" className={getRiskBadge(selectedPacket.risk_level)}>
                                  Risk: {selectedPacket.risk_level}
                                </Badge>
                              </div>
                              {selectedPacket.aiExplanations.map((explanation, i) => (
                                <motion.div
                                  key={i}
                                  initial={{ opacity: 0, x: -6 }}
                                  animate={{ opacity: 1, x: 0 }}
                                  transition={{ delay: i * 0.08 }}
                                  className={`flex items-start gap-2 p-2.5 rounded-lg border ${
                                    selectedPacket.prediction === 'Malicious'
                                      ? 'bg-[#ff3366]/5 border-[#ff3366]/20'
                                      : selectedPacket.prediction === 'Suspicious'
                                        ? 'bg-yellow-400/5 border-yellow-400/20'
                                        : 'bg-[#00ff88]/5 border-[#00ff88]/20'
                                  }`}
                                >
                                  {selectedPacket.prediction === 'Normal' ? (
                                    <Shield className="w-3.5 h-3.5 text-[#00ff88] shrink-0 mt-0.5" />
                                  ) : (
                                    <AlertTriangle className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${selectedPacket.prediction === 'Malicious' ? 'text-[#ff3366]' : 'text-yellow-400'}`} />
                                  )}
                                  <span className="text-xs text-gray-300">{explanation}</span>
                                </motion.div>
                              ))}

                              {/* Confidence note */}
                              <div className="pt-2 border-t border-gray-700/40 mt-2">
                                <p className="text-[10px] text-gray-500 italic">
                                  Analysis powered by ensemble ML model with feature importance scoring.
                                  {selectedPacket.prediction !== 'Normal' && ' Manual review recommended for flagged packets.'}
                                </p>
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      ) : (
                        <motion.div
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          className="text-center py-6 rounded-lg border border-dashed border-gray-700/50"
                        >
                          <ChevronRight className="w-8 h-8 mx-auto text-gray-700 mb-2" />
                          <p className="text-sm text-gray-500">Select a packet row above to inspect details</p>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                )}
              </CardContent>
            </Card>
          </div>
        </motion.div>
      </div>
    </div>
  );
}