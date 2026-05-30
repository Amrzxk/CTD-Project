import { useState, useRef, useEffect, useCallback } from 'react';
import {
  Upload, File, X, CheckCircle, Download, CloudUpload, FileSearch,
  Shield, AlertTriangle, Info, ChevronRight, Cpu, Brain, Network, Search as SearchIcon
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Progress } from '../components/ui/progress';
import { Badge } from '../components/ui/badge';
import { RiskBadge, severityToRisk } from '../components/RiskBadge';
import { ConfidenceQuality } from '../components/ConfidenceQuality';
import { StageProbBars } from '../components/StageProbBars';
import { VerdictBadge } from '../components/VerdictBadge';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'motion/react';
import { threatService } from '../services/threatDetectionService';
import { parseCSV, validateCSVStructure, downloadFile, generateSampleCSV } from '../utils/helpers';
import type { ThreatPrediction, ThreatPredictionSummary, ThreatSource } from '../types/threat';

type VerdictFilter = 'all' | ThreatSource;
const VERDICT_FILTER_KEY = 'hids.upload.verdictFilter';
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
  // `results` is the single source of truth for the analyzed table. Holding
  // the slim summary shape (no `stage2_probs` / `stage3_probs` /
  // `mlFeatures` / `mitre.techniques`) — the heavy fields are fetched
  // on demand via the detail endpoint when the drawer opens. We used to
  // also build an `analyzedPackets` duplicate here which doubled memory
  // at 82k flows; that's gone now.
  const [results, setResults] = useState<ThreatPredictionSummary[] | null>(null);
  // Batch metadata so the summary tiles stay accurate even when the row list
  // is capped for the browser on a large upload (the full set lives in the DB).
  const [batchMeta, setBatchMeta] = useState<{
    total: number;
    returned: number;
    counts?: import('../types/threat').BatchCounts;
  } | null>(null);
  const [selectedRow, setSelectedRow] = useState<ThreatPredictionSummary | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<ThreatPrediction | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [stageDetail, setStageDetail] = useState<string>('');
  // Pagination keeps the rendered table at <= ROWS_PER_PAGE DOM rows so
  // 80k-flow PCAPs don't crash the browser.
  const ROWS_PER_PAGE = 100;
  const [tablePage, setTablePage] = useState(1);
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>(() => {
    if (typeof window === 'undefined') return 'all';
    const stored = window.localStorage.getItem(VERDICT_FILTER_KEY) as VerdictFilter | null;
    return stored ?? 'all';
  });
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(VERDICT_FILTER_KEY, verdictFilter);
    }
    // Reset to the first page whenever the filter or dataset changes —
    // otherwise the user can land on page 87 of a now-empty filter cell.
    setTablePage(1);
  }, [verdictFilter, results]);

  // Lazy-load the full prediction (with stage2_probs, stage3_probs,
  // mlFeatures, mitre.techniques) whenever the analyst opens a row.
  // Cached on the service so repeat opens are free.
  useEffect(() => {
    if (!selectedRow) {
      setSelectedDetail(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    threatService
      .getPredictionDetail(selectedRow.id)
      .then((full) => {
        if (!cancelled) setSelectedDetail(full);
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedDetail(null);
          toast.error('Failed to load prediction detail');
        }
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedRow]);

  // Verdict-source filter applied to the packet list. Counts also feed the
  // filter pill labels so the analyst can see how many flows fall in each cell.
  const allPackets = results ?? [];
  const verdictCounts = allPackets.reduce(
    (acc, pkt) => {
      const v = (pkt.source as ThreatSource | undefined) ?? 'benign';
      acc[v] = (acc[v] ?? 0) + 1;
      return acc;
    },
    {} as Record<ThreatSource, number>,
  );
  const filteredPackets =
    verdictFilter === 'all'
      ? allPackets
      : allPackets.filter((p) => (p.source ?? 'benign') === verdictFilter);
  const totalPages = Math.max(1, Math.ceil(filteredPackets.length / ROWS_PER_PAGE));
  const safePage = Math.min(tablePage, totalPages);
  const pageStart = (safePage - 1) * ROWS_PER_PAGE;
  // displayedPackets is now just the current page's slice — keeps DOM size
  // bounded regardless of how many flows the PCAP produces.
  const displayedPackets = filteredPackets.slice(pageStart, pageStart + ROWS_PER_PAGE);
  // Convenience: prefer the lazily-loaded detail when its id matches the
  // currently-selected row; fall back to the summary so the drawer can
  // render most fields immediately.
  const drawerData: ThreatPrediction | ThreatPredictionSummary | null =
    selectedDetail && selectedRow && selectedDetail.id === selectedRow.id
      ? selectedDetail
      : selectedRow;

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
    setFile(selectedFile);
    setResults(null);
    setBatchMeta(null);
    setSelectedRow(null);
    setSelectedDetail(null);
    setCurrentStep(-1);
    setPreview(null);

    // Binary capture files (PCAP / PCAPng) — don't try to read them as text
    // or run parseCSV; the preview panel will fall back to the placeholder.
    const isBinary = fileName.endsWith('.pcap') || fileName.endsWith('.pcapng');
    if (isBinary) {
      toast.success('PCAP loaded. Ready for analysis.');
      return;
    }

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
    setStageDetail('Uploading file…');

    // Map backend stage events from /analyze/upload/stream into the
    // 4-step progress UI. Stage names are documented in app/api/routes.py
    // analyze_upload_stream.
    try {
      const result = await threatService.predictBatch(file, (evt) => {
        if (evt.event !== 'stage') return;
        const e = evt as { event: 'stage'; stage: string; [k: string]: any };
        switch (e.stage) {
          case 'received':
            setCurrentStep(0);
            setProgress(5);
            setStageDetail(`Received ${(e.sizeMB ?? 0).toFixed?.(1) || e.sizeMB} MB · queued for extraction`);
            break;
          case 'snort_start':
            setStageDetail('Snort signature replay running in parallel');
            break;
          case 'extract_start':
            setCurrentStep(1);
            setProgress(10);
            setStageDetail('Extracting network flows via NFStream');
            break;
          case 'nfstream:flow':
          case 'extract_progress': {
            const n = (e.count as number) ?? 0;
            // 10% → 50% scaled against an expected-magnitude target so
            // we never appear stuck. Caps at 50% so extract_done can
            // overshoot it cleanly.
            const pct = Math.min(50, 10 + Math.log10(Math.max(n, 1)) * 8);
            setProgress(Math.round(pct));
            setStageDetail(`Extracted ${n.toLocaleString()} flows…`);
            break;
          }
          case 'extract_done':
          case 'nfstream:done': {
            setProgress(55);
            const flows = (e.flows ?? e.count) as number | undefined;
            const ms = e.elapsedMs as number | undefined;
            setStageDetail(
              flows !== undefined
                ? `Extracted ${flows.toLocaleString()} flows${ms ? ` in ${(ms / 1000).toFixed(1)}s` : ''}`
                : 'Flow extraction complete',
            );
            break;
          }
          case 'predict_start':
            setCurrentStep(2);
            setProgress(65);
            setStageDetail(`Running 3-tier hierarchical ML on ${((e.total as number) ?? 0).toLocaleString()} flows`);
            break;
          case 'predict_done':
            setCurrentStep(3);
            setProgress(80);
            setStageDetail('ML inference complete · waiting on Snort');
            break;
          case 'snort_done': {
            const alerts = (e.alerts as number) ?? 0;
            const ms = e.elapsedMs as number | undefined;
            setProgress(90);
            setStageDetail(
              `Snort matched ${alerts.toLocaleString()} alert flows${ms ? ` in ${(ms / 1000).toFixed(1)}s` : ''}`,
            );
            break;
          }
          case 'format_start':
            setProgress(95);
            setStageDetail('Building hybrid verdicts + MITRE enrichment');
            break;
          default:
            break;
        }
      });
      setProgress(100);
      setCurrentStep(PROCESSING_STEPS.length);
      setStageDetail(`Done · ${result.total.toLocaleString()} flows analysed`);
      // result.predictions is already the slim summary shape — render
      // straight from it instead of building a duplicate AnalyzedPacket[]
      // array (which was the main cause of the 82k-flow OOM crash).
      setResults(result.predictions);
      setBatchMeta({
        total: result.total,
        returned: result.returned ?? result.predictions.length,
        counts: result.counts,
      });
      setSelectedRow(null);
      setSelectedDetail(null);
      toast.success(`Successfully processed ${result.total.toLocaleString()} records!`);
      const maliciousCount = result.counts?.malicious
        ?? result.predictions.filter(p => p.prediction === 'Malicious').length;
      const suspiciousCount = result.counts?.suspicious
        ?? result.predictions.filter(p => p.prediction === 'Suspicious').length;
      if (maliciousCount > 0) {
        toast.warning(`Detected ${maliciousCount} malicious connections!`, { duration: 5000 });
      }
      if (suspiciousCount > 0) {
        toast.info(`${suspiciousCount} suspicious (ML-only) flows flagged for analyst review`, { duration: 4000 });
      }
    } catch (error) {
      toast.error('Failed to process file. Please try again.');
      console.error(error);
      setStageDetail('Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setPreview(null);
    setResults(null);
    setBatchMeta(null);
    setSelectedRow(null);
    setSelectedDetail(null);
    setProgress(0);
    setCurrentStep(-1);
    setStageDetail('');
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

  const getPredictionColor = (p: ThreatPredictionSummary['prediction']) => {
    if (p === 'Normal') return 'text-[#00ff88]';
    if (p === 'Malicious') return 'text-[#ff3366]';
    if (p === 'Suspicious') return 'text-yellow-400';
    return 'text-yellow-400';
  };

  const getPredictionBg = (p: ThreatPredictionSummary['prediction']) => {
    if (p === 'Normal') return 'bg-[#00ff88]/5';
    if (p === 'Malicious') return 'bg-[#ff3366]/8';
    if (p === 'Suspicious') return 'bg-yellow-400/5';
    return 'bg-yellow-400/5';
  };

  const getPredictionBadge = (p: ThreatPredictionSummary['prediction']) => {
    if (p === 'Normal') return 'bg-[#00ff88]/15 text-[#00ff88] border-[#00ff88]/40';
    if (p === 'Malicious') return 'bg-[#ff3366]/15 text-[#ff3366] border-[#ff3366]/40';
    if (p === 'Suspicious') return 'bg-yellow-400/15 text-yellow-400 border-yellow-400/40';
    return 'bg-yellow-400/15 text-yellow-400 border-yellow-400/40';
  };

  // Risk-badge styling lives in <RiskBadge /> (shared with the live dashboard).

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
  const showAnalyzer = !!results && results.length > 0;

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
                      <p className="text-xs text-gray-500 mt-3">Supports Wireshark packet captures and network traffic files. Unlimited size.</p>
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
                        {stageDetail && (
                          <p className="text-[11px] text-gray-500 font-mono truncate" title={stageDetail}>
                            {stageDetail}
                          </p>
                        )}
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
                                className={`flex items-center gap-3 p-2.5 rounded-lg transition-colors ${isActive ? 'bg-[#00ff88]/10 border border-[#00ff88]/30' :
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
                            <p className="text-xs text-gray-400">{(batchMeta?.total ?? results.length).toLocaleString()} packets analyzed</p>
                          </div>
                        </div>
                        {/* Truncation notice — when the upload produced more rows
                            than we ship to the browser, the full set lives in the
                            DB and is reachable via Dashboard/Alerts. */}
                        {batchMeta && batchMeta.returned < batchMeta.total && (
                          <div className="flex items-start gap-2 p-3 rounded-xl bg-[#00ccff]/10 border border-[#00ccff]/30">
                            <Info className="w-4 h-4 text-[#00ccff] shrink-0 mt-0.5" />
                            <p className="text-xs text-gray-300">
                              Showing <span className="font-mono text-[#00ccff]">{batchMeta.returned.toLocaleString()}</span> of{' '}
                              <span className="font-mono text-[#00ccff]">{batchMeta.total.toLocaleString()}</span> flows (actionable rows prioritized).
                              The full set is searchable in <span className="text-[#00ff88]">Dashboard</span> and <span className="text-[#00ff88]">Alerts</span>.
                            </p>
                          </div>
                        )}
                        <div className="grid grid-cols-3 gap-3">
                          <div className="p-3 rounded-xl bg-[#00ff88]/5 border border-[#00ff88]/20 text-center">
                            <p className="text-xl font-bold text-[#00ff88]">{(batchMeta?.counts?.normal ?? allPackets.filter(p => p.prediction === 'Normal').length).toLocaleString()}</p>
                            <p className="text-xs text-gray-400 mt-0.5">Normal</p>
                          </div>
                          <div className="p-3 rounded-xl bg-[#ff3366]/5 border border-[#ff3366]/20 text-center">
                            <p className="text-xl font-bold text-[#ff3366]">{(batchMeta?.counts?.malicious ?? allPackets.filter(p => p.prediction === 'Malicious').length).toLocaleString()}</p>
                            <p className="text-xs text-gray-400 mt-0.5">Malicious</p>
                          </div>
                          <div className="p-3 rounded-xl bg-yellow-400/5 border border-yellow-400/20 text-center">
                            <p className="text-xl font-bold text-yellow-400">{(batchMeta?.counts?.suspicious ?? allPackets.filter(p => p.prediction === 'Suspicious').length).toLocaleString()}</p>
                            <p className="text-xs text-gray-400 mt-0.5">Suspicious</p>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <Button onClick={handleExportResults} className="bg-[#00ccff]/15 hover:bg-[#00ccff]/25 text-[#00ccff] border border-[#00ccff]/40">
                            <Download className="mr-2 h-4 w-4" />Export
                          </Button>
                          <Button onClick={() => navigate('/dashboard')} className="bg-[#00ff88]/15 hover:bg-[#00ff88]/25 text-[#00ff88] border border-[#00ff88]/40">
                            Dashboard
                          </Button>
                        </div>
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
                {/* Empty state — no file selected */}
                {!preview && !showAnalyzer && !file && (
                  <div className="text-center py-16">
                    <SearchIcon className="w-12 h-12 mx-auto mb-4 text-gray-700" />
                    <p className="text-gray-500">No file selected</p>
                    <p className="text-sm text-gray-600 mt-1">Upload a packet file to preview data</p>
                  </div>
                )}

                {/* Binary PCAP placeholder — no text preview possible */}
                {!preview && !showAnalyzer && file && (
                  file.name.toLowerCase().endsWith('.pcap') ||
                  file.name.toLowerCase().endsWith('.pcapng')
                ) && (
                  <div className="text-center py-12">
                    <Shield className="w-12 h-12 mx-auto mb-4 text-[#00ccff]/60" />
                    <p className="text-gray-300 font-semibold">Binary capture file</p>
                    <p className="text-sm text-gray-500 mt-1 max-w-sm mx-auto">
                      PCAP files contain raw packet bytes — a text preview isn't meaningful.
                      Per-flow analysis will appear here after extraction.
                    </p>
                    <div className="mt-4 inline-flex items-center gap-2 text-xs text-gray-500 font-mono">
                      <span>{file.name}</span>
                      <span className="opacity-50">·</span>
                      <span>{(file.size / (1024 * 1024)).toFixed(1)} MB</span>
                    </div>
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
                    {/* Verdict-source filter pills. Lets the analyst narrow to
                        a verdict cell (confirmed/sig-only/ml-only/benign) so
                        the table doesn't dilute the actionable rows. */}
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="text-gray-500 uppercase tracking-wide text-[10px]">Verdict</span>
                      {([
                        { key: 'all',            label: 'All',         cls: 'bg-gray-800/60 text-gray-300 border-gray-600/60' },
                        { key: 'confirmed',      label: 'Confirmed',   cls: 'bg-[#ff3366]/15 text-[#ff3366] border-[#ff3366]/40' },
                        { key: 'signature_only', label: 'Sig-only',    cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40' },
                        { key: 'ml_only',        label: 'ML-only',     cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40' },
                        { key: 'benign',         label: 'Benign',      cls: 'bg-gray-700/30 text-gray-400 border-gray-600/40' },
                      ] as { key: VerdictFilter; label: string; cls: string }[]).map((p) => {
                        const active = verdictFilter === p.key;
                        const n = p.key === 'all'
                          ? allPackets.length
                          : (verdictCounts[p.key as ThreatSource] ?? 0);
                        return (
                          <button
                            key={p.key}
                            type="button"
                            onClick={() => setVerdictFilter(p.key)}
                            className={`px-2.5 py-1 rounded border transition-colors ${p.cls} ${active ? 'ring-1 ring-inset ring-white/30 brightness-125' : 'opacity-75 hover:opacity-100'}`}
                          >
                            {p.label} <span className="font-mono opacity-80">({n})</span>
                          </button>
                        );
                      })}
                    </div>

                    {/* Section 1: Packet List Table */}
                    <div className="rounded-lg border border-gray-700/60 overflow-hidden">
                      <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/60 border-b border-gray-700/60">
                        <Network className="w-3.5 h-3.5 text-[#00ccff]" />
                        <span className="text-xs font-semibold text-gray-300">Packet List</span>
                        <span className="text-xs text-gray-500 ml-auto">
                          {filteredPackets.length === 0
                            ? '0 packets'
                            : `${(pageStart + 1).toLocaleString()}–${Math.min(pageStart + ROWS_PER_PAGE, filteredPackets.length).toLocaleString()} of ${filteredPackets.length.toLocaleString()} packets`}
                          {filteredPackets.length !== allPackets.length && (
                            <span className="text-gray-600"> (filtered from {allPackets.length.toLocaleString()})</span>
                          )}
                        </span>
                      </div>
                      <div className="overflow-x-auto max-h-[220px] overflow-y-auto">
                        <table className="w-full text-xs">
                          <thead className="sticky top-0 z-10">
                            <tr className="bg-gray-900/80 border-b border-gray-700/60">
                              {['Time', 'Source', 'Destination', 'Proto', 'SrcPort', 'DstPort', 'Length', 'Verdict', 'Prediction', 'Risk'].map(h => (
                                <th key={h} className="text-left p-2 text-[#00ff88]/80 font-semibold whitespace-nowrap">{h}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {displayedPackets.map((pkt) => (
                              <tr
                                key={pkt.id}
                                onClick={() => setSelectedRow(pkt)}
                                className={`border-b border-gray-700/30 cursor-pointer transition-colors
                                  ${selectedRow?.id === pkt.id ? 'ring-1 ring-inset ring-[#00ccff]/60 bg-[#00ccff]/5' : `${getPredictionBg(pkt.prediction)} hover:bg-gray-700/20`}
                                `}
                              >
                                <td className="p-2 text-gray-400 font-mono whitespace-nowrap">{formatTimestamp(pkt.timestamp)}</td>
                                <td className="p-2 text-gray-300 font-mono whitespace-nowrap">{pkt.sourceIp}</td>
                                <td className="p-2 text-gray-300 font-mono whitespace-nowrap">{pkt.destinationIp}</td>
                                <td className="p-2 text-gray-300 whitespace-nowrap">{pkt.protocol}</td>
                                <td className="p-2 text-gray-400 whitespace-nowrap">{pkt.sourcePort}</td>
                                <td className="p-2 text-gray-400 whitespace-nowrap">{pkt.destinationPort}</td>
                                <td className="p-2 text-gray-400 whitespace-nowrap">{pkt.packetSize}</td>
                                <td className="p-2 whitespace-nowrap">
                                  <VerdictBadge source={pkt.source} size="text-[10px] py-0" title={pkt.snort_msg || ''} />
                                </td>
                                <td className="p-2 whitespace-nowrap">
                                  <Badge variant="outline" className={`text-[10px] py-0 ${getPredictionBadge(pkt.prediction)}`}>{pkt.prediction}</Badge>
                                </td>
                                <td className="p-2 whitespace-nowrap">
                                  <RiskBadge risk={severityToRisk(pkt.severity)} size="text-[10px] py-0" />
                                </td>
                              </tr>
                            ))}
                            {displayedPackets.length === 0 && (
                              <tr>
                                <td colSpan={10} className="p-6 text-center text-xs text-gray-500">
                                  No packets in this verdict cell. Try a different filter.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                      {/* Pagination — only shown when there's more than one page. */}
                      {totalPages > 1 && (
                        <div className="flex items-center justify-between gap-3 px-3 py-2 bg-gray-900/40 border-t border-gray-700/60 text-xs">
                          <span className="text-gray-500">
                            Page <span className="font-mono text-gray-300">{safePage}</span> of{' '}
                            <span className="font-mono text-gray-300">{totalPages.toLocaleString()}</span>
                          </span>
                          <div className="flex items-center gap-1">
                            <button
                              type="button"
                              onClick={() => setTablePage(1)}
                              disabled={safePage === 1}
                              className="px-2 py-1 rounded border border-gray-700/60 text-gray-400 hover:text-white hover:bg-gray-700/40 disabled:opacity-30 disabled:cursor-not-allowed"
                            >
                              «
                            </button>
                            <button
                              type="button"
                              onClick={() => setTablePage((p) => Math.max(1, p - 1))}
                              disabled={safePage === 1}
                              className="px-2 py-1 rounded border border-gray-700/60 text-gray-400 hover:text-white hover:bg-gray-700/40 disabled:opacity-30 disabled:cursor-not-allowed"
                            >
                              Prev
                            </button>
                            <button
                              type="button"
                              onClick={() => setTablePage((p) => Math.min(totalPages, p + 1))}
                              disabled={safePage === totalPages}
                              className="px-2 py-1 rounded border border-gray-700/60 text-gray-400 hover:text-white hover:bg-gray-700/40 disabled:opacity-30 disabled:cursor-not-allowed"
                            >
                              Next
                            </button>
                            <button
                              type="button"
                              onClick={() => setTablePage(totalPages)}
                              disabled={safePage === totalPages}
                              className="px-2 py-1 rounded border border-gray-700/60 text-gray-400 hover:text-white hover:bg-gray-700/40 disabled:opacity-30 disabled:cursor-not-allowed"
                            >
                              »
                            </button>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Section 2 & 3: Packet Details + Hierarchical Model + Snort.
                        Scalars render immediately from the summary row; the
                        heavy fields (`stage2_probs`, `stage3_probs`,
                        `mlFeatures`, `mitre.techniques`) load asynchronously
                        from `/predictions/{id}` so we never hold 80k of them
                        in memory. */}
                    <AnimatePresence mode="wait">
                      {drawerData ? (
                        <motion.div
                          key={drawerData.id}
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
                              {detailLoading && (
                                <span className="text-[10px] text-gray-500 ml-auto animate-pulse">loading detail…</span>
                              )}
                            </div>
                            <div className="p-3 space-y-1.5 max-h-[240px] overflow-y-auto">
                              {[
                                { label: 'Source IP', value: drawerData.sourceIp },
                                { label: 'Destination IP', value: drawerData.destinationIp },
                                { label: 'Source Port', value: drawerData.sourcePort },
                                { label: 'Destination Port', value: drawerData.destinationPort },
                                { label: 'Protocol', value: drawerData.protocol },
                                { label: 'Packet Size', value: `${drawerData.packetSize} bytes` },
                                { label: 'Duration', value: `${drawerData.duration}s` },
                              ].map(item => (
                                <div key={item.label} className="flex justify-between items-center py-1 border-b border-gray-700/30 last:border-0">
                                  <span className="text-xs text-gray-500">{item.label}</span>
                                  <span className={`text-xs font-mono ${getPredictionColor(drawerData.prediction)}`}>{item.value}</span>
                                </div>
                              ))}

                              {/* ML Features — pulled from the lazy-fetched
                                  detail. Until the fetch resolves we show a
                                  shimmer; the scalar fields above are already
                                  visible from the summary row. */}
                              <div className="pt-2">
                                <p className="text-xs text-[#00ccff] font-semibold mb-1.5 flex items-center gap-1">
                                  <Cpu className="w-3 h-3" /> ML Feature Values
                                </p>
                                {selectedDetail?.mlFeatures ? (
                                  <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                                    {Object.entries(selectedDetail.mlFeatures).map(([key, val]) => (
                                      <div key={key} className="flex justify-between items-center">
                                        <span className="text-[10px] text-gray-500 font-mono">{key}</span>
                                        <span className="text-[10px] text-gray-300 font-mono">{typeof val === 'number' ? val.toLocaleString() : String(val)}</span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-[10px] text-gray-600 italic">
                                    {detailLoading ? 'Loading ML feature values…' : 'Feature values not available'}
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>

                          {/* Per-stage hierarchical model breakdown — scalars
                              are on the summary; full probability vectors are
                              lazy-loaded via /predictions/{id}. Also rendered
                              for Suspicious so the analyst can see why ML
                              flagged the flow even when Snort didn't. */}
                          {(drawerData.prediction === 'Malicious' || drawerData.prediction === 'Suspicious')
                            && (typeof drawerData.stage2_p === 'number' || typeof drawerData.stage3_p === 'number') && (
                            <div className="rounded-lg border border-[#ff3366]/20 bg-[#ff3366]/5 p-3 space-y-3">
                              <div className="flex items-center gap-2">
                                <Cpu className="w-3.5 h-3.5 text-[#ff3366]" />
                                <span className="text-xs font-semibold text-gray-300">Hierarchical Model Breakdown</span>
                              </div>
                              {(drawerData.family || drawerData.attack_type) && (
                                <div className="text-[11px] text-gray-400 space-y-0.5">
                                  {drawerData.family && (
                                    <div><span className="text-gray-500">Family:</span> <span className="font-mono">{drawerData.family}</span></div>
                                  )}
                                  {drawerData.attack_type && (
                                    <div><span className="text-gray-500">Leaf:</span> <span className="font-mono text-[#ff3366]">{drawerData.attack_type}</span></div>
                                  )}
                                </div>
                              )}
                              <div className="space-y-1">
                                <div className="text-[10px] text-gray-500 uppercase tracking-wide">Per-stage Probabilities</div>
                                {typeof drawerData.stage1_p === 'number' && (
                                  <div className="flex items-center justify-between text-[11px]">
                                    <span className="text-gray-500" title="Stage-1 binary gate output. Calibration-shifted by the FPR<=1% threshold — used for routing only, not as a confidence signal.">Stage 1 (routing only)</span>
                                    <span className="font-mono text-gray-400">{(drawerData.stage1_p * 100).toFixed(3)}%</span>
                                  </div>
                                )}
                                {typeof drawerData.stage2_p === 'number' && (
                                  <div className="flex items-center justify-between text-[11px]">
                                    <span className="text-gray-500" title="Stage-2 top family probability — the main 'is this routing trustworthy?' signal.">Stage 2 (family)</span>
                                    <span className="font-mono text-[#00ccff]">{(drawerData.stage2_p * 100).toFixed(1)}%</span>
                                  </div>
                                )}
                                {typeof drawerData.stage3_p === 'number' && (
                                  <div className="flex items-center justify-between text-[11px]">
                                    <span className="text-gray-500" title="Stage-3 top leaf probability inside the chosen family.">Stage 3 (leaf)</span>
                                    <span className="font-mono text-[#00ff88]">{(drawerData.stage3_p * 100).toFixed(1)}%</span>
                                  </div>
                                )}
                              </div>
                              {selectedDetail?.stage2_probs || selectedDetail?.stage3_probs ? (
                                <>
                                  <StageProbBars
                                    probs={selectedDetail.stage2_probs ?? null}
                                    label="Stage-2 family vector"
                                    highlight={drawerData.family ?? null}
                                  />
                                  <StageProbBars
                                    probs={selectedDetail.stage3_probs ?? null}
                                    label="Stage-3 leaf vector"
                                    highlight={drawerData.attack_type ?? null}
                                  />
                                </>
                              ) : (
                                <div className="text-[10px] text-gray-500 italic">
                                  {detailLoading ? 'Loading probability vectors…' : 'Probability vectors not available'}
                                </div>
                              )}
                            </div>
                          )}

                          {/* Hybrid Verdict + Snort signature metadata. Renders
                              only when Snort actually fired on this flow
                              (source = confirmed or signature_only). */}
                          {drawerData.snort_msg && (
                            <div className="rounded-lg border border-[#ffaa00]/20 bg-[#ffaa00]/5 p-3 space-y-2">
                              <div className="flex items-center justify-between gap-2">
                                <div className="flex items-center gap-2">
                                  <AlertTriangle className="w-3.5 h-3.5 text-[#ffaa00]" />
                                  <span className="text-xs font-semibold text-gray-300">Snort Signature</span>
                                </div>
                                <VerdictBadge source={drawerData.source} size="text-[10px] py-0" />
                              </div>
                              <div className="space-y-1">
                                {[
                                  { label: 'Message',  value: drawerData.snort_msg },
                                  { label: 'SID',      value: drawerData.snort_sid },
                                  { label: 'Classtype', value: drawerData.snort_classtype },
                                  { label: 'Priority', value: drawerData.snort_priority },
                                ].filter(item => item.value).map((item) => (
                                  <div key={item.label} className="flex justify-between items-center py-1 border-b border-gray-700/30 last:border-0">
                                    <span className="text-[11px] text-gray-500">{item.label}</span>
                                    <span className="text-[11px] font-mono text-gray-300">{String(item.value)}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Verdict summary card (replaces the old random
                              "AI Explanation" mock text). Shows prediction,
                              risk and confidence-quality together. */}
                          <div className="rounded-lg border border-gray-700/60 overflow-hidden">
                            <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/60 border-b border-gray-700/60">
                              <Brain className="w-3.5 h-3.5 text-[#00ccff]" />
                              <span className="text-xs font-semibold text-gray-300">Verdict</span>
                            </div>
                            <div className="p-3 space-y-2">
                              <div className="flex items-center gap-2 flex-wrap">
                                <Badge variant="outline" className={getPredictionBadge(drawerData.prediction)}>
                                  {drawerData.prediction}
                                </Badge>
                                <RiskBadge risk={severityToRisk(drawerData.severity)} prefix="Risk" />
                                <ConfidenceQuality stage2_p={drawerData.stage2_p ?? null} />
                              </div>
                              <p className="text-[10px] text-gray-500 italic">
                                Confidence is driven by Stage 2 × Stage 3 family/leaf probability — Stage 1 is the
                                calibration-shifted routing gate, not a trust signal.
                                {drawerData.prediction === 'Suspicious'
                                  && ' Suspicious = ML flagged, Snort did not corroborate — most are calibration FPs. Analyst review recommended.'}
                                {drawerData.prediction === 'Malicious'
                                  && ' Manual review recommended for flagged packets.'}
                              </p>
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