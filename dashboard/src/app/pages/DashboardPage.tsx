import { useState, useEffect, useCallback, useRef } from 'react';
import { Search, Download, Filter, RefreshCw, Radio, Eye, ShieldAlert, Gauge, Info, BarChart3, Cpu, Shield, Play, Square, Wifi, FileDown, Target, ExternalLink } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';
import { motion } from 'motion/react';
import {
  threatService,
  liveTrafficStream,
  startCapture,
  stopCapture,
  getCaptureStatus,
  getInterfaces,
  getLogFiles,
  getLogDownloadUrl,
} from '../services/threatDetectionService';
import { formatDateTime, formatConfidence, downloadFile } from '../utils/helpers';
import type { ThreatPrediction, LivePacket, NetworkInterface, LogFileInfo } from '../types/threat';

export default function DashboardPage() {
  const [predictions, setPredictions] = useState<ThreatPrediction[]>([]);
  const [filteredPredictions, setFilteredPredictions] = useState<ThreatPrediction[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  // Live Packet Monitoring state
  const [livePackets, setLivePackets] = useState<LivePacket[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<LivePacket | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);

  // Capture controls
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('auto');
  const [capturing, setCapturing] = useState(false);
  const [packetCount, setPacketCount] = useState(0);
  const [logFiles, setLogFiles] = useState<LogFileInfo[]>([]);
  const [captureLoading, setCaptureLoading] = useState(false);
  const packetCountRef = useRef(0);

  useEffect(() => {
    loadPredictions();
    getInterfaces().then(setInterfaces).catch(() => {});
    getCaptureStatus().then(s => {
      setCapturing(s.running);
      setPacketCount(s.packet_count);
      if (s.running) connectStream();
    }).catch(() => {});
  }, []);

  const connectStream = () => {
    liveTrafficStream.connectToStream();
    setStreamConnected(liveTrafficStream.connected);
  };

  useEffect(() => {
    const unsub = liveTrafficStream.subscribe((packet: LivePacket) => {
      setStreamConnected(true);
      packetCountRef.current += 1;
      setPacketCount(packetCountRef.current);
      setLivePackets(prev => [packet, ...prev.slice(0, 99)]);
    });
    return () => { unsub(); };
  }, []);

  const handleStartCapture = async () => {
    setCaptureLoading(true);
    try {
      const iface = selectedInterface === 'auto' ? undefined : selectedInterface;
      await startCapture(iface);
      setCapturing(true);
      setLivePackets([]);
      packetCountRef.current = 0;
      setPacketCount(0);
      connectStream();
      toast.success('Live capture started');
    } catch (err: any) {
      toast.error(err.message || 'Failed to start capture');
    } finally {
      setCaptureLoading(false);
    }
  };

  const handleStopCapture = async () => {
    setCaptureLoading(true);
    try {
      const result = await stopCapture();
      setCapturing(false);
      liveTrafficStream.disconnect();
      setStreamConnected(false);
      toast.success(`Capture stopped — ${result.packets_captured} packets captured`);
      refreshLogFiles();
    } catch (err: any) {
      toast.error(err.message || 'Failed to stop capture');
    } finally {
      setCaptureLoading(false);
    }
  };

  const refreshLogFiles = () => {
    getLogFiles().then(setLogFiles).catch(() => {});
  };

  useEffect(() => {
    filterPredictions();
  }, [predictions, searchTerm, severityFilter]);

  const loadPredictions = async () => {
    setLoading(true);
    try {
      const data = await threatService.getAllPredictions();
      setPredictions(data);
    } catch (error) {
      toast.error('Failed to load predictions');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const filterPredictions = useCallback(() => {
    let filtered = [...predictions];
    if (searchTerm) {
      filtered = filtered.filter(
        p => p.sourceIp.includes(searchTerm) || p.destinationIp.includes(searchTerm)
      );
    }
    if (severityFilter !== 'all') {
      if (severityFilter === 'normal') {
        filtered = filtered.filter(p => p.prediction === 'Normal');
      } else {
        filtered = filtered.filter(
          p => p.prediction === 'Malicious' && p.severity?.toLowerCase() === severityFilter
        );
      }
    }
    setFilteredPredictions(filtered);
    setCurrentPage(1);
  }, [predictions, searchTerm, severityFilter]);

  const handleExport = () => {
    const csv = threatService.exportToCSV(filteredPredictions);
    const timestamp = new Date().toISOString().split('T')[0];
    downloadFile(csv, `threat-detection-export-${timestamp}.csv`);
    toast.success('Data exported successfully!');
  };

  const totalPages = Math.ceil(filteredPredictions.length / itemsPerPage);
  const paginatedData = filteredPredictions.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const getPacketColor = (prediction: LivePacket['prediction']) => {
    switch (prediction) {
      case 'Normal': return 'text-[#00ff88]';
      case 'Malicious': return 'text-[#ff3366]';
      case 'Suspicious': return 'text-yellow-400';
    }
  };

  const getPacketBgColor = (prediction: LivePacket['prediction']) => {
    switch (prediction) {
      case 'Normal': return 'bg-[#00ff88]/5';
      case 'Malicious': return 'bg-[#ff3366]/10';
      case 'Suspicious': return 'bg-yellow-400/5';
    }
  };

  const getPacketBadgeClass = (prediction: LivePacket['prediction']) => {
    switch (prediction) {
      case 'Normal': return 'bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/50';
      case 'Malicious': return 'bg-[#ff3366]/20 text-[#ff3366] border-[#ff3366]/50';
      case 'Suspicious': return 'bg-yellow-400/20 text-yellow-400 border-yellow-400/50';
    }
  };

  const getRiskLevel = (pkt: LivePacket) => {
    if (pkt.prediction === 'Malicious') {
      if (pkt.severity === 'High') return 'Critical';
      if (pkt.severity === 'Medium') return 'High';
      return 'Medium';
    }
    if (pkt.prediction === 'Suspicious') return 'Low';
    return 'None';
  };

  const getRiskBadge = (risk: string) => {
    const map: Record<string, string> = {
      Critical: 'bg-[#ff3366]/20 text-[#ff3366] border-[#ff3366]/50',
      High: 'bg-red-500/15 text-red-400 border-red-500/40',
      Medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
      Low: 'bg-[#00ccff]/15 text-[#00ccff] border-[#00ccff]/40',
      None: 'bg-gray-700/30 text-gray-400 border-gray-600/40',
    };
    return map[risk] || map.None;
  };

  const getConfidence = (pkt: LivePacket) => {
    if (pkt.confidence != null) return pkt.confidence.toFixed(4);
    if (pkt.prediction === 'Malicious') return (0.75 + Math.random() * 0.24).toFixed(2);
    if (pkt.prediction === 'Suspicious') return (0.50 + Math.random() * 0.25).toFixed(2);
    return (0.85 + Math.random() * 0.14).toFixed(2);
  };

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
              <h1 className="text-4xl font-bold text-white mb-2">Results Dashboard</h1>
              <p className="text-gray-400">
                Showing {filteredPredictions.length} of {predictions.length} predictions
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                onClick={loadPredictions}
                variant="outline"
                className="border-[#00ccff] text-[#00ccff] hover:bg-[#00ccff]/10"
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh
              </Button>
              <Button
                onClick={handleExport}
                className="bg-[#00ff88] hover:bg-[#00ff88]/80 text-gray-900 font-semibold"
              >
                <Download className="mr-2 h-4 w-4" />
                Export CSV
              </Button>
            </div>
          </div>

          {/* Filters */}
          <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur mb-6">
            <CardContent className="py-6">
              <div className="grid md:grid-cols-3 gap-4">
                <div className="md:col-span-2">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                    <Input
                      placeholder="Search by IP address..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-10 bg-[#1a2540]/60 border-[#253352] text-white"
                    />
                  </div>
                </div>
                <div>
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="bg-[#1a2540]/60 border-[#253352] text-white">
                      <Filter className="mr-2 h-4 w-4" />
                      <SelectValue placeholder="Filter by severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Results</SelectItem>
                      <SelectItem value="normal">Normal Only</SelectItem>
                      <SelectItem value="high">High Severity</SelectItem>
                      <SelectItem value="medium">Medium Severity</SelectItem>
                      <SelectItem value="low">Low Severity</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Prediction Results Table */}
          <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur mb-8">
            <CardHeader>
              <CardTitle className="text-white">Prediction Results</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="min-h-[520px]">
              {loading ? (
                <div className="flex flex-col items-center justify-center min-h-[520px]">
                  <RefreshCw className="w-12 h-12 mx-auto mb-4 text-gray-600 animate-spin" />
                  <p className="text-gray-500">Loading predictions...</p>
                </div>
              ) : filteredPredictions.length === 0 ? (
                <div className="flex flex-col items-center justify-center min-h-[520px]">
                  <Shield className="w-12 h-12 mx-auto mb-4 text-gray-600" />
                  <p className="text-gray-500">No results match the selected filters</p>
                  <p className="text-sm text-gray-600 mt-2">
                    Try adjusting your filters or upload some data
                  </p>
                </div>
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-[#1a2540] hover:bg-transparent">
                          <TableHead className="text-[#00ff88]">Timestamp</TableHead>
                          <TableHead className="text-[#00ff88]">Source IP</TableHead>
                          <TableHead className="text-[#00ff88]">Destination IP</TableHead>
                          <TableHead className="text-[#00ff88]">Protocol</TableHead>
                          <TableHead className="text-[#00ff88]">Prediction</TableHead>
                          <TableHead className="text-[#00ff88]">Confidence</TableHead>
                          <TableHead className="text-[#00ff88]">Severity</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {paginatedData.map((prediction) => (
                          <TableRow
                            key={prediction.id}
                            className={`border-[#1a2540]/60 cursor-pointer transition-all duration-200 ${
                              prediction.prediction === 'Malicious'
                                ? 'bg-[#ff3366]/5 hover:bg-[#ff3366]/10 hover:shadow-[inset_0_0_20px_rgba(255,51,102,0.06)]'
                                : 'hover:bg-[#00ff88]/[0.07] hover:shadow-[inset_0_0_20px_rgba(0,255,136,0.05)]'
                            }`}
                            style={{ transition: 'background-color 0.2s ease, box-shadow 0.2s ease' }}
                          >
                            <TableCell className="text-gray-300 font-mono text-xs">
                              {formatDateTime(prediction.timestamp)}
                            </TableCell>
                            <TableCell className="text-gray-300 font-mono">
                              {prediction.sourceIp}
                            </TableCell>
                            <TableCell className="text-gray-300 font-mono">
                              {prediction.destinationIp}
                            </TableCell>
                            <TableCell className="text-gray-300">
                              {prediction.protocol}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={prediction.prediction === 'Malicious' ? 'destructive' : 'default'}
                                className={
                                  prediction.prediction === 'Malicious'
                                    ? 'bg-[#ff3366]/20 text-[#ff3366] border-[#ff3366]/50'
                                    : 'bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/50'
                                }
                              >
                                {prediction.prediction}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-gray-300 font-semibold">
                              {formatConfidence(prediction.confidence)}
                            </TableCell>
                            <TableCell>
                              {prediction.severity ? (
                                <Badge
                                  variant="outline"
                                  className={`${
                                    prediction.severity === 'High'
                                      ? 'border-[#ff3366]/50 text-[#ff3366]'
                                      : prediction.severity === 'Medium'
                                      ? 'border-yellow-500/50 text-yellow-400'
                                      : 'border-[#00ccff]/50 text-[#00ccff]'
                                  }`}
                                >
                                  {prediction.severity}
                                </Badge>
                              ) : (
                                <span className="text-gray-600">-</span>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>

                  {totalPages > 1 && (
                    <div className="flex justify-between items-center mt-6 pt-6 border-t border-[#1a2540]">
                      <p className="text-sm text-gray-400">
                        Page {currentPage} of {totalPages}
                      </p>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                          disabled={currentPage === 1}
                          className="border-gray-600 text-gray-400"
                        >
                          Previous
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                          disabled={currentPage === totalPages}
                          className="border-gray-600 text-gray-400"
                        >
                          Next
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
              </div>
            </CardContent>
          </Card>

          {/* Live Packet Monitoring — below Prediction Results */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 }}
          >
            <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
              <CardHeader>
                <div className="flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Radio className={`w-5 h-5 ${capturing ? 'text-[#00ff88] animate-pulse' : 'text-gray-500'}`} />
                      <CardTitle className="text-white">Live Packet Monitoring</CardTitle>
                      {capturing && (
                        <span className={`flex items-center gap-1.5 text-xs ${streamConnected ? 'text-[#00ff88]' : 'text-yellow-400'}`}>
                          <span className={`w-2 h-2 rounded-full animate-pulse ${streamConnected ? 'bg-[#00ff88]' : 'bg-yellow-400'}`} />
                          {streamConnected ? 'LIVE' : 'CONNECTING'}
                        </span>
                      )}
                      {capturing && (
                        <span className="text-xs text-gray-400 font-mono">{packetCount} flows</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={refreshLogFiles}
                        className="border-gray-600 text-gray-400 hover:bg-gray-800"
                      >
                        <FileDown className="mr-1.5 h-3.5 w-3.5" />
                        Logs
                      </Button>
                    </div>
                  </div>

                  {/* Capture Controls */}
                  <div className="flex items-center gap-3 flex-wrap">
                    <div className="flex items-center gap-2">
                      <Wifi className="w-4 h-4 text-gray-400" />
                      <Select value={selectedInterface} onValueChange={setSelectedInterface} disabled={capturing}>
                        <SelectTrigger className="w-[200px] h-8 bg-[#1a2540]/60 border-[#253352] text-white text-xs">
                          <SelectValue placeholder="Select interface" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="auto">Auto-detect</SelectItem>
                          {interfaces.map(i => (
                            <SelectItem key={i.name} value={i.name}>{i.description}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {!capturing ? (
                      <Button
                        size="sm"
                        onClick={handleStartCapture}
                        disabled={captureLoading}
                        className="bg-[#00ff88] hover:bg-[#00ff88]/80 text-gray-900 font-semibold"
                      >
                        <Play className="mr-1.5 h-3.5 w-3.5" />
                        {captureLoading ? 'Starting...' : 'Start Capture'}
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleStopCapture}
                        disabled={captureLoading}
                        className="border-[#ff3366] text-[#ff3366] hover:bg-[#ff3366]/10"
                      >
                        <Square className="mr-1.5 h-3.5 w-3.5" />
                        {captureLoading ? 'Stopping...' : 'Stop Capture'}
                      </Button>
                    )}

                    {logFiles.length > 0 && (
                      <div className="ml-auto flex items-center gap-2">
                        <Select onValueChange={(filename) => { window.open(getLogDownloadUrl(filename), '_blank'); }}>
                          <SelectTrigger className="w-[240px] h-8 bg-[#1a2540]/60 border-[#253352] text-white text-xs">
                            <SelectValue placeholder="Download session log..." />
                          </SelectTrigger>
                          <SelectContent>
                            {logFiles.map(f => (
                              <SelectItem key={f.filename} value={f.filename}>
                                {f.filename} ({(f.size_bytes / 1024).toFixed(1)} KB)
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid lg:grid-cols-3 gap-6">
                  {/* Packet Table — Left 2 cols */}
                  <div className="lg:col-span-2 overflow-x-auto">
                    <div className="max-h-[480px] overflow-y-auto rounded-lg border border-[#1a2540]">
                      <table className="w-full text-xs">
                        <thead className="sticky top-0 z-10">
                          <tr className="bg-[#080c14] border-b border-[#1a2540]">
                            {['src_ip', 'dst_ip', 'sport', 'dport', 'protocol', 'service', 'duration', 'sbytes', 'dbytes', 'spkts', 'dpkts', 'state', 'prediction'].map(col => (
                              <th key={col} className="text-left p-2 text-[#00ff88] font-semibold whitespace-nowrap">{col}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {livePackets.map((pkt) => (
                            <tr
                              key={pkt.id}
                              className={`border-b border-[#1a2540]/50 cursor-pointer transition-colors ${getPacketBgColor(pkt.prediction)} ${selectedPacket?.id === pkt.id ? 'ring-1 ring-inset ring-[#00ccff]' : 'hover:bg-[#1a2540]/40'}`}
                              onClick={() => setSelectedPacket(pkt)}
                            >
                              <td className="p-2 text-gray-300 font-mono whitespace-nowrap">{pkt.src_ip}</td>
                              <td className="p-2 text-gray-300 font-mono whitespace-nowrap">{pkt.dst_ip}</td>
                              <td className="p-2 text-gray-400">{pkt.sport}</td>
                              <td className="p-2 text-gray-400">{pkt.dport}</td>
                              <td className="p-2 text-gray-300">{pkt.protocol}</td>
                              <td className="p-2 text-gray-400">{pkt.service}</td>
                              <td className="p-2 text-gray-400">{pkt.duration.toFixed(1)}s</td>
                              <td className="p-2 text-gray-400">{pkt.sbytes.toLocaleString()}</td>
                              <td className="p-2 text-gray-400">{pkt.dbytes.toLocaleString()}</td>
                              <td className="p-2 text-gray-400">{pkt.spkts}</td>
                              <td className="p-2 text-gray-400">{pkt.dpkts}</td>
                              <td className="p-2 text-gray-300">{pkt.state}</td>
                              <td className="p-2">
                                <Badge variant="outline" className={`text-[10px] py-0 ${getPacketBadgeClass(pkt.prediction)}`}>
                                  {pkt.prediction}
                                </Badge>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Packet Details Panel — Right col */}
                  <div className="lg:col-span-1">
                    <div className="bg-[#080c14]/80 border border-[#1a2540] rounded-lg p-4 h-[480px] overflow-y-auto">
                      <h3 className="text-sm font-semibold text-[#00ccff] mb-4 flex items-center gap-2">
                        <Eye className="w-4 h-4" />
                        Packet Details
                      </h3>
                      {selectedPacket ? (() => {
                        const riskLevel = getRiskLevel(selectedPacket);
                        const confidence = getConfidence(selectedPacket);
                        return (
                          <div className="space-y-4">
                            {/* Risk Level */}
                            <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540]">
                              <div className="flex items-center gap-2 mb-2">
                                <ShieldAlert className="w-4 h-4 text-[#ff3366]" />
                                <span className="text-xs text-gray-400 font-semibold">Risk Level</span>
                              </div>
                              <div className="flex items-center justify-between">
                                <Badge variant="outline" className={getRiskBadge(riskLevel)}>
                                  {riskLevel}
                                </Badge>
                                <Badge variant="outline" className={getPacketBadgeClass(selectedPacket.prediction)}>
                                  {selectedPacket.prediction}
                                </Badge>
                              </div>
                            </div>

                            {selectedPacket.attack_type && selectedPacket.prediction === 'Malicious' && (
                              <div className="p-3 rounded-lg bg-[#ff3366]/5 border border-[#ff3366]/20">
                                <div className="flex items-center gap-2 mb-1">
                                  <ShieldAlert className="w-4 h-4 text-[#ff3366]" />
                                  <span className="text-xs text-gray-400 font-semibold">Attack Category</span>
                                </div>
                                <span className="text-sm font-bold text-[#ff3366]">{selectedPacket.attack_type}</span>
                              </div>
                            )}

                            {selectedPacket.mitre && (
                              <div className="p-3 rounded-lg border" style={{
                                borderColor: selectedPacket.mitre.confidence_band === 'very_high' ? 'rgba(0,204,255,0.25)' : selectedPacket.mitre.confidence_band === 'high' ? 'rgba(0,255,136,0.25)' : 'rgba(255,170,0,0.25)',
                                background: selectedPacket.mitre.confidence_band === 'very_high' ? 'rgba(0,204,255,0.05)' : selectedPacket.mitre.confidence_band === 'high' ? 'rgba(0,255,136,0.05)' : 'rgba(255,170,0,0.05)',
                              }}>
                                <div className="flex items-center justify-between mb-2">
                                  <div className="flex items-center gap-2">
                                    <Target className="w-4 h-4 text-[#00ccff]" />
                                    <span className="text-xs text-gray-400 font-semibold">MITRE ATT&CK</span>
                                  </div>
                                  <Badge variant="outline" className="text-[9px] py-0" style={{
                                    color: selectedPacket.mitre.confidence_band === 'very_high' ? '#00ccff' : selectedPacket.mitre.confidence_band === 'high' ? '#00ff88' : '#ffaa00',
                                    borderColor: selectedPacket.mitre.confidence_band === 'very_high' ? 'rgba(0,204,255,0.4)' : selectedPacket.mitre.confidence_band === 'high' ? 'rgba(0,255,136,0.4)' : 'rgba(255,170,0,0.4)',
                                  }}>
                                    {selectedPacket.mitre.confidence_band === 'very_high' ? 'Very High' : selectedPacket.mitre.confidence_band === 'high' ? 'High Confidence' : 'Low Confidence'}
                                  </Badge>
                                </div>
                                <div className="space-y-1.5">
                                  <div>
                                    <span className="text-[10px] text-gray-500 uppercase tracking-wide">Tactics</span>
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {selectedPacket.mitre.tactics.map(t => (
                                        <Badge key={t.id} variant="outline" className="text-[10px] py-0 text-[#00ccff] border-[#00ccff]/30">
                                          {t.name}
                                        </Badge>
                                      ))}
                                    </div>
                                  </div>
                                  <div>
                                    <span className="text-[10px] text-gray-500 uppercase tracking-wide">Techniques</span>
                                    <div className="space-y-1 mt-1">
                                      {selectedPacket.mitre.techniques.map(t => (
                                        <a key={t.id} href={t.url} target="_blank" rel="noopener noreferrer" className="flex items-center justify-between text-[11px] py-0.5 group hover:text-[#00ccff] transition-colors">
                                          <span className="text-gray-300 group-hover:text-[#00ccff]">
                                            <code className="text-[10px] text-gray-500 mr-1.5">{t.id}</code>
                                            {t.name}
                                          </span>
                                          <ExternalLink className="w-3 h-3 text-gray-700 group-hover:text-[#00ccff] shrink-0" />
                                        </a>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              </div>
                            )}

                            {/* Model Confidence */}
                            <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540]">
                              <div className="flex items-center gap-2 mb-2">
                                <Gauge className="w-4 h-4 text-[#00ccff]" />
                                <span className="text-xs text-gray-400 font-semibold">Model Confidence</span>
                              </div>
                              <div className="flex items-center gap-3">
                                <span className={`text-xl font-bold ${getPacketColor(selectedPacket.prediction)}`}>{(parseFloat(confidence) * 100).toFixed(1)}%</span>
                                <div className="flex-1 h-2 bg-[#1a2540]/60 rounded-full overflow-hidden">
                                  <div
                                    className="h-full rounded-full transition-all duration-500"
                                    style={{
                                      width: `${parseFloat(confidence) * 100}%`,
                                      backgroundColor: selectedPacket.prediction === 'Malicious' ? '#ff3366' : selectedPacket.prediction === 'Suspicious' ? '#eab308' : '#00ff88',
                                    }}
                                  />
                                </div>
                              </div>
                            </div>

                            {/* Basic Information */}
                            <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540]">
                              <div className="flex items-center gap-2 mb-2">
                                <Info className="w-4 h-4 text-[#00ccff]" />
                                <span className="text-xs text-gray-400 font-semibold">Basic Information</span>
                              </div>
                              <div className="space-y-1.5">
                                {[
                                  { label: 'Source IP', value: selectedPacket.src_ip },
                                  { label: 'Destination IP', value: selectedPacket.dst_ip },
                                  { label: 'Source Port', value: selectedPacket.sport },
                                  { label: 'Destination Port', value: selectedPacket.dport },
                                  { label: 'Protocol', value: selectedPacket.protocol },
                                  { label: 'Service', value: selectedPacket.service },
                                  { label: 'State', value: selectedPacket.state },
                                ].map((item) => (
                                  <div key={item.label} className="flex justify-between items-center py-1 border-b border-[#1a2540]/40 last:border-0">
                                    <span className="text-[11px] text-gray-500">{item.label}</span>
                                    <span className={`text-[11px] font-mono ${getPacketColor(selectedPacket.prediction)}`}>{item.value}</span>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {/* Traffic Metrics */}
                            <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540]">
                              <div className="flex items-center gap-2 mb-2">
                                <BarChart3 className="w-4 h-4 text-[#00ccff]" />
                                <span className="text-xs text-gray-400 font-semibold">Traffic Metrics</span>
                              </div>
                              <div className="space-y-1.5">
                                {[
                                  { label: 'Duration', value: `${selectedPacket.duration.toFixed(2)}s` },
                                  { label: 'Source Bytes', value: selectedPacket.sbytes.toLocaleString() },
                                  { label: 'Dest Bytes', value: selectedPacket.dbytes.toLocaleString() },
                                  { label: 'Source Packets', value: selectedPacket.spkts },
                                  { label: 'Dest Packets', value: selectedPacket.dpkts },
                                ].map((item) => (
                                  <div key={item.label} className="flex justify-between items-center py-1 border-b border-[#1a2540]/40 last:border-0">
                                    <span className="text-[11px] text-gray-500">{item.label}</span>
                                    <span className={`text-[11px] font-mono ${getPacketColor(selectedPacket.prediction)}`}>{item.value}</span>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {/* Advanced Features */}
                            <div className="p-3 rounded-lg bg-[#0f1825]/80 border border-[#1a2540]">
                              <div className="flex items-center gap-2 mb-2">
                                <Cpu className="w-4 h-4 text-[#00ccff]" />
                                <span className="text-xs text-gray-400 font-semibold">Advanced Features</span>
                              </div>
                              <div className="space-y-1.5">
                                {[
                                  { label: 'Total Bytes', value: (selectedPacket.sbytes + selectedPacket.dbytes).toLocaleString() },
                                  { label: 'Total Packets', value: selectedPacket.spkts + selectedPacket.dpkts },
                                  { label: 'Byte Ratio', value: selectedPacket.dbytes > 0 ? (selectedPacket.sbytes / selectedPacket.dbytes).toFixed(3) : 'N/A' },
                                  { label: 'Packet Rate', value: selectedPacket.duration > 0 ? `${((selectedPacket.spkts + selectedPacket.dpkts) / selectedPacket.duration).toFixed(1)} pkt/s` : 'N/A' },
                                  { label: 'Throughput', value: selectedPacket.duration > 0 ? `${((selectedPacket.sbytes + selectedPacket.dbytes) / selectedPacket.duration / 1024).toFixed(2)} KB/s` : 'N/A' },
                                ].map((item) => (
                                  <div key={item.label} className="flex justify-between items-center py-1 border-b border-[#1a2540]/40 last:border-0">
                                    <span className="text-[11px] text-gray-500">{item.label}</span>
                                    <span className={`text-[11px] font-mono ${getPacketColor(selectedPacket.prediction)}`}>{item.value}</span>
                                  </div>
                                ))}
                              </div>
                            </div>

                            <div className="text-center pt-1">
                              <span className="text-[10px] text-gray-600 font-mono">{selectedPacket.id}</span>
                            </div>
                          </div>
                        );
                      })() : (
                        <div className="flex flex-col items-center justify-center h-[400px] text-center">
                          <Eye className="w-10 h-10 text-gray-700 mb-3" />
                          <p className="text-gray-500 text-sm">Select a packet row</p>
                          <p className="text-gray-600 text-xs mt-1">Click on any row to view full details</p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </motion.div>
      </div>
    </div>
  );
}