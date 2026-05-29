import { useState, useEffect, useCallback, useMemo } from 'react';
import { Search, Download, Filter, RefreshCw, Shield } from 'lucide-react';
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
import { VerdictBadge } from '../components/VerdictBadge';
import { TimeRangeSelector, loadRange } from '../components/TimeRangeSelector';
import { toast } from 'sonner';
import { motion } from 'motion/react';
import { threatService } from '../services/threatDetectionService';
import { formatDateTime, formatConfidence, downloadFile } from '../utils/helpers';
import type {
  ThreatPredictionSummary,
  AnalyticsRange,
} from '../types/threat';

// Persistence key for the severity filter so refreshes keep the analyst's
// chosen view. Default for new sessions is 'actionable' (Medium+High) — see
// Docs/ReportAI.md §6: on production NFStream-extracted features most
// Low-severity ML-only alerts are calibration-driven false positives.
const SEVERITY_FILTER_STORAGE_KEY = 'hids.dashboard.severityFilter';
const DEFAULT_SEVERITY_FILTER = 'actionable';
const TIME_RANGE_STORAGE_KEY = 'hids.dashboard.timeRange';

const RANGE_SECONDS: Record<AnalyticsRange, number | null> = {
  '1h': 3600,
  '24h': 24 * 3600,
  '7d': 7 * 24 * 3600,
  '30d': 30 * 24 * 3600,
  'all': null,
};

export default function DashboardPage() {
  // Server-side pagination: we only ever hold the current page of summaries
  // in state, not the full predictions_store (which could be 100k rows).
  // `total` comes from the paginated /predictions response and drives the
  // pager. Search / time-range / 'actionable' filters are still applied
  // client-side over the rows currently on screen.
  const [pageRows, setPageRows] = useState<ThreatPredictionSummary[]>([]);
  const [totalRows, setTotalRows] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>(() => {
    if (typeof window === 'undefined') return DEFAULT_SEVERITY_FILTER;
    return window.localStorage.getItem(SEVERITY_FILTER_STORAGE_KEY) || DEFAULT_SEVERITY_FILTER;
  });
  const [timeRange, setTimeRange] = useState<AnalyticsRange>(() => loadRange(TIME_RANGE_STORAGE_KEY));

  // Persist the analyst's filter choice so refreshes don't reset to default.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(SEVERITY_FILTER_STORAGE_KEY, severityFilter);
  }, [severityFilter]);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 50;

  // Refetch whenever pagination or the server-side severity filter changes.
  useEffect(() => {
    loadPredictions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentPage, severityFilter]);

  // Reset to page 1 when severity filter changes (otherwise we could land
  // on an out-of-range page once the result set shrinks).
  useEffect(() => {
    setCurrentPage(1);
  }, [severityFilter]);

  const loadPredictions = useCallback(async () => {
    setLoading(true);
    try {
      // Server-side severity filter when it maps cleanly. 'actionable' /
      // 'normal' are client-side concepts (Medium+High, or non-Malicious)
      // so we fetch without a server filter and refine below.
      const sev = (severityFilter === 'high' || severityFilter === 'medium' || severityFilter === 'low')
        ? (severityFilter as 'high' | 'medium' | 'low')
        : undefined;
      const page = await threatService.getPredictionsPage({
        limit: itemsPerPage,
        offset: (currentPage - 1) * itemsPerPage,
        severity: sev,
      });
      setPageRows(page.items);
      setTotalRows(page.total);
    } catch (error) {
      toast.error('Failed to load predictions');
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [currentPage, severityFilter]);

  // Client-side refinement on the current page only — keeps memory bounded
  // and the pager simple. Total-row math uses the server's `total` so the
  // user still sees the true store size.
  const filteredPredictions = useMemo(() => {
    let rows = pageRows;
    const windowSeconds = RANGE_SECONDS[timeRange];
    if (windowSeconds !== null) {
      const cutoffMs = Date.now() - windowSeconds * 1000;
      rows = rows.filter((p) => {
        const t = Date.parse(p.timestamp);
        return Number.isFinite(t) && t >= cutoffMs;
      });
    }
    if (searchTerm) {
      rows = rows.filter((p) => p.sourceIp.includes(searchTerm) || p.destinationIp.includes(searchTerm));
    }
    if (severityFilter === 'normal') {
      rows = rows.filter((p) => p.prediction === 'Normal');
    } else if (severityFilter === 'actionable') {
      // Actionable = confirmed malicious (Snort + ML agreement) OR sig-only.
      // Suspicious (ml_only) is hidden by default — most are calibration FPs.
      rows = rows.filter((p) =>
        p.prediction === 'Malicious' && (p.severity === 'High' || p.severity === 'Medium'),
      );
    } else if (severityFilter === 'suspicious') {
      rows = rows.filter((p) => p.prediction === 'Suspicious');
    }
    return rows;
  }, [pageRows, searchTerm, severityFilter, timeRange]);

  const handleExport = () => {
    const csv = threatService.exportToCSV(filteredPredictions);
    const timestamp = new Date().toISOString().split('T')[0];
    downloadFile(csv, `threat-detection-export-${timestamp}.csv`);
    toast.success('Data exported successfully!');
  };

  const totalPages = Math.max(1, Math.ceil(totalRows / itemsPerPage));
  // The visible page is already the server's window; client-side refinement
  // above just drops rows from it. No second slice needed.
  const paginatedData = filteredPredictions;

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
                Showing {filteredPredictions.length} of {totalRows.toLocaleString()} predictions
              </p>
            </div>
            <div className="flex items-center gap-2">
              <TimeRangeSelector
                value={timeRange}
                onChange={setTimeRange}
                storageKey={TIME_RANGE_STORAGE_KEY}
              />
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
                      <SelectItem value="actionable">Actionable (Confirmed + Sig-only)</SelectItem>
                      <SelectItem value="all">All (incl. Suspicious / Low FPs)</SelectItem>
                      <SelectItem value="suspicious">Suspicious (ML-only)</SelectItem>
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
                          <TableHead className="text-[#00ff88]">Verdict</TableHead>
                          <TableHead className="text-[#00ff88]">Prediction</TableHead>
                          <TableHead className="text-[#00ff88]">Attack Type</TableHead>
                          <TableHead className="text-[#00ff88]">Confidence</TableHead>
                          <TableHead className="text-[#00ff88]">Severity</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {paginatedData.map((prediction) => {
                          const predClass =
                            prediction.prediction === 'Malicious'
                              ? 'bg-[#ff3366]/20 text-[#ff3366] border-[#ff3366]/50'
                              : prediction.prediction === 'Suspicious'
                              ? 'bg-yellow-400/15 text-yellow-400 border-yellow-400/50'
                              : 'bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/50';
                          const rowBg =
                            prediction.prediction === 'Malicious'
                              ? 'bg-[#ff3366]/5 hover:bg-[#ff3366]/10 hover:shadow-[inset_0_0_20px_rgba(255,51,102,0.06)]'
                              : prediction.prediction === 'Suspicious'
                              ? 'bg-yellow-400/5 hover:bg-yellow-400/10 hover:shadow-[inset_0_0_20px_rgba(250,204,21,0.06)]'
                              : 'hover:bg-[#00ff88]/[0.07] hover:shadow-[inset_0_0_20px_rgba(0,255,136,0.05)]';
                          return (
                          <TableRow
                            key={prediction.id}
                            className={`border-[#1a2540]/60 cursor-pointer transition-all duration-200 ${rowBg}`}
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
                              <VerdictBadge source={prediction.source} size="text-[10px] py-0" title={prediction.snort_msg || ''} />
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={prediction.prediction === 'Malicious' ? 'destructive' : 'default'}
                                className={predClass}
                              >
                                {prediction.prediction}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-gray-300 font-mono text-xs max-w-[200px] truncate" title={prediction.attack_type || ''}>
                              {prediction.attack_type || <span className="text-gray-600">-</span>}
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
                        );})}
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
        </motion.div>
      </div>
    </div>
  );
}
