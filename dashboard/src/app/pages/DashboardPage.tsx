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
    <div className="min-h-screen bg-gradient-to-br from-bg via-bg to-bg py-12">
      <div className="container mx-auto px-4">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          {/* Page Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-4xl font-bold text-foreground mb-2">Results Dashboard</h1>
              <p className="text-muted-foreground">
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
                className="border-sev-low text-sev-low hover:bg-sev-low/10"
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh
              </Button>
              <Button
                onClick={handleExport}
                className="bg-brand hover:bg-brand/80 text-[var(--on-brand)] font-semibold"
              >
                <Download className="mr-2 h-4 w-4" />
                Export CSV
              </Button>
            </div>
          </div>

          {/* Filters */}
          <Card className="bg-panel/70 border-line backdrop-blur mb-6">
            <CardContent className="py-6">
              <div className="grid md:grid-cols-3 gap-4">
                <div className="md:col-span-2">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                    <Input
                      placeholder="Search by IP address..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-10 bg-line/60 border-line-strong text-foreground"
                    />
                  </div>
                </div>
                <div>
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="bg-line/60 border-line-strong text-foreground">
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
          <Card className="bg-panel/70 border-line backdrop-blur mb-8">
            <CardHeader>
              <CardTitle className="text-foreground">Prediction Results</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="min-h-[520px]">
              {loading ? (
                <div className="flex flex-col items-center justify-center min-h-[520px]">
                  <RefreshCw className="w-12 h-12 mx-auto mb-4 text-faint animate-spin" />
                  <p className="text-muted-foreground">Loading predictions...</p>
                </div>
              ) : filteredPredictions.length === 0 ? (
                <div className="flex flex-col items-center justify-center min-h-[520px]">
                  <Shield className="w-12 h-12 mx-auto mb-4 text-faint" />
                  <p className="text-muted-foreground">No results match the selected filters</p>
                  <p className="text-sm text-faint mt-2">
                    Try adjusting your filters or upload some data
                  </p>
                </div>
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-line hover:bg-transparent">
                          <TableHead className="text-brand">Timestamp</TableHead>
                          <TableHead className="text-brand">Source IP</TableHead>
                          <TableHead className="text-brand">Destination IP</TableHead>
                          <TableHead className="text-brand">Protocol</TableHead>
                          <TableHead className="text-brand">Verdict</TableHead>
                          <TableHead className="text-brand">Prediction</TableHead>
                          <TableHead className="text-brand">Attack Type</TableHead>
                          <TableHead className="text-brand">Confidence</TableHead>
                          <TableHead className="text-brand">Severity</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {paginatedData.map((prediction) => {
                          const predClass =
                            prediction.prediction === 'Malicious'
                              ? 'bg-sev-high/20 text-sev-high border-sev-high/50'
                              : prediction.prediction === 'Suspicious'
                              ? 'bg-sev-med/15 text-sev-med border-sev-med/50'
                              : 'bg-brand/20 text-brand border-brand/50';
                          const rowBg =
                            prediction.prediction === 'Malicious'
                              ? 'bg-sev-high/5 hover:bg-sev-high/10 hover:shadow-[inset_0_0_20px_rgba(240,73,75,0.06)]'
                              : prediction.prediction === 'Suspicious'
                              ? 'bg-sev-med/5 hover:bg-sev-med/10 hover:shadow-[inset_0_0_20px_rgba(250,204,21,0.06)]'
                              : 'hover:bg-brand/[0.07] hover:shadow-[inset_0_0_20px_rgba(242,169,59,0.05)]';
                          return (
                          <TableRow
                            key={prediction.id}
                            className={`border-line/60 cursor-pointer transition-all duration-200 ${rowBg}`}
                            style={{ transition: 'background-color 0.2s ease, box-shadow 0.2s ease' }}
                          >
                            <TableCell className="text-foreground font-mono text-xs">
                              {formatDateTime(prediction.timestamp)}
                            </TableCell>
                            <TableCell className="text-foreground font-mono">
                              {prediction.sourceIp}
                            </TableCell>
                            <TableCell className="text-foreground font-mono">
                              {prediction.destinationIp}
                            </TableCell>
                            <TableCell className="text-foreground">
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
                            <TableCell className="text-foreground font-mono text-xs max-w-[200px] truncate" title={prediction.attack_type || ''}>
                              {prediction.attack_type || <span className="text-faint">-</span>}
                            </TableCell>
                            <TableCell className="text-foreground font-semibold">
                              {formatConfidence(prediction.confidence)}
                            </TableCell>
                            <TableCell>
                              {prediction.severity ? (
                                <Badge
                                  variant="outline"
                                  className={`${
                                    prediction.severity === 'High'
                                      ? 'border-sev-high/50 text-sev-high'
                                      : prediction.severity === 'Medium'
                                      ? 'border-sev-med/50 text-sev-med'
                                      : 'border-sev-low/50 text-sev-low'
                                  }`}
                                >
                                  {prediction.severity}
                                </Badge>
                              ) : (
                                <span className="text-faint">-</span>
                              )}
                            </TableCell>
                          </TableRow>
                        );})}
                      </TableBody>
                    </Table>
                  </div>

                  {totalPages > 1 && (
                    <div className="flex justify-between items-center mt-6 pt-6 border-t border-line">
                      <p className="text-sm text-muted-foreground">
                        Page {currentPage} of {totalPages}
                      </p>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                          disabled={currentPage === 1}
                          className="border-line-strong text-muted-foreground"
                        >
                          Previous
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                          disabled={currentPage === totalPages}
                          className="border-line-strong text-muted-foreground"
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
