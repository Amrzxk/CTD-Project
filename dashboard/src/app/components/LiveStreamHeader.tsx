import { useRef } from 'react';
import { Database, Radio, Zap, ZapOff, Upload, FileDown, Trash2, AlertTriangle } from 'lucide-react';
import { Button } from './ui/button';
import { Checkbox } from './ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from './ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import type {
  DetectionMode,
  LiveSession,
  LiveSource,
  ReplaySpeed,
} from '../types/threat';

interface Props {
  active: LiveSession | null;
  connected: boolean;
  reconnecting: { attempt: number; in_ms: number } | null;
  // Form state (only meaningful while idle)
  source: LiveSource;
  setSource: (s: LiveSource) => void;
  mode: DetectionMode;
  setMode: (m: DetectionMode) => void;
  speed: ReplaySpeed;
  setSpeed: (s: ReplaySpeed) => void;
  persistToAlerts: boolean;
  setPersistToAlerts: (p: boolean) => void;
  // Actions
  onStart: () => void;
  onStop: () => void;
  onAttachPcap: (file: File) => void;
  onDownloadLog: (format: 'csv' | 'ndjson') => void;
  /** True when a current OR just-stopped session has a downloadable log. */
  logAvailable?: boolean;
  onClearView: () => void;
  // Stats
  eventCount: number;
  rateEps: number;
}

const SPEED_LABEL: Record<ReplaySpeed, string> = {
  1: '1x',
  2: '2x',
  10: '10x',
  0: 'Max',
};

/** Header strip with source/mode/speed controls + start/stop + log download.
 *
 *  Designed to read top-to-bottom: status pill, then the three orthogonal
 *  selectors (source / mode / speed), then the action buttons. Inputs are
 *  disabled while a session is active so the analyst can't half-mutate
 *  config underneath a running stream. */
export function LiveStreamHeader(props: Props) {
  const {
    active,
    connected,
    reconnecting,
    source,
    setSource,
    mode,
    setMode,
    speed,
    setSpeed,
    persistToAlerts,
    setPersistToAlerts,
    onStart,
    onStop,
    onAttachPcap,
    onDownloadLog,
    logAvailable,
    onClearView,
    eventCount,
    rateEps,
  } = props;

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const isActive = active !== null;
  const isPcap = source === 'pcap';
  const needsPcapAttach = isActive && active.source === 'pcap' && !active.pcap_attached;

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) onAttachPcap(f);
    e.target.value = '';
  };

  return (
    <div className="flex flex-col gap-4 p-4 rounded-lg border border-line bg-panel/70 backdrop-blur">
      {/* Status row */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <Radio
            className={`w-5 h-5 ${
              connected ? 'text-brand animate-pulse' : 'text-muted-foreground'
            }`}
          />
          <div className="flex flex-col">
            <span className="text-foreground font-semibold">Live Threat Stream</span>
            <span className="text-[11px] text-muted-foreground">
              {isActive
                ? `Session ${active.session_id.slice(0, 8)} • ${active.source}/${active.detection_mode}`
                : 'No active session'}
            </span>
          </div>
          {isActive && active.persist_to_alerts && (
            <span
              className="flex items-center gap-1.5 text-xs text-sev-low"
              title="Live events are being persisted to the Alerts queue"
            >
              <Database className="w-3.5 h-3.5" />
              Persisting
            </span>
          )}
          {connected && (
            <span className="flex items-center gap-1.5 text-xs text-brand">
              <span className="w-2 h-2 rounded-full animate-pulse bg-brand" />
              LIVE
            </span>
          )}
          {reconnecting && (
            <span className="flex items-center gap-1.5 text-xs text-sev-med">
              <AlertTriangle className="w-3.5 h-3.5" />
              Reconnecting #{reconnecting.attempt} ({Math.round(reconnecting.in_ms / 1000)}s)
            </span>
          )}
        </div>

        <div className="flex items-center gap-4 text-[11px] font-mono text-muted-foreground">
          <span>
            <span className="text-muted-foreground">EVENTS</span>{' '}
            <span className="text-foreground">{eventCount.toLocaleString()}</span>
          </span>
          <span>
            <span className="text-muted-foreground">EPS</span>{' '}
            <span className="text-foreground">{rateEps.toFixed(1)}</span>
          </span>
        </div>
      </div>

      {/* Controls row */}
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase tracking-wide text-muted-foreground">Source</label>
          <Select
            value={source}
            onValueChange={(v) => setSource(v as LiveSource)}
            disabled={isActive}
          >
            <SelectTrigger className="w-[170px] h-9 bg-line/60 border-line-strong text-foreground text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="interface">Live Interface</SelectItem>
              <SelectItem value="pcap">PCAP Replay</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase tracking-wide text-muted-foreground">Detection</label>
          <Select
            value={mode}
            onValueChange={(v) => setMode(v as DetectionMode)}
            disabled={isActive}
          >
            <SelectTrigger className="w-[170px] h-9 bg-line/60 border-line-strong text-foreground text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="hybrid">Hybrid (ML + Snort)</SelectItem>
              <SelectItem value="ml">ML only</SelectItem>
              <SelectItem value="snort">Snort only</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {isPcap && (
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase tracking-wide text-muted-foreground">Speed</label>
            <Select
              value={String(speed)}
              onValueChange={(v) => setSpeed(Number(v) as ReplaySpeed)}
              disabled={isActive}
            >
              <SelectTrigger className="w-[110px] h-9 bg-line/60 border-line-strong text-foreground text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">{SPEED_LABEL[1]} (real-time)</SelectItem>
                <SelectItem value="2">{SPEED_LABEL[2]}</SelectItem>
                <SelectItem value="10">{SPEED_LABEL[10]}</SelectItem>
                <SelectItem value="0">{SPEED_LABEL[0]}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}

        {!isActive && (
          <div className="flex flex-col gap-1">
            <label className="text-[10px] uppercase tracking-wide text-muted-foreground">
              Persist
            </label>
            <label
              className="flex items-center gap-2 h-9 px-2 rounded bg-line/60 border border-line-strong text-xs text-foreground cursor-pointer select-none"
              title={
                isPcap
                  ? 'PCAP findings stream into the Alerts queue (default on).'
                  : 'Interface mode is OFF by default — a busy NIC can flood Postgres. Toggle on if you want to triage this session in Alerts.'
              }
            >
              <Checkbox
                checked={persistToAlerts}
                onCheckedChange={(v) => setPersistToAlerts(v === true)}
              />
              <span>To Alerts</span>
            </label>
          </div>
        )}

        <div className="flex items-center gap-2 ml-auto">
          {!isActive && (
            <Button
              size="sm"
              onClick={onStart}
              className="bg-brand hover:bg-brand/80 text-[var(--on-brand)] font-semibold"
            >
              <Zap className="mr-1.5 h-3.5 w-3.5" />
              Start Session
            </Button>
          )}

          {needsPcapAttach && (
            <>
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng"
                className="hidden"
                onChange={handleFile}
              />
              <Button
                size="sm"
                onClick={() => fileInputRef.current?.click()}
                className="bg-sev-low hover:bg-sev-low/80 text-white font-semibold"
              >
                <Upload className="mr-1.5 h-3.5 w-3.5" />
                Upload PCAP
              </Button>
            </>
          )}

          {isActive && (
            <Button
              size="sm"
              variant="outline"
              onClick={onStop}
              className="border-sev-high text-sev-high hover:bg-sev-high/10"
            >
              <ZapOff className="mr-1.5 h-3.5 w-3.5" />
              Stop
            </Button>
          )}

          {(isActive || logAvailable) && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  size="sm"
                  variant="outline"
                  className="border-line-strong text-muted-foreground hover:bg-panel-raised"
                >
                  <FileDown className="mr-1.5 h-3.5 w-3.5" />
                  Download Log
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onClick={() => onDownloadLog('csv')}>
                  CSV (analyst summary)
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => onDownloadLog('ndjson')}>
                  NDJSON (full payload)
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}

          <Button
            size="sm"
            variant="ghost"
            onClick={onClearView}
            className="text-muted-foreground hover:text-foreground hover:bg-line"
            title="Clear visible events"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>
    </div>
  );
}
