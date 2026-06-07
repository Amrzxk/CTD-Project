import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Badge } from './ui/badge';
import { VerdictBadge } from './VerdictBadge';
import type { LivePacket } from '../types/threat';

interface Props {
  packets: LivePacket[];
  selectedId: string | null;
  onSelect: (pkt: LivePacket) => void;
}

// Prediction column dropped — every verdict already implies it
// (confirmed/signature_only → Malicious, ml_only → Suspicious). The
// subtype column gets the freed horizontal budget so leaf names like
// "DoS-SlowHTTPTest" render in full instead of truncating to "Dr...".
const COLUMNS = [
  'time', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
  'proto', 'source', 'family', 'subtype', 'confidence', 'severity',
];

// Matched header + row grid so columns stay aligned. `minmax(0, …)` on
// every track is the non-obvious part: grid items default to
// `min-width: auto`, which means a long unbreakable word like
// "BotnetInfiltration" would push its column wider than its declared
// size and squash neighbouring 1fr tracks down to a single character.
// `minmax(0, X)` lets the cell honour its truncate class instead.
const GRID_TEMPLATE =
  'minmax(0, 95px) minmax(0, 115px) minmax(0, 115px) minmax(0, 65px) ' +
  'minmax(0, 65px) minmax(0, 55px) minmax(0, 95px) minmax(0, 140px) ' +
  'minmax(0, 1fr) minmax(0, 70px) minmax(0, 75px)';

const ROW_HEIGHT = 28;

function rowBgClass(pkt: LivePacket, selected: boolean): string {
  if (selected) return 'ring-1 ring-inset ring-sev-low bg-sev-low/5';
  switch (pkt.source) {
    case 'confirmed':
      return 'hover:bg-sev-high/10';
    case 'signature_only':
      return 'hover:bg-sev-med/10';
    case 'ml_only':
      return 'hover:bg-sev-med/10';
    default:
      return 'hover:bg-line/40';
  }
}

/** Virtualized event table — only the visible window's worth of rows
 *  is rendered to the DOM, so a 2000-row ring buffer costs constant
 *  memory regardless of how long the session has been running. */
export function LiveEventTable({ packets, selectedId, onSelect }: Props) {
  const parentRef = useRef<HTMLDivElement>(null);

  const rowVirtualizer = useVirtualizer({
    count: packets.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 8,
  });

  return (
    <div className="rounded-lg border border-line overflow-hidden bg-bg">
      {/* Sticky header */}
      <div
        className="grid bg-bg border-b border-line sticky top-0 z-10"
        style={{ gridTemplateColumns: GRID_TEMPLATE }}
      >
        {COLUMNS.map((c) => (
          <div
            key={c}
            className="px-2 py-1.5 text-[11px] text-brand font-semibold whitespace-nowrap min-w-0 truncate"
          >
            {c}
          </div>
        ))}
      </div>

      {/* Virtual list */}
      <div
        ref={parentRef}
        className="overflow-y-auto"
        style={{ height: 540 }}
      >
        {packets.length === 0 ? (
          <div className="flex items-center justify-center h-[200px] text-faint text-sm">
            Waiting for events…
          </div>
        ) : (
          <div
            style={{
              height: rowVirtualizer.getTotalSize(),
              width: '100%',
              position: 'relative',
            }}
          >
            {rowVirtualizer.getVirtualItems().map((virtualRow) => {
              const pkt = packets[virtualRow.index];
              if (!pkt) return null;
              const selected = selectedId === pkt.id;
              return (
                <div
                  key={pkt.id}
                  className={`grid border-b border-line/40 cursor-pointer transition-colors ${rowBgClass(
                    pkt,
                    selected,
                  )}`}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: ROW_HEIGHT,
                    transform: `translateY(${virtualRow.start}px)`,
                    gridTemplateColumns: GRID_TEMPLATE,
                  }}
                  onClick={() => onSelect(pkt)}
                >
                  <div className="px-2 py-1 text-muted-foreground font-mono text-[11px] whitespace-nowrap truncate min-w-0">
                    {pkt.timestamp ? new Date(pkt.timestamp).toLocaleTimeString() : '-'}
                  </div>
                  <div className="px-2 py-1 text-foreground font-mono text-[11px] whitespace-nowrap truncate min-w-0">
                    {pkt.src_ip}
                  </div>
                  <div className="px-2 py-1 text-foreground font-mono text-[11px] whitespace-nowrap truncate min-w-0">
                    {pkt.dst_ip}
                  </div>
                  <div className="px-2 py-1 text-muted-foreground text-[11px] truncate min-w-0">{pkt.src_port}</div>
                  <div className="px-2 py-1 text-muted-foreground text-[11px] truncate min-w-0">{pkt.dst_port}</div>
                  <div className="px-2 py-1 text-foreground text-[11px] truncate min-w-0">{pkt.protocol}</div>
                  <div className="px-2 py-1 min-w-0">
                    <VerdictBadge
                      source={pkt.source}
                      size="text-[9px] py-0"
                      title={pkt.snort_msg || ''}
                    />
                  </div>
                  <div className="px-2 py-1 text-muted-foreground text-[11px] truncate min-w-0">
                    {pkt.family || (pkt.source === 'signature_only' ? 'Snort' : '-')}
                  </div>
                  <div
                    className="px-2 py-1 text-foreground font-mono text-[11px] truncate min-w-0"
                    title={pkt.subtype || pkt.snort_msg || ''}
                  >
                    {pkt.subtype ||
                      (pkt.source === 'signature_only' ? pkt.snort_msg : '') ||
                      '-'}
                  </div>
                  <div className="px-2 py-1 text-foreground font-mono text-[11px] truncate min-w-0">
                    {(pkt.confidence * 100).toFixed(1)}%
                  </div>
                  <div className="px-2 py-1 min-w-0">
                    {pkt.severity ? (
                      <Badge
                        variant="outline"
                        className={`text-[9px] py-0 ${
                          pkt.severity === 'High'
                            ? 'border-sev-high/50 text-sev-high'
                            : pkt.severity === 'Medium'
                              ? 'border-sev-med/50 text-sev-med'
                              : 'border-sev-low/50 text-sev-low'
                        }`}
                      >
                        {pkt.severity}
                      </Badge>
                    ) : (
                      <span className="text-faint">-</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
