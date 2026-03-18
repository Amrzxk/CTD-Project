import React, { useState, useEffect, useMemo } from 'react';
import { Target, ExternalLink, Shield, ChevronDown, Info, Zap, Layers, Search, X } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { getMitreMatrix } from '../services/threatDetectionService';
import type { MitreMatrixData, MitreMatrixEntry, MitreTechnique } from '../types/threat';

// ─── Design tokens ────────────────────────────────────────────────────────────

const CATEGORY_COLORS: Record<string, { accent: string; glow: string }> = {
  DoS:            { accent: '#ff3366', glow: 'rgba(255,51,102,0.15)' },
  Reconnaissance: { accent: '#00ccff', glow: 'rgba(0,204,255,0.15)' },
  Exploits:       { accent: '#ff6633', glow: 'rgba(255,102,51,0.15)' },
  Fuzzers:        { accent: '#ffaa00', glow: 'rgba(255,170,0,0.15)'  },
  Backdoor:       { accent: '#cc66ff', glow: 'rgba(204,102,255,0.15)'},
  Shellcode:      { accent: '#ff3366', glow: 'rgba(255,51,102,0.15)' },
  Worms:          { accent: '#00ff88', glow: 'rgba(0,255,136,0.15)'  },
  Generic:        { accent: '#00ccff', glow: 'rgba(0,204,255,0.15)'  },
  Analysis:       { accent: '#ffaa00', glow: 'rgba(255,170,0,0.15)'  },
};

const TACTIC_COLORS: Record<string, string> = {
  TA0043: '#00ccff',
  TA0001: '#ff6633',
  TA0002: '#ffaa00',
  TA0003: '#cc66ff',
  TA0004: '#ff3366',
  TA0007: '#00ccff',
  TA0008: '#33ffaa',
  TA0009: '#00ccff',
  TA0011: '#cc66ff',
  TA0040: '#ff3366',
};

const BAND_CONFIG = {
  low:       { label: '70–85%',  color: '#ffaa00', desc: 'Low Confidence'  },
  high:      { label: '85–95%',  color: '#00ccff', desc: 'High Confidence' },
  very_high: { label: '95–100%', color: '#00ff88', desc: 'Very High'       },
};

const CATEGORY_ICONS: Record<string, string> = {
  DoS:            '⚡',
  Reconnaissance: '🔍',
  Exploits:       '💥',
  Fuzzers:        '🌀',
  Backdoor:       '🚪',
  Shellcode:      '💻',
  Worms:          '🪱',
  Generic:        '⚠️',
  Analysis:       '📡',
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function TechniqueChip({ tech, color }: { tech: MitreTechnique; color: string }) {
  return (
    <a
      href={tech.url}
      target="_blank"
      rel="noopener noreferrer"
      className="group flex items-center gap-2 px-3 py-2 rounded-lg border transition-all duration-200 hover:scale-[1.02] hover:shadow-lg"
      style={{
        borderColor: `${color}25`,
        background: `linear-gradient(135deg, ${color}0a 0%, transparent 100%)`,
      }}
      onMouseEnter={e => {
        (e.currentTarget as HTMLElement).style.borderColor = `${color}55`;
        (e.currentTarget as HTMLElement).style.background = `linear-gradient(135deg, ${color}18 0%, transparent 100%)`;
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLElement).style.borderColor = `${color}25`;
        (e.currentTarget as HTMLElement).style.background = `linear-gradient(135deg, ${color}0a 0%, transparent 100%)`;
      }}
    >
      <code
        className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded shrink-0"
        style={{ color, backgroundColor: `${color}18` }}
      >
        {tech.id}
      </code>
      <span className="text-xs text-gray-300 leading-tight flex-1 min-w-0 truncate">{tech.name}</span>
      <ExternalLink
        className="w-3 h-3 shrink-0 opacity-0 group-hover:opacity-60 transition-opacity"
        style={{ color }}
      />
    </a>
  );
}

function TacticBlock({
  tactic,
  color,
}: {
  tactic: MitreMatrixEntry['tactics'][0];
  color: string;
}) {
  const tacticColor = TACTIC_COLORS[tactic.id] || color;
  return (
    <div className="space-y-2">
      {/* Tactic header */}
      <div className="flex items-center gap-2.5">
        <div className="w-0.5 h-5 rounded-full shrink-0" style={{ backgroundColor: tacticColor }} />
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xs font-bold tracking-wide uppercase" style={{ color: tacticColor }}>
            {tactic.name}
          </span>
          <code className="text-[9px] font-mono text-gray-600 shrink-0">{tactic.id}</code>
        </div>
        <div
          className="ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded shrink-0"
          style={{ color: tacticColor, backgroundColor: `${tacticColor}15` }}
        >
          {tactic.techniques.length}
        </div>
      </div>
      {/* Technique grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-1.5 pl-3">
        {tactic.techniques.map(tech => (
          <TechniqueChip key={tech.id} tech={tech} color={tacticColor} />
        ))}
      </div>
    </div>
  );
}

function CategoryRow({
  entry,
  index,
  isExpanded,
  onToggle,
}: {
  entry: MitreMatrixEntry;
  index: number;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const colors = CATEGORY_COLORS[entry.category] ?? { accent: '#00ccff', glow: 'rgba(0,204,255,0.15)' };
  const totalTechniques = entry.tactics.reduce((s, t) => s + t.techniques.length, 0);
  const icon = CATEGORY_ICONS[entry.category] ?? '🛡️';

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.04 }}
      className="rounded-xl border overflow-hidden transition-all duration-300"
      style={{
        borderColor: isExpanded ? `${colors.accent}35` : 'rgba(26,37,64,0.8)',
        background: isExpanded
          ? `linear-gradient(135deg, ${colors.glow} 0%, rgba(15,24,37,0.95) 40%)`
          : 'rgba(10,16,28,0.6)',
        boxShadow: isExpanded ? `0 0 30px ${colors.glow}` : 'none',
      }}
    >
      {/* Row header — always visible */}
      <button
        onClick={onToggle}
        className="w-full text-left px-5 py-4 flex items-center gap-4 group transition-colors"
      >
        {/* Icon bubble */}
        <div
          className="w-10 h-10 rounded-xl flex items-center justify-center text-lg shrink-0 transition-all duration-300"
          style={{
            background: isExpanded ? `${colors.accent}20` : 'rgba(26,37,64,0.6)',
            boxShadow: isExpanded ? `0 0 16px ${colors.accent}30` : 'none',
          }}
        >
          {icon}
        </div>

        {/* Name + description */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5">
            <h3
              className="text-sm font-bold tracking-wide transition-colors duration-200"
              style={{ color: isExpanded ? colors.accent : '#e2e8f0' }}
            >
              {entry.category}
            </h3>
          </div>
          <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed truncate pr-4">
            {entry.description}
          </p>
        </div>

        {/* Tactic pills */}
        <div className="hidden lg:flex items-center gap-1.5 shrink-0">
          {entry.tactics.map(t => {
            const tc = TACTIC_COLORS[t.id] || colors.accent;
            return (
              <span
                key={t.id}
                className="text-[9px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full border"
                style={{ color: tc, borderColor: `${tc}40`, backgroundColor: `${tc}10` }}
              >
                {t.name}
              </span>
            );
          })}
        </div>

        {/* Stats + chevron */}
        <div className="flex items-center gap-3 shrink-0 ml-2">
          <div className="text-right hidden sm:block">
            <div className="text-xs font-bold" style={{ color: colors.accent }}>
              {totalTechniques}
            </div>
            <div className="text-[9px] text-gray-600 uppercase tracking-wider">techniques</div>
          </div>
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center transition-all duration-300"
            style={{
              background: isExpanded ? `${colors.accent}20` : 'rgba(26,37,64,0.6)',
              transform: isExpanded ? 'rotate(0deg)' : 'rotate(-90deg)',
            }}
          >
            <ChevronDown className="w-3.5 h-3.5" style={{ color: isExpanded ? colors.accent : '#4b5563' }} />
          </div>
        </div>
      </button>

      {/* Expanded content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            {/* Divider */}
            <div className="mx-5 h-px" style={{ background: `linear-gradient(90deg, ${colors.accent}30, transparent)` }} />

            <div className="px-5 py-4 space-y-5">
              {entry.tactics.map(tactic => (
                <TacticBlock key={tactic.id} tactic={tactic} color={colors.accent} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function StatCard({ value, label, color }: { value: number | string; label: string; color: string }) {
  return (
    <div
      className="rounded-xl p-4 border text-center"
      style={{ borderColor: `${color}25`, background: `linear-gradient(135deg, ${color}08 0%, transparent 100%)` }}
    >
      <div className="text-3xl font-black tabular-nums" style={{ color }}>{value}</div>
      <div className="text-[11px] text-gray-500 mt-1 uppercase tracking-wider font-medium">{label}</div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function MitrePage() {
  const [matrix, setMatrix] = useState<MitreMatrixData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [filterTactic, setFilterTactic] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  useEffect(() => {
    getMitreMatrix()
      .then(data => {
        setMatrix(data);
        // Open first entry by default
        if (data.entries.length > 0) {
          setExpandedCategories(new Set([data.entries[0].category]));
        }
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const toggleCategory = (cat: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      next.has(cat) ? next.delete(cat) : next.add(cat);
      return next;
    });
  };

  const allTactics = useMemo(
    () => matrix
      ? [...new Map(matrix.entries.flatMap(e => e.tactics).map(t => [t.id, t])).values()]
      : [],
    [matrix]
  );

  const totalUniqueTechniques = useMemo(
    () => matrix
      ? new Set(matrix.entries.flatMap(e => e.tactics.flatMap(t => t.techniques.map(te => te.id)))).size
      : 0,
    [matrix]
  );

  const filteredEntries = useMemo(() => {
    if (!matrix) return [];
    return matrix.entries.filter(entry => {
      const matchesTactic = !filterTactic || entry.tactics.some(t => t.id === filterTactic);
      const matchesSearch = !search.trim() ||
        entry.category.toLowerCase().includes(search.toLowerCase()) ||
        entry.description.toLowerCase().includes(search.toLowerCase()) ||
        entry.tactics.some(t =>
          t.name.toLowerCase().includes(search.toLowerCase()) ||
          t.techniques.some(te => te.name.toLowerCase().includes(search.toLowerCase()) || te.id.toLowerCase().includes(search.toLowerCase()))
        );
      return matchesTactic && matchesSearch;
    });
  }, [matrix, filterTactic, search]);

  // ── Loading ──
  if (loading) {
    return (
      <div className="flex items-center justify-center h-[70vh]">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-[#ff3366]/20 animate-ping" />
            <div className="absolute inset-2 rounded-full border-2 border-[#ff3366]/40 animate-pulse" />
            <div className="absolute inset-0 flex items-center justify-center">
              <Target className="w-6 h-6 text-[#ff3366]" />
            </div>
          </div>
          <p className="text-sm text-gray-500 tracking-widest uppercase">Loading MITRE ATT&CK</p>
        </div>
      </div>
    );
  }

  // ── Error ──
  if (error || !matrix) {
    return (
      <div className="flex items-center justify-center h-[70vh]">
        <div className="flex flex-col items-center gap-4 text-center max-w-sm">
          <div className="w-16 h-16 rounded-2xl bg-[#ff3366]/10 border border-[#ff3366]/20 flex items-center justify-center">
            <Shield className="w-7 h-7 text-[#ff3366]" />
          </div>
          <div>
            <p className="text-white font-semibold">Failed to load MITRE data</p>
            <p className="text-sm text-gray-500 mt-1">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  const allExpanded = filteredEntries.every(e => expandedCategories.has(e.category));

  return (
    <div className="min-h-screen bg-[#050810]">
      {/* Background ambient glow */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-40 -right-40 w-96 h-96 rounded-full bg-[#ff3366]/5 blur-3xl" />
        <div className="absolute top-1/2 -left-40 w-80 h-80 rounded-full bg-[#00ccff]/4 blur-3xl" />
      </div>

      <div className="relative container mx-auto px-4 py-8 max-w-6xl space-y-6">

        {/* ── Header ── */}
        <motion.div initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div
                className="w-12 h-12 rounded-2xl flex items-center justify-center shrink-0"
                style={{ background: 'linear-gradient(135deg, rgba(255,51,102,0.25), rgba(255,51,102,0.08))', border: '1px solid rgba(255,51,102,0.3)', boxShadow: '0 0 24px rgba(255,51,102,0.15)' }}
              >
                <Target className="w-6 h-6 text-[#ff3366]" />
              </div>
              <div>
                <h1 className="text-xl font-black text-white tracking-tight">MITRE ATT&CK Mapping</h1>
                <p className="text-xs text-gray-500 mt-0.5">
                  {matrix.framework} &nbsp;·&nbsp; {matrix.entries.length} attack categories
                </p>
              </div>
            </div>

            {/* Expand / Collapse */}
            <button
              onClick={() =>
                allExpanded
                  ? setExpandedCategories(new Set())
                  : setExpandedCategories(new Set(filteredEntries.map(e => e.category)))
              }
              className="flex items-center gap-2 text-xs px-4 py-2 rounded-lg border border-[#1a2540] text-gray-400 hover:text-white hover:border-[#2a3550] transition-all"
            >
              <Layers className="w-3.5 h-3.5" />
              {allExpanded ? 'Collapse All' : 'Expand All'}
            </button>
          </div>
        </motion.div>

        {/* ── Stats row ── */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.05 }}
          className="grid grid-cols-3 gap-3"
        >
          <StatCard value={matrix.entries.length} label="Attack Categories" color="#ff3366" />
          <StatCard value={allTactics.length} label="Unique Tactics" color="#00ccff" />
          <StatCard value={totalUniqueTechniques} label="Unique Techniques" color="#00ff88" />
        </motion.div>

        {/* ── Confidence threshold banner ── */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="rounded-xl border border-[#1a2540] bg-[#0a1018]/80 px-5 py-3.5 flex flex-col sm:flex-row sm:items-center gap-3"
        >
          <div className="flex items-center gap-2.5 shrink-0">
            <div className="w-7 h-7 rounded-lg bg-[#00ccff]/10 border border-[#00ccff]/20 flex items-center justify-center">
              <Info className="w-3.5 h-3.5 text-[#00ccff]" />
            </div>
            <span className="text-xs font-semibold text-gray-300">
              Confidence threshold: <span className="text-[#00ccff]">{(matrix.min_confidence * 100).toFixed(0)}%</span>
            </span>
          </div>
          <div className="w-px h-4 bg-[#1a2540] hidden sm:block" />
          <div className="flex flex-wrap items-center gap-3">
            {Object.entries(BAND_CONFIG).map(([key, band]) => (
              <div key={key} className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: band.color, boxShadow: `0 0 6px ${band.color}` }} />
                <span className="text-[11px] text-gray-500">
                  <span style={{ color: band.color }}>{band.desc}</span>
                  <span className="text-gray-600 ml-1">({band.label})</span>
                </span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* ── Search + Tactic filters ── */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.15 }}
          className="space-y-3"
        >
          {/* Search input */}
          <div className="relative">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search categories, tactics, techniques…"
              className="w-full bg-[#0a1018] border border-[#1a2540] rounded-xl pl-10 pr-10 py-2.5 text-sm text-gray-300 placeholder-gray-600 outline-none focus:border-[#2a3550] transition-colors"
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-400 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Tactic filter pills */}
          <div className="flex flex-wrap gap-1.5">
            <button
              onClick={() => setFilterTactic(null)}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-full border transition-all duration-200"
              style={{
                borderColor: !filterTactic ? 'rgba(255,255,255,0.25)' : '#1a2540',
                color: !filterTactic ? '#fff' : '#4b5563',
                background: !filterTactic ? 'rgba(255,255,255,0.08)' : 'transparent',
              }}
            >
              All Tactics
            </button>
            {allTactics.map(t => {
              const color = TACTIC_COLORS[t.id] || '#00ccff';
              const active = filterTactic === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setFilterTactic(active ? null : t.id)}
                  className="text-[11px] font-semibold px-3 py-1.5 rounded-full border transition-all duration-200"
                  style={{
                    borderColor: active ? `${color}60` : '#1a2540',
                    color: active ? color : '#4b5563',
                    background: active ? `${color}12` : 'transparent',
                    boxShadow: active ? `0 0 10px ${color}20` : 'none',
                  }}
                >
                  {t.name}
                </button>
              );
            })}
          </div>
        </motion.div>

        {/* ── Category list ── */}
        <div className="space-y-2">
          <AnimatePresence mode="popLayout">
            {filteredEntries.length === 0 ? (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-center py-16 text-gray-600"
              >
                <Zap className="w-8 h-8 mx-auto mb-3 opacity-30" />
                <p className="text-sm">No categories match your filters</p>
              </motion.div>
            ) : (
              filteredEntries.map((entry, i) => (
                <CategoryRow
                  key={entry.category}
                  entry={entry}
                  index={i}
                  isExpanded={expandedCategories.has(entry.category)}
                  onToggle={() => toggleCategory(entry.category)}
                />
              ))
            )}
          </AnimatePresence>
        </div>

        {/* ── Footer note ── */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="flex items-center justify-center gap-2 py-4 text-[11px] text-gray-700"
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Mapped to {matrix.framework} &nbsp;·&nbsp; Enrichment applied above {(matrix.min_confidence * 100).toFixed(0)}% model confidence</span>
        </motion.div>
      </div>
    </div>
  );
}
