import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Target, ExternalLink, Shield, ChevronDown, ChevronRight, Info } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { getMitreMatrix } from '../services/threatDetectionService';
import type { MitreMatrixData, MitreMatrixEntry, MitreTechnique } from '../types/threat';

const TACTIC_COLORS: Record<string, string> = {
  'TA0043': '#ff3366',
  'TA0001': '#ff6633',
  'TA0002': '#ffaa00',
  'TA0003': '#cc66ff',
  'TA0004': '#ff3366',
  'TA0007': '#00ccff',
  'TA0008': '#33ffaa',
  'TA0009': '#00ccff',
  'TA0011': '#cc66ff',
  'TA0040': '#ff3366',
};

const BAND_STYLES: Record<string, { label: string; color: string; bg: string }> = {
  low:       { label: 'Low Confidence',  color: '#ffaa00', bg: 'rgba(255,170,0,0.1)' },
  high:      { label: 'High Confidence', color: '#00ff88', bg: 'rgba(0,255,136,0.1)' },
  very_high: { label: 'Very High',       color: '#00ccff', bg: 'rgba(0,204,255,0.1)' },
};

function TechniqueCard({ tech, color }: { tech: MitreTechnique; color: string }) {
  return (
    <a
      href={tech.url}
      target="_blank"
      rel="noopener noreferrer"
      className="group block p-3 rounded-lg border transition-all hover:scale-[1.02]"
      style={{
        borderColor: `${color}30`,
        background: `linear-gradient(135deg, ${color}08, transparent)`,
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <code className="text-[10px] px-1.5 py-0.5 rounded font-mono" style={{ color, backgroundColor: `${color}15` }}>
              {tech.id}
            </code>
            <ExternalLink className="w-3 h-3 text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
          <span className="text-xs text-gray-300 leading-relaxed">{tech.name}</span>
        </div>
      </div>
    </a>
  );
}

function CategorySection({ entry, isExpanded, onToggle }: {
  entry: MitreMatrixEntry;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const totalTechniques = entry.tactics.reduce((sum, t) => sum + t.techniques.length, 0);

  return (
    <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full text-left p-4 flex items-center justify-between hover:bg-[#1a2540]/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-[#ff3366]/15">
            <Shield className="w-4 h-4 text-[#ff3366]" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">{entry.category}</h3>
            <p className="text-[11px] text-gray-500 mt-0.5">{entry.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            {entry.tactics.map(t => {
              const color = TACTIC_COLORS[t.id] || '#00ccff';
              return (
                <Badge
                  key={t.id}
                  variant="outline"
                  className="text-[10px] py-0 border-opacity-40"
                  style={{ color, borderColor: `${color}60` }}
                >
                  {t.name}
                </Badge>
              );
            })}
          </div>
          <span className="text-[10px] text-gray-500 font-mono w-14 text-right">
            {totalTechniques} tech{totalTechniques !== 1 ? 's' : ''}
          </span>
          {isExpanded
            ? <ChevronDown className="w-4 h-4 text-gray-500" />
            : <ChevronRight className="w-4 h-4 text-gray-500" />
          }
        </div>
      </button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-4">
              {entry.tactics.map(tactic => {
                const color = TACTIC_COLORS[tactic.id] || '#00ccff';
                return (
                  <div key={tactic.id}>
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-1 h-4 rounded-full" style={{ backgroundColor: color }} />
                      <span className="text-xs font-semibold" style={{ color }}>{tactic.name}</span>
                      <code className="text-[10px] text-gray-600 font-mono">{tactic.id}</code>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 ml-3">
                      {tactic.techniques.map(tech => (
                        <TechniqueCard key={tech.id} tech={tech} color={color} />
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}

export default function MitrePage() {
  const [matrix, setMatrix] = useState<MitreMatrixData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [filterTactic, setFilterTactic] = useState<string | null>(null);

  useEffect(() => {
    getMitreMatrix()
      .then(setMatrix)
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const toggleCategory = (cat: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  const expandAll = () => {
    if (!matrix) return;
    setExpandedCategories(new Set(matrix.entries.map(e => e.category)));
  };

  const collapseAll = () => setExpandedCategories(new Set());

  const allTactics = matrix
    ? [...new Map(matrix.entries.flatMap(e => e.tactics).map(t => [t.id, t])).values()]
    : [];

  const filteredEntries = matrix?.entries.filter(entry => {
    if (!filterTactic) return true;
    return entry.tactics.some(t => t.id === filterTactic);
  }) ?? [];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="text-gray-500 flex flex-col items-center gap-3">
          <Target className="w-8 h-8 animate-pulse" />
          <span className="text-sm">Loading MITRE ATT&CK data...</span>
        </div>
      </div>
    );
  }

  if (error || !matrix) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="text-red-400 flex flex-col items-center gap-3">
          <Shield className="w-8 h-8" />
          <span className="text-sm">{error || 'Failed to load MITRE data'}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050810]">
      <div className="container mx-auto px-4 py-8 max-w-7xl space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[#ff3366]/15">
                  <Target className="w-6 h-6 text-[#ff3366]" />
                </div>
                MITRE ATT&CK Mapping
              </h1>
              <p className="text-sm text-gray-500 mt-2 ml-[52px]">
                Attack categories mapped to {matrix.framework} tactics and techniques
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={expandAll} className="text-xs text-gray-500 hover:text-gray-300 transition-colors px-2 py-1">
                Expand All
              </button>
              <span className="text-gray-700">|</span>
              <button onClick={collapseAll} className="text-xs text-gray-500 hover:text-gray-300 transition-colors px-2 py-1">
                Collapse All
              </button>
            </div>
          </div>
        </motion.div>

        {/* Info Banner */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <Card className="bg-[#0f1825]/50 border-[#1a2540]">
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <Info className="w-4 h-4 text-[#00ccff] mt-0.5 shrink-0" />
                <div className="text-xs text-gray-400 leading-relaxed">
                  <span className="text-gray-300 font-medium">Confidence threshold: {(matrix.min_confidence * 100).toFixed(0)}%</span>
                  {' '}&mdash; MITRE mappings are only applied when the ML model confidence exceeds this threshold.
                  <span className="ml-2">
                    {Object.entries(BAND_STYLES).map(([key, band]) => (
                      <span key={key} className="inline-flex items-center gap-1 mr-3">
                        <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: band.color }} />
                        <span style={{ color: band.color }}>{band.label}</span>
                      </span>
                    ))}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Tactic Filter */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="flex flex-wrap gap-2"
        >
          <button
            onClick={() => setFilterTactic(null)}
            className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
              !filterTactic
                ? 'bg-white/10 border-white/20 text-white'
                : 'border-[#1a2540] text-gray-500 hover:text-gray-300'
            }`}
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
                className="text-xs px-3 py-1.5 rounded-full border transition-colors"
                style={{
                  borderColor: active ? `${color}80` : '#1a2540',
                  color: active ? color : '#6b7280',
                  backgroundColor: active ? `${color}15` : 'transparent',
                }}
              >
                {t.name}
              </button>
            );
          })}
        </motion.div>

        {/* Category Cards */}
        <div className="space-y-3">
          {filteredEntries.map((entry, i) => (
            <motion.div
              key={entry.category}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.05 * i }}
            >
              <CategorySection
                entry={entry}
                isExpanded={expandedCategories.has(entry.category)}
                onToggle={() => toggleCategory(entry.category)}
              />
            </motion.div>
          ))}
        </div>

        {/* Summary Stats */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="bg-[#0f1825]/50 border-[#1a2540]">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-gray-400">Coverage Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center">
                  <span className="text-2xl font-bold text-white">{matrix.entries.length}</span>
                  <p className="text-[11px] text-gray-500 mt-1">Attack Categories</p>
                </div>
                <div className="text-center">
                  <span className="text-2xl font-bold text-[#00ccff]">{allTactics.length}</span>
                  <p className="text-[11px] text-gray-500 mt-1">Unique Tactics</p>
                </div>
                <div className="text-center">
                  <span className="text-2xl font-bold text-[#ff3366]">
                    {new Set(matrix.entries.flatMap(e => e.tactics.flatMap(t => t.techniques.map(te => te.id)))).size}
                  </span>
                  <p className="text-[11px] text-gray-500 mt-1">Unique Techniques</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
