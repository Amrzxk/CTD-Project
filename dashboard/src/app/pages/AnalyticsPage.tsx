import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { AlertTriangle, Shield, Activity, TrendingUp, BarChart3, Wifi } from 'lucide-react';
import { motion } from 'motion/react';
import { PieChart, Pie, Cell, LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { threatService } from '../services/threatDetectionService';
import type { AnalyticsData } from '../types/threat';

const RADIAN = Math.PI / 180;
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }: any) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 1.3;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="#e5e7eb" textAnchor={x > cx ? 'start' : 'end'} dominantBaseline="central" style={{ fontSize: '12px' }}>
      {`${name} ${(percent * 100).toFixed(1)}%`}
    </text>
  );
};

// Custom tooltip for Attack Category Distribution pie chart
const PieCategoryTooltip = ({ active, payload }: any) => {
  if (!active || !payload || !payload.length) return null;
  const { name, value, payload: entryPayload } = payload[0];
  const color = entryPayload?.color || '#00ff88';
  // Compute percentage from siblings
  const total = entryPayload?._total ?? value;
  const percent = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0';

  return (
    <div
      style={{
        background: 'linear-gradient(135deg, rgba(15,24,37,0.95), rgba(18,28,45,0.97))',
        border: `1px solid ${color}55`,
        borderRadius: '10px',
        padding: '12px 16px',
        boxShadow: `0 4px 24px rgba(0,0,0,0.5), 0 0 15px ${color}18`,
        backdropFilter: 'blur(12px)',
        minWidth: '140px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
        <span
          style={{
            width: '10px',
            height: '10px',
            borderRadius: '3px',
            backgroundColor: color,
            boxShadow: `0 0 6px ${color}80`,
            display: 'inline-block',
            flexShrink: 0,
          }}
        />
        <span style={{ color: '#f0f2f5', fontWeight: 600, fontSize: '13px' }}>{name}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', paddingLeft: '18px' }}>
        <span style={{ color, fontWeight: 700, fontSize: '18px', fontFamily: 'monospace' }}>{value}</span>
        <span style={{ color: '#9ca3af', fontSize: '12px' }}>({percent}%)</span>
      </div>
    </div>
  );
};

// Custom tooltip for Protocol Distribution bar chart
const ProtocolTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload || !payload.length) return null;
  const value = payload[0]?.value;
  return (
    <div
      style={{
        background: 'linear-gradient(135deg, rgba(15,24,37,0.95), rgba(18,28,45,0.97))',
        border: '1px solid rgba(0,255,166,0.35)',
        borderRadius: '10px',
        padding: '12px 16px',
        boxShadow: '0 4px 24px rgba(0,0,0,0.5), 0 0 15px rgba(0,255,166,0.1)',
        backdropFilter: 'blur(12px)',
        minWidth: '120px',
      }}
    >
      <div style={{ color: '#f0f2f5', fontWeight: 600, fontSize: '13px', marginBottom: '6px' }}>
        {label}
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
        <span style={{ color: '#9ca3af', fontSize: '12px' }}>Packets:</span>
        <span style={{ color: '#00FFA6', fontWeight: 700, fontSize: '16px', fontFamily: 'monospace' }}>
          {value?.toLocaleString()}
        </span>
      </div>
    </div>
  );
};

export default function AnalyticsPage() {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAnalytics();
  }, []);

  const loadAnalytics = async () => {
    setLoading(true);
    try {
      const data = await threatService.getAnalytics();
      setAnalytics(data);
    } catch (error) {
      console.error('Failed to load analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] flex items-center justify-center">
        <div className="text-center">
          <Activity className="w-12 h-12 mx-auto mb-4 text-[#00ff88] animate-pulse" />
          <p className="text-gray-400">Loading analytics...</p>
        </div>
      </div>
    );
  }

  if (!analytics) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] flex items-center justify-center">
        <p className="text-gray-400">No analytics data available</p>
      </div>
    );
  }

  const totalThreats = analytics.normalCount + analytics.maliciousCount;
  const threatPercentage = totalThreats > 0 ? ((analytics.maliciousCount / totalThreats) * 100).toFixed(1) : 0;

  // Enrich attack categories with _total so the custom tooltip can compute %
  const attackCategoriesTotal = analytics.attackCategories.reduce((s, c) => s + c.value, 0);
  const enrichedAttackCategories = analytics.attackCategories.map(cat => ({
    ...cat,
    _total: attackCategoriesTotal,
  }));

  // Protocol distribution mock data
  const protocolData = [
    { name: 'TCP', count: Math.floor(totalThreats * 0.62), color: '#00ff88' },
    { name: 'UDP', count: Math.floor(totalThreats * 0.28), color: '#00ccff' },
    { name: 'ICMP', count: Math.floor(totalThreats * 0.10), color: '#ff3366' },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] py-12">
      <div className="container mx-auto px-4">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="mb-8">
            <h1 className="text-4xl font-bold text-white mb-2">Analytics Dashboard</h1>
            <p className="text-gray-400">Real-time threat intelligence and statistics</p>
          </div>

          {/* Summary Cards */}
          <div className="grid md:grid-cols-4 gap-6 mb-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              <Card className="bg-gradient-to-br from-[#ff3366]/15 to-[#ff3366]/5 border-[#ff3366]/40 backdrop-blur">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between mb-2">
                    <AlertTriangle className="w-8 h-8 text-[#ff3366]" />
                    <span className="text-xs text-[#ff3366] font-semibold">HIGH</span>
                  </div>
                  <p className="text-3xl font-bold text-white mb-1">
                    {analytics.severityCounts.high}
                  </p>
                  <p className="text-sm text-gray-400">High Severity Threats</p>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <Card className="bg-gradient-to-br from-yellow-500/15 to-yellow-600/5 border-yellow-500/40 backdrop-blur">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between mb-2">
                    <AlertTriangle className="w-8 h-8 text-yellow-400" />
                    <span className="text-xs text-yellow-400 font-semibold">MEDIUM</span>
                  </div>
                  <p className="text-3xl font-bold text-white mb-1">
                    {analytics.severityCounts.medium}
                  </p>
                  <p className="text-sm text-gray-400">Medium Severity Threats</p>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              <Card className="bg-gradient-to-br from-[#00ccff]/15 to-[#00ccff]/5 border-[#00ccff]/40 backdrop-blur">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between mb-2">
                    <Shield className="w-8 h-8 text-[#00ccff]" />
                    <span className="text-xs text-[#00ccff] font-semibold">LOW</span>
                  </div>
                  <p className="text-3xl font-bold text-white mb-1">
                    {analytics.severityCounts.low}
                  </p>
                  <p className="text-sm text-gray-400">Low Severity Threats</p>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
            >
              <Card className="bg-gradient-to-br from-[#00ff88]/15 to-[#00ff88]/5 border-[#00ff88]/40 backdrop-blur">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between mb-2">
                    <TrendingUp className="w-8 h-8 text-[#00ff88]" />
                    <span className="text-xs text-[#00ff88] font-semibold">RATE</span>
                  </div>
                  <p className="text-3xl font-bold text-white mb-1">
                    {threatPercentage}%
                  </p>
                  <p className="text-sm text-gray-400">Threat Detection Rate</p>
                </CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Charts Grid */}
          <div className="grid lg:grid-cols-2 gap-8 mb-8">
            {/* Pie Chart - Attack Category Distribution */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.5 }}
            >
              <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                <CardHeader>
                  <CardTitle className="text-white">Attack Category Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={enrichedAttackCategories}
                        cx="50%"
                        cy="50%"
                        labelLine={true}
                        label={renderCustomLabel}
                        outerRadius={100}
                        fill="#8884d8"
                        dataKey="value"
                        strokeWidth={2}
                        stroke="#0f1825"
                      >
                        {enrichedAttackCategories.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        content={<PieCategoryTooltip />}
                        wrapperStyle={{ outline: 'none', zIndex: 50 }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-5 gap-2 mt-4">
                    {analytics.attackCategories.map((cat) => (
                      <div key={cat.name} className="text-center p-2 rounded-lg" style={{ backgroundColor: `${cat.color}10`, border: `1px solid ${cat.color}30` }}>
                        <p className="text-lg font-bold text-white">{cat.value}</p>
                        <p className="text-xs text-gray-400">{cat.name}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            {/* Line Chart - Traffic Over Time (Normal + Suspicious) */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.6 }}
            >
              <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                <CardHeader>
                  <CardTitle className="text-white">Traffic Over Time</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={analytics.timelineData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" />
                      <XAxis
                        dataKey="time"
                        stroke="#9ca3af"
                        style={{ fontSize: '12px' }}
                      />
                      <YAxis
                        stroke="#9ca3af"
                        style={{ fontSize: '12px' }}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f1520',
                          border: '1px solid #1a2540',
                          borderRadius: '8px',
                          color: '#e5e7eb'
                        }}
                      />
                      <Legend />
                      <Line
                        type="monotone"
                        dataKey="normal"
                        stroke="#00ff88"
                        strokeWidth={2}
                        dot={{ fill: '#00ff88', r: 3 }}
                        name="Normal Traffic"
                      />
                      <Line
                        type="monotone"
                        dataKey="suspicious"
                        stroke="#ff3366"
                        strokeWidth={2}
                        dot={{ fill: '#ff3366', r: 3 }}
                        name="Suspicious Traffic"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Feature Importance Chart */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.65 }}
            className="mb-8"
          >
            <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <BarChart3 className="w-6 h-6 text-[#00ccff]" />
                  <CardTitle className="text-white">Top 10 Feature Importance</CardTitle>
                </div>
                <p className="text-sm text-gray-400 mt-1">Most influential ML features in threat detection model</p>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={400}>
                  <BarChart
                    data={analytics.featureImportance}
                    layout="vertical"
                    margin={{ left: 20, right: 30 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" horizontal={false} />
                    <XAxis
                      type="number"
                      stroke="#9ca3af"
                      style={{ fontSize: '12px' }}
                      domain={[0, 1]}
                      tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
                    />
                    <YAxis
                      type="category"
                      dataKey="feature"
                      stroke="#9ca3af"
                      style={{ fontSize: '13px', fontFamily: 'monospace' }}
                      width={70}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f1520',
                        border: '1px solid #1a2540',
                        borderRadius: '8px',
                        color: '#e5e7eb'
                      }}
                      formatter={(value: number) => [`${(value * 100).toFixed(1)}%`, 'Importance']}
                    />
                    <Bar
                      dataKey="importance"
                      name="Importance"
                      radius={[0, 6, 6, 0]}
                      fill="#00ff88"
                    />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>

          {/* Bottom Charts: Protocol Distribution + Top 5 Malicious IPs — side by side */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.7 }}
          >
            <div className="grid lg:grid-cols-2 gap-8">
              {/* Protocol Distribution — Bar Chart */}
              <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <Wifi className="w-5 h-5 text-[#00ccff]" />
                    <CardTitle className="text-white">Protocol Distribution</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={280}>
                    <BarChart data={protocolData} barCategoryGap="30%">
                      <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" />
                      <XAxis
                        dataKey="name"
                        stroke="#9ca3af"
                        style={{ fontSize: '12px' }}
                        tickLine={false}
                        axisLine={{ stroke: '#1a2540' }}
                      />
                      <YAxis
                        stroke="#9ca3af"
                        style={{ fontSize: '12px' }}
                        tickLine={false}
                        axisLine={{ stroke: '#1a2540' }}
                      />
                      <Tooltip
                        content={<ProtocolTooltip />}
                        wrapperStyle={{ outline: 'none', zIndex: 50 }}
                        cursor={{ fill: 'rgba(0,255,166,0.06)' }}
                      />
                      <Bar
                        dataKey="count"
                        name="Packets"
                        fill="#00FFA6"
                        radius={[8, 8, 0, 0]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              {/* Top 5 Malicious Source IPs — Horizontal Bar Chart */}
              <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <AlertTriangle className="w-5 h-5 text-[#ff3366]" />
                    <CardTitle className="text-white">Top 5 Malicious Source IPs</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  {analytics.topMaliciousIPs.length > 0 ? (
                    <ResponsiveContainer width="100%" height={280}>
                      <BarChart
                        data={analytics.topMaliciousIPs}
                        layout="vertical"
                        margin={{ left: 10, right: 20 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" horizontal={false} />
                        <XAxis
                          type="number"
                          stroke="#9ca3af"
                          style={{ fontSize: '12px' }}
                        />
                        <YAxis
                          type="category"
                          dataKey="ip"
                          stroke="#9ca3af"
                          style={{ fontSize: '11px', fontFamily: 'monospace' }}
                          width={110}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#0f1520',
                            border: '1px solid #1a2540',
                            borderRadius: '8px',
                            color: '#e5e7eb'
                          }}
                        />
                        <Bar
                          dataKey="count"
                          fill="#ff3366"
                          name="Threat Count"
                          radius={[0, 6, 6, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="text-center py-12">
                      <Shield className="w-12 h-12 mx-auto mb-4 text-gray-600" />
                      <p className="text-gray-500">No malicious IPs detected</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </motion.div>
        </motion.div>
      </div>
    </div>
  );
}