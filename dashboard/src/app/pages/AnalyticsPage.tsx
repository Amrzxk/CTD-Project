import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { AlertTriangle, Shield, Activity, TrendingUp, BarChart3, Wifi } from 'lucide-react';
import { motion } from 'motion/react';
import { PieChart, Pie, Cell, LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { threatService } from '../services/threatDetectionService';
import type { AnalyticsData } from '../types/threat';

const RADIAN = Math.PI / 180;
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }: any) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 1.3;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
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

// Feature Dictionary for Tooltip linking packet data
const FEATURE_DESCRIPTIONS: Record<string, string> = {
  sbytes: "Source to destination bytes",
  dbytes: "Destination to source bytes",
  dur: "Record total duration",
  spkts: "Source to destination packet count",
  dpkts: "Destination to source packet count",
  sload: "Source bits per second",
  dload: "Destination bits per second",
  ct_srv_dst: "Connections with same service and destination",
  ct_srv_src: "Connections with same service and source",
  sttl: "Source to destination time to live value",
  dttl: "Destination to source time to live value",
  proto: "Transaction protocol",
  service: "Network service (http, ftp, dns, etc)",
  state: "Connection state",
  rate: "Transfer rate"
};

const FeatureTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload || !payload.length) return null;
  const value = payload[0]?.value;
  const desc = FEATURE_DESCRIPTIONS[label] || "Diagnostic ML feature metric";
  return (
    <div
      style={{
        background: 'linear-gradient(135deg, rgba(15,24,37,0.95), rgba(18,28,45,0.97))',
        border: '1px solid rgba(0,255,136,0.3)',
        borderRadius: '8px',
        padding: '12px 14px',
        boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
        backdropFilter: 'blur(10px)',
        minWidth: '220px',
      }}
    >
      <div style={{ color: '#00ff88', fontWeight: 600, fontSize: '14px', marginBottom: '4px', fontFamily: 'monospace' }}>
        {label}
      </div>
      <div style={{ color: '#9ca3af', fontSize: '12px', marginBottom: '8px' }}>
        {desc}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
        <span style={{ color: '#e5e7eb', fontSize: '12px' }}>Importance Score:</span>
        <span style={{ color: '#fff', fontWeight: 700, fontSize: '14px' }}>
          {(value * 100).toFixed(1)}%
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

  if (!analytics || (analytics.normalCount === 0 && analytics.maliciousCount === 0)) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] flex flex-col items-center justify-center p-4">
        <div className="text-center bg-[#0f1825]/70 p-8 rounded-2xl border border-[#1a2540] backdrop-blur max-w-md shadow-2xl">
          <Activity className="w-16 h-16 text-[#9ca3af] mx-auto mb-4 opacity-70" />
          <h2 className="text-2xl font-bold text-white mb-3">No analysis data available yet</h2>
          <p className="text-gray-400">
            Please upload a network traffic file or generate manual predictions to view your analytics dashboard.
          </p>
        </div>
      </div>
    );
  }

  const totalThreats = analytics.normalCount + analytics.maliciousCount;
  const threatPercentage = totalThreats > 0 ? ((analytics.maliciousCount / totalThreats) * 100).toFixed(1) : 0;

  // Enrich attack categories with specific percentage calculations
  const attackCategoriesTotal = analytics.attackCategories.reduce((s, c) => s + c.value, 0);
  const enrichedAttackCategories = analytics.attackCategories.map(cat => ({
    ...cat,
    _total: attackCategoriesTotal,
    calculatedPercent: attackCategoriesTotal > 0 ? (cat.value / attackCategoriesTotal) * 100 : 0
  }));

  // Prediction Distribution Donut Chart mapped dynamically
  const enrichedPredictionData = [
    { name: 'Normal', value: analytics.normalCount, color: '#00ff88', _total: totalThreats, calculatedPercent: totalThreats > 0 ? (analytics.normalCount / totalThreats) * 100 : 0 },
    { name: 'Malicious', value: analytics.maliciousCount, color: '#ff3366', _total: totalThreats, calculatedPercent: totalThreats > 0 ? (analytics.maliciousCount / totalThreats) * 100 : 0 }
  ];

  // Map maximum axis boundaries safely calculating ceiling traffic mapping dynamically properly scaling Y-Axis arrays mathematically perfectly.
  const maxTrafficValue = Math.max(...(analytics.timelineData || []).map(d => Math.max(d.normal, d.suspicious)), 0);

  // Protocol distribution from backend
  const protocolData = analytics.protocolDistribution || [];

  // Normalize mapping formatting raw packet features to mathematical percentages for layout rendering limits
  const rawFeatures = analytics.featureImportance || [];
  const maxFeatureValue = Math.max(...rawFeatures.map(f => f.importance), 0);
  const hasFeatureData = maxFeatureValue > 0;
  
  const normalizedFeatureImportance = rawFeatures.map(f => ({
    feature: f.feature,
    importance: hasFeatureData ? (f.importance / maxFeatureValue) : 0,
    rawValue: f.importance
  }));


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

            {/* Donut Chart - Prediction Distribution */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.6 }}
            >
              <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                <CardHeader>
                  <CardTitle className="text-white">Prediction Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={enrichedPredictionData}
                        cx="50%"
                        cy="50%"
                        innerRadius={65}
                        outerRadius={95}
                        labelLine={true}
                        label={renderCustomLabel}
                        fill="#8884d8"
                        dataKey="value"
                        strokeWidth={2}
                        stroke="#0f1825"
                      >
                        {enrichedPredictionData.map((entry, index) => (
                          <Cell key={`cell-pred-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        content={<PieCategoryTooltip />}
                        wrapperStyle={{ outline: 'none', zIndex: 50 }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-2 gap-4 mt-4">
                    {enrichedPredictionData.map((cat) => (
                      <div key={cat.name} className="flex items-center gap-3 p-3 rounded-lg" style={{ backgroundColor: `${cat.color}10`, border: `1px solid ${cat.color}30` }}>
                        <div className="w-12 h-12 rounded-full flex items-center justify-center font-bold" style={{ backgroundColor: `${cat.color}20`, color: cat.color }}>
                          {cat.calculatedPercent.toFixed(0)}%
                        </div>
                        <div>
                          <p className="text-xl font-bold" style={{ color: cat.color }}>{cat.value}</p>
                          <p className="text-xs text-gray-400">{cat.name}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Line Chart - Traffic Wave Visualization */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.65 }}
            className="mb-8"
          >
            <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur border-t-4 border-t-[#00ccff]">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Activity className="w-6 h-6 text-[#00ccff]" />
                    <CardTitle className="text-white">Traffic Wave Diagnostics</CardTitle>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={350}>
                  <LineChart data={analytics.timelineData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" />
                    <XAxis
                      dataKey="step"
                      stroke="#9ca3af"
                      style={{ fontSize: '12px' }}
                      tickMargin={10}
                    />
                    <YAxis
                      stroke="#9ca3af"
                      style={{ fontSize: '12px' }}
                      tickMargin={10}
                      domain={[0, maxTrafficValue > 0 ? maxTrafficValue : 'auto']}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f1520',
                        border: '1px solid #1a2540',
                        borderRadius: '8px',
                        color: '#e5e7eb',
                        boxShadow: '0 4px 20px rgba(0,0,0,0.5)'
                      }}
                    />
                    <Legend iconType="circle" wrapperStyle={{ paddingTop: "20px" }} />
                    <Line
                      type="monotone"
                      dataKey="normal"
                      stroke="#00ff88"
                      strokeWidth={3}
                      name="Normal Traffic"
                      dot={false}
                      activeDot={{ r: 6, strokeWidth: 0, fill: '#00ff88' }}
                      animationDuration={800}
                    />
                    <Line
                      type="monotone"
                      dataKey="suspicious"
                      stroke="#ff3366"
                      strokeWidth={3}
                      name="Suspicious / Malicious Traffic"
                      dot={false}
                      activeDot={{ r: 6, strokeWidth: 0, fill: '#ff3366' }}
                      animationDuration={800}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>

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
                {hasFeatureData ? (
                  <ResponsiveContainer width="100%" height={400}>
                    <BarChart
                      data={normalizedFeatureImportance}
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
                      <Tooltip content={<FeatureTooltip />} cursor={{ fill: 'rgba(0,255,136,0.05)' }} />
                      <Bar
                        dataKey="importance"
                        name="Importance"
                        radius={[0, 6, 6, 0]}
                        fill="#00ff88"
                      />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex flex-col items-center justify-center h-[400px] text-center border border-dashed border-[#1a2540] rounded-xl bg-[#111a2e]/30">
                    <BarChart3 className="w-10 h-10 text-gray-600 mb-3" />
                    <p className="text-gray-400 font-medium text-sm">No feature importance data available</p>
                    <p className="text-gray-600 text-xs mt-1">Upload a packet file to extract live metrics</p>
                  </div>
                )}
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