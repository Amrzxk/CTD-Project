import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Shield, Loader2, AlertTriangle, CheckCircle2, Network, Globe, Activity, Radio, Clock } from 'lucide-react';
import { toast } from 'sonner';
import { motion } from 'motion/react';
import { threatService } from '../services/threatDetectionService';
import { isValidIPv4, isValidPort, formatConfidence } from '../utils/helpers';
import type { ManualInputForm, ThreatPrediction } from '../types/threat';
import { useNavigate } from 'react-router';

export default function ManualInputPage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ThreatPrediction | null>(null);
  const navigate = useNavigate();
  
  const { register, handleSubmit, setValue, watch, formState: { errors }, reset } = useForm<ManualInputForm>({
    defaultValues: {
      protocol: 'TCP',
      service: 'http',
    }
  });

  const protocol = watch('protocol');
  const service = watch('service');

  const onSubmit = async (data: ManualInputForm) => {
    setLoading(true);
    setResult(null);

    try {
      const prediction = await threatService.predictSingle(data);
      setResult(prediction);
      
      if (prediction.prediction === 'Malicious') {
        toast.error(`⚠️ Malicious threat detected! Severity: ${prediction.severity}`, {
          duration: 5000
        });
      } else {
        toast.success('✓ Normal traffic detected');
      }
    } catch (error) {
      toast.error('Failed to analyze data. Please try again.');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    reset();
    setResult(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] py-12">
      <div className="container mx-auto px-4 max-w-6xl">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="mb-8">
            <h1 className="text-4xl font-bold text-white mb-2">Manual Threat Analysis</h1>
            <p className="text-gray-400">Enter network connection details for real-time threat detection</p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            {/* Input Form */}
            <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
              <CardHeader>
                <CardTitle className="text-white">Network Flow Parameters</CardTitle>
                <CardDescription className="text-gray-400">
                  Enter network flow details matching the ML model input schema
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">

                  {/* ── Connection Details ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Globe className="w-4 h-4 text-[#00ccff]" />
                      <h3 className="text-sm text-[#00ccff] font-semibold tracking-wide uppercase">Connection Details</h3>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <Label htmlFor="sourceIp" className="text-gray-300">Source IP Address</Label>
                        <Input
                          id="sourceIp"
                          placeholder="192.168.1.100"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('sourceIp', {
                            required: 'Source IP is required',
                            validate: (value) => isValidIPv4(value) || 'Invalid IPv4 address format'
                          })}
                        />
                        {errors.sourceIp && (
                          <p className="text-red-400 text-sm mt-1">{errors.sourceIp.message}</p>
                        )}
                      </div>

                      <div>
                        <Label htmlFor="destinationIp" className="text-gray-300">Destination IP Address</Label>
                        <Input
                          id="destinationIp"
                          placeholder="10.0.0.50"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('destinationIp', {
                            required: 'Destination IP is required',
                            validate: (value) => isValidIPv4(value) || 'Invalid IPv4 address format'
                          })}
                        />
                        {errors.destinationIp && (
                          <p className="text-red-400 text-sm mt-1">{errors.destinationIp.message}</p>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="protocol" className="text-gray-300">Protocol</Label>
                          <Select value={protocol} onValueChange={(value) => setValue('protocol', value)}>
                            <SelectTrigger className="bg-[#1a2540]/60 border-[#253352] text-white">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="TCP">TCP</SelectItem>
                              <SelectItem value="UDP">UDP</SelectItem>
                              <SelectItem value="ICMP">ICMP</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        <div>
                          <Label htmlFor="service" className="text-gray-300">Service</Label>
                          <Select value={service} onValueChange={(value) => setValue('service', value)}>
                            <SelectTrigger className="bg-[#1a2540]/60 border-[#253352] text-white">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="http">http</SelectItem>
                              <SelectItem value="https">https</SelectItem>
                              <SelectItem value="dns">dns</SelectItem>
                              <SelectItem value="ftp">ftp</SelectItem>
                              <SelectItem value="ssh">ssh</SelectItem>
                              <SelectItem value="smtp">smtp</SelectItem>
                              <SelectItem value="imap">imap</SelectItem>
                              <SelectItem value="rdp">rdp</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* ── Ports ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Network className="w-4 h-4 text-[#00ccff]" />
                      <h3 className="text-sm text-[#00ccff] font-semibold tracking-wide uppercase">Ports</h3>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="sourcePort" className="text-gray-300">Source Port</Label>
                        <Input
                          id="sourcePort"
                          type="number"
                          placeholder="8080"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('sourcePort', {
                            required: 'Source port is required',
                            valueAsNumber: true,
                            validate: (value) => isValidPort(value) || 'Port must be between 0-65535'
                          })}
                        />
                        {errors.sourcePort && (
                          <p className="text-red-400 text-sm mt-1">{errors.sourcePort.message}</p>
                        )}
                      </div>
                      <div>
                        <Label htmlFor="destinationPort" className="text-gray-300">Destination Port</Label>
                        <Input
                          id="destinationPort"
                          type="number"
                          placeholder="443"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('destinationPort', {
                            required: 'Destination port is required',
                            valueAsNumber: true,
                            validate: (value) => isValidPort(value) || 'Port must be between 0-65535'
                          })}
                        />
                        {errors.destinationPort && (
                          <p className="text-red-400 text-sm mt-1">{errors.destinationPort.message}</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* ── Traffic Metrics ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Activity className="w-4 h-4 text-[#00ff88]" />
                      <h3 className="text-sm text-[#00ff88] font-semibold tracking-wide uppercase">Traffic Metrics</h3>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <Label htmlFor="duration" className="text-gray-300">Duration (seconds)</Label>
                        <Input
                          id="duration"
                          type="number"
                          step="0.01"
                          placeholder="5.2"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('duration', {
                            required: 'Duration is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' }
                          })}
                        />
                        {errors.duration && (
                          <p className="text-red-400 text-sm mt-1">{errors.duration.message}</p>
                        )}
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="sourceBytes" className="text-gray-300">Source Bytes</Label>
                          <Input
                            id="sourceBytes"
                            type="number"
                            placeholder="2048"
                            className="bg-[#1a2540]/60 border-[#253352] text-white"
                            {...register('sourceBytes', {
                              required: 'Source bytes is required',
                              valueAsNumber: true,
                              min: { value: 0, message: 'Must be 0 or greater' }
                            })}
                          />
                          {errors.sourceBytes && (
                            <p className="text-red-400 text-sm mt-1">{errors.sourceBytes.message}</p>
                          )}
                        </div>
                        <div>
                          <Label htmlFor="destinationBytes" className="text-gray-300">Destination Bytes</Label>
                          <Input
                            id="destinationBytes"
                            type="number"
                            placeholder="4096"
                            className="bg-[#1a2540]/60 border-[#253352] text-white"
                            {...register('destinationBytes', {
                              required: 'Destination bytes is required',
                              valueAsNumber: true,
                              min: { value: 0, message: 'Must be 0 or greater' }
                            })}
                          />
                          {errors.destinationBytes && (
                            <p className="text-red-400 text-sm mt-1">{errors.destinationBytes.message}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* ── Packet Metrics ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Radio className="w-4 h-4 text-[#00ff88]" />
                      <h3 className="text-sm text-[#00ff88] font-semibold tracking-wide uppercase">Packet Metrics</h3>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="sourcePackets" className="text-gray-300">Source Packets</Label>
                        <Input
                          id="sourcePackets"
                          type="number"
                          placeholder="12"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('sourcePackets', {
                            required: 'Source packets is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' }
                          })}
                        />
                        {errors.sourcePackets && (
                          <p className="text-red-400 text-sm mt-1">{errors.sourcePackets.message}</p>
                        )}
                      </div>
                      <div>
                        <Label htmlFor="destinationPackets" className="text-gray-300">Destination Packets</Label>
                        <Input
                          id="destinationPackets"
                          type="number"
                          placeholder="8"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('destinationPackets', {
                            required: 'Destination packets is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' }
                          })}
                        />
                        {errors.destinationPackets && (
                          <p className="text-red-400 text-sm mt-1">{errors.destinationPackets.message}</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* ── TTL Metrics ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Clock className="w-4 h-4 text-[#ff3366]" />
                      <h3 className="text-sm text-[#ff3366] font-semibold tracking-wide uppercase">TTL Metrics</h3>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="sourceTTL" className="text-gray-300">Source TTL</Label>
                        <Input
                          id="sourceTTL"
                          type="number"
                          placeholder="64"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('sourceTTL', {
                            required: 'Source TTL is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' },
                            max: { value: 255, message: 'Max TTL is 255' }
                          })}
                        />
                        {errors.sourceTTL && (
                          <p className="text-red-400 text-sm mt-1">{errors.sourceTTL.message}</p>
                        )}
                      </div>
                      <div>
                        <Label htmlFor="destinationTTL" className="text-gray-300">Destination TTL</Label>
                        <Input
                          id="destinationTTL"
                          type="number"
                          placeholder="128"
                          className="bg-[#1a2540]/60 border-[#253352] text-white"
                          {...register('destinationTTL', {
                            required: 'Destination TTL is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' },
                            max: { value: 255, message: 'Max TTL is 255' }
                          })}
                        />
                        {errors.destinationTTL && (
                          <p className="text-red-400 text-sm mt-1">{errors.destinationTTL.message}</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-3 pt-4">
                    <Button
                      type="submit"
                      disabled={loading}
                      className="flex-1 bg-[#00ff88] hover:bg-[#00ff88]/80 text-gray-900 font-semibold"
                    >
                      {loading ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Analyzing...
                        </>
                      ) : (
                        <>
                          <Shield className="mr-2 h-4 w-4" />
                          Analyze Threat
                        </>
                      )}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={handleReset}
                      className="border-gray-600 text-gray-400"
                    >
                      Reset
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>

            {/* Results Display */}
            <div className="space-y-6">
              {!result && !loading && (
                <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                  <CardContent className="py-12">
                    <div className="text-center">
                      <Shield className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                      <p className="text-gray-500">No analysis yet</p>
                      <p className="text-sm text-gray-500 mt-2">
                        Fill in the form and click "Analyze Threat" to get results
                      </p>
                    </div>
                  </CardContent>
                </Card>
              )}

              {loading && (
                <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                  <CardContent className="py-12">
                    <div className="text-center">
                      <Loader2 className="w-16 h-16 mx-auto mb-4 text-[#00ff88] animate-spin" />
                      <p className="text-gray-300">Analyzing network traffic...</p>
                      <p className="text-sm text-gray-500 mt-2">AI model is processing your data</p>
                    </div>
                  </CardContent>
                </Card>
              )}

              {result && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3 }}
                >
                  {/* Main Result Card */}
                  <Card className={`border backdrop-blur ${
                    result.prediction === 'Malicious'
                      ? 'bg-[#ff3366]/10 border-[#ff3366]/50'
                      : 'bg-[#00ff88]/10 border-[#00ff88]/50'
                  }`}>
                    <CardContent className="py-8">
                      <div className="text-center">
                        {result.prediction === 'Malicious' ? (
                          <AlertTriangle className="w-20 h-20 mx-auto mb-4 text-[#ff3366]" />
                        ) : (
                          <CheckCircle2 className="w-20 h-20 mx-auto mb-4 text-[#00ff88]" />
                        )}
                        <h2 className={`text-3xl font-bold mb-2 ${
                          result.prediction === 'Malicious' ? 'text-[#ff3366]' : 'text-[#00ff88]'
                        }`}>
                          {result.prediction === 'Malicious' ? 'Threat Detected' : 'Normal Traffic'}
                        </h2>
                        <p className="text-gray-400 mb-4">
                          Prediction: {result.prediction}
                        </p>
                        <div className="inline-block px-6 py-3 bg-[#0f1825]/80 rounded-lg border border-[#1a2540]">
                          <p className="text-sm text-gray-400 mb-1">Confidence Score</p>
                          <p className="text-2xl font-bold text-white">
                            {formatConfidence(result.confidence)}
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Details Card */}
                  <Card className="bg-[#0f1825]/70 border-[#1a2540] backdrop-blur">
                    <CardHeader>
                      <CardTitle className="text-white">Analysis Details</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="p-3 bg-[#0f1825]/80 rounded-lg border border-[#1a2540]">
                          <p className="text-xs text-gray-400 mb-1">Source IP</p>
                          <p className="text-white font-mono">{result.sourceIp}</p>
                        </div>
                        <div className="p-3 bg-[#0f1825]/80 rounded-lg border border-[#1a2540]">
                          <p className="text-xs text-gray-400 mb-1">Destination IP</p>
                          <p className="text-white font-mono">{result.destinationIp}</p>
                        </div>
                        <div className="p-3 bg-[#0f1825]/80 rounded-lg border border-[#1a2540]">
                          <p className="text-xs text-gray-400 mb-1">Protocol</p>
                          <p className="text-white">{result.protocol}</p>
                        </div>
                        <div className="p-3 bg-[#0f1825]/80 rounded-lg border border-[#1a2540]">
                          <p className="text-xs text-gray-400 mb-1">Packet Size</p>
                          <p className="text-white">{result.packetSize} bytes</p>
                        </div>
                      </div>

                      {result.prediction === 'Malicious' && result.severity && (
                        <div className={`p-4 rounded-lg border ${
                          result.severity === 'High'
                            ? 'bg-[#ff3366]/10 border-[#ff3366]/40'
                            : result.severity === 'Medium'
                            ? 'bg-yellow-500/10 border-yellow-500/40'
                            : 'bg-[#00ccff]/10 border-[#00ccff]/40'
                        }`}>
                          <p className="text-sm text-gray-400 mb-1">Threat Severity</p>
                          <p className={`text-xl font-bold ${
                            result.severity === 'High'
                              ? 'text-[#ff3366]'
                              : result.severity === 'Medium'
                              ? 'text-yellow-400'
                              : 'text-[#00ccff]'
                          }`}>
                            {result.severity}
                          </p>
                        </div>
                      )}

                      <Button
                        onClick={() => navigate('/dashboard')}
                        className="w-full bg-[#00ccff]/20 hover:bg-[#00ccff]/30 text-[#00ccff] border border-[#00ccff]/50"
                      >
                        View in Dashboard
                      </Button>
                    </CardContent>
                  </Card>
                </motion.div>
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}