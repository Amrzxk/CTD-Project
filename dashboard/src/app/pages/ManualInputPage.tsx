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

    // Map form data to API schema
    const apiPayload = {
      proto: data.protocol.toLowerCase(),
      service: data.service,
      sport: data.sourcePort,
      dsport: data.destinationPort,
      dur: data.duration,
      sbytes: data.sourceBytes,
      dbytes: data.destinationBytes,
      spkts: data.sourcePackets,
      dpkts: data.destinationPackets,
      sttl: data.sourceTTL,
      dttl: data.destinationTTL,
      srcip: data.sourceIp,
      dstip: data.destinationIp
    };

    try {
      const prediction = await threatService.predictSingle(apiPayload as any);
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
    <div className="min-h-screen bg-gradient-to-br from-bg via-bg to-bg py-12">
      <div className="container mx-auto px-4 max-w-6xl">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="mb-8">
            <h1 className="text-4xl font-bold text-foreground mb-2">Manual Threat Analysis</h1>
            <p className="text-muted-foreground">Enter network connection details for real-time threat detection</p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            {/* Input Form */}
            <Card className="bg-panel/70 border-line backdrop-blur">
              <CardHeader>
                <CardTitle className="text-foreground">Network Flow Parameters</CardTitle>
                <CardDescription className="text-muted-foreground">
                  Enter network flow details matching the ML model input schema
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">

                  {/* ── Connection Details ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Globe className="w-4 h-4 text-sev-low" />
                      <h3 className="text-sm text-sev-low font-semibold tracking-wide uppercase">Connection Details</h3>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <Label htmlFor="sourceIp" className="text-foreground">Source IP Address</Label>
                        <Input
                          id="sourceIp"
                          placeholder="192.168.1.100"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('sourceIp', {
                            required: 'Source IP is required',
                            validate: (value) => isValidIPv4(value) || 'Invalid IPv4 address format'
                          })}
                        />
                        {errors.sourceIp && (
                          <p className="text-sev-high text-sm mt-1">{errors.sourceIp.message}</p>
                        )}
                      </div>

                      <div>
                        <Label htmlFor="destinationIp" className="text-foreground">Destination IP Address</Label>
                        <Input
                          id="destinationIp"
                          placeholder="10.0.0.50"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('destinationIp', {
                            required: 'Destination IP is required',
                            validate: (value) => isValidIPv4(value) || 'Invalid IPv4 address format'
                          })}
                        />
                        {errors.destinationIp && (
                          <p className="text-sev-high text-sm mt-1">{errors.destinationIp.message}</p>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="protocol" className="text-foreground">Protocol</Label>
                          <Select value={protocol} onValueChange={(value) => setValue('protocol', value)}>
                            <SelectTrigger className="bg-line/60 border-line-strong text-foreground">
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
                          <Label htmlFor="service" className="text-foreground">Service</Label>
                          <Select value={service} onValueChange={(value) => setValue('service', value)}>
                            <SelectTrigger className="bg-line/60 border-line-strong text-foreground">
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
                              <SelectItem value="unknown">unknown</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* ── Ports ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Network className="w-4 h-4 text-sev-low" />
                      <h3 className="text-sm text-sev-low font-semibold tracking-wide uppercase">Ports</h3>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="sourcePort" className="text-foreground">Source Port</Label>
                        <Input
                          id="sourcePort"
                          type="number"
                          placeholder="8080"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('sourcePort', {
                            required: 'Source port is required',
                            valueAsNumber: true,
                            validate: (value) => isValidPort(value) || 'Port must be between 0-65535'
                          })}
                        />
                        {errors.sourcePort && (
                          <p className="text-sev-high text-sm mt-1">{errors.sourcePort.message}</p>
                        )}
                      </div>
                      <div>
                        <Label htmlFor="destinationPort" className="text-foreground">Destination Port</Label>
                        <Input
                          id="destinationPort"
                          type="number"
                          placeholder="443"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('destinationPort', {
                            required: 'Destination port is required',
                            valueAsNumber: true,
                            validate: (value) => isValidPort(value) || 'Port must be between 0-65535'
                          })}
                        />
                        {errors.destinationPort && (
                          <p className="text-sev-high text-sm mt-1">{errors.destinationPort.message}</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* ── Traffic Metrics ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Activity className="w-4 h-4 text-brand" />
                      <h3 className="text-sm text-brand font-semibold tracking-wide uppercase">Traffic Metrics</h3>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <Label htmlFor="duration" className="text-foreground">Duration (seconds)</Label>
                        <Input
                          id="duration"
                          type="number"
                          step="0.01"
                          min="0"
                          placeholder="5.2"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('duration', {
                            required: 'Duration is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' }
                          })}
                        />
                        {errors.duration && (
                          <p className="text-sev-high text-sm mt-1">{errors.duration.message}</p>
                        )}
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="sourceBytes" className="text-foreground">Source Bytes</Label>
                          <Input
                            id="sourceBytes"
                            type="number"
                            min="0"
                            placeholder="2048"
                            className="bg-line/60 border-line-strong text-foreground"
                            {...register('sourceBytes', {
                              required: 'Source bytes is required',
                              valueAsNumber: true,
                              min: { value: 0, message: 'Must be 0 or greater' }
                            })}
                          />
                          {errors.sourceBytes && (
                            <p className="text-sev-high text-sm mt-1">{errors.sourceBytes.message}</p>
                          )}
                        </div>
                        <div>
                          <Label htmlFor="destinationBytes" className="text-foreground">Destination Bytes</Label>
                          <Input
                            id="destinationBytes"
                            type="number"
                            min="0"
                            placeholder="4096"
                            className="bg-line/60 border-line-strong text-foreground"
                            {...register('destinationBytes', {
                              required: 'Destination bytes is required',
                              valueAsNumber: true,
                              min: { value: 0, message: 'Must be 0 or greater' }
                            })}
                          />
                          {errors.destinationBytes && (
                            <p className="text-sev-high text-sm mt-1">{errors.destinationBytes.message}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* ── Packet Metrics ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Radio className="w-4 h-4 text-brand" />
                      <h3 className="text-sm text-brand font-semibold tracking-wide uppercase">Packet Metrics</h3>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="sourcePackets" className="text-foreground">Source Packets</Label>
                        <Input
                          id="sourcePackets"
                          type="number"
                          min="0"
                          placeholder="12"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('sourcePackets', {
                            required: 'Source packets is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' }
                          })}
                        />
                        {errors.sourcePackets && (
                          <p className="text-sev-high text-sm mt-1">{errors.sourcePackets.message}</p>
                        )}
                      </div>
                      <div>
                        <Label htmlFor="destinationPackets" className="text-foreground">Destination Packets</Label>
                        <Input
                          id="destinationPackets"
                          type="number"
                          min="0"
                          placeholder="8"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('destinationPackets', {
                            required: 'Destination packets is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' }
                          })}
                        />
                        {errors.destinationPackets && (
                          <p className="text-sev-high text-sm mt-1">{errors.destinationPackets.message}</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* ── TTL Metrics ── */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Clock className="w-4 h-4 text-sev-high" />
                      <h3 className="text-sm text-sev-high font-semibold tracking-wide uppercase">TTL Metrics</h3>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="sourceTTL" className="text-foreground">Source TTL</Label>
                        <Input
                          id="sourceTTL"
                          type="number"
                          min="0"
                          placeholder="64"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('sourceTTL', {
                            required: 'Source TTL is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' },
                            max: { value: 255, message: 'Max TTL is 255' }
                          })}
                        />
                        {errors.sourceTTL && (
                          <p className="text-sev-high text-sm mt-1">{errors.sourceTTL.message}</p>
                        )}
                      </div>
                      <div>
                        <Label htmlFor="destinationTTL" className="text-foreground">Destination TTL</Label>
                        <Input
                          id="destinationTTL"
                          type="number"
                          min="0"
                          placeholder="128"
                          className="bg-line/60 border-line-strong text-foreground"
                          {...register('destinationTTL', {
                            required: 'Destination TTL is required',
                            valueAsNumber: true,
                            min: { value: 0, message: 'Must be 0 or greater' },
                            max: { value: 255, message: 'Max TTL is 255' }
                          })}
                        />
                        {errors.destinationTTL && (
                          <p className="text-sev-high text-sm mt-1">{errors.destinationTTL.message}</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-3 pt-4">
                    <Button
                      type="submit"
                      disabled={loading}
                      className="flex-1 bg-brand hover:bg-brand/80 text-[var(--on-brand)] font-semibold"
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
                      className="border-line-strong text-muted-foreground"
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
                <Card className="bg-panel/70 border-line backdrop-blur">
                  <CardContent className="py-12">
                    <div className="text-center">
                      <Shield className="w-16 h-16 mx-auto mb-4 text-faint" />
                      <p className="text-muted-foreground">No analysis yet</p>
                      <p className="text-sm text-muted-foreground mt-2">
                        Fill in the form and click "Analyze Threat" to get results
                      </p>
                    </div>
                  </CardContent>
                </Card>
              )}

              {loading && (
                <Card className="bg-panel/70 border-line backdrop-blur">
                  <CardContent className="py-12">
                    <div className="text-center">
                      <Loader2 className="w-16 h-16 mx-auto mb-4 text-brand animate-spin" />
                      <p className="text-foreground">Analyzing network traffic...</p>
                      <p className="text-sm text-muted-foreground mt-2">AI model is processing your data</p>
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
                      ? 'bg-sev-high/10 border-sev-high/50'
                      : 'bg-brand/10 border-brand/50'
                  }`}>
                    <CardContent className="py-8">
                      <div className="text-center">
                        {result.prediction === 'Malicious' ? (
                          <AlertTriangle className="w-20 h-20 mx-auto mb-4 text-sev-high" />
                        ) : (
                          <CheckCircle2 className="w-20 h-20 mx-auto mb-4 text-brand" />
                        )}
                        <h2 className={`text-3xl font-bold mb-2 ${
                          result.prediction === 'Malicious' ? 'text-sev-high' : 'text-brand'
                        }`}>
                          {result.prediction === 'Malicious' ? 'Threat Detected' : 'Normal Traffic'}
                        </h2>
                        <p className="text-muted-foreground mb-4">
                          Prediction: {result.prediction}
                        </p>
                        <div className="inline-block px-6 py-3 bg-panel/80 rounded-lg border border-line">
                          <p className="text-sm text-muted-foreground mb-1">Confidence Score</p>
                          <p className="text-2xl font-bold text-foreground">
                            {formatConfidence(result.confidence)}
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Details Card */}
                  <Card className="bg-panel/70 border-line backdrop-blur">
                    <CardHeader>
                      <CardTitle className="text-foreground">Analysis Details</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="p-3 bg-panel/80 rounded-lg border border-line">
                          <p className="text-xs text-muted-foreground mb-1">Source IP</p>
                          <p className="text-foreground font-mono">{result.sourceIp}</p>
                        </div>
                        <div className="p-3 bg-panel/80 rounded-lg border border-line">
                          <p className="text-xs text-muted-foreground mb-1">Destination IP</p>
                          <p className="text-foreground font-mono">{result.destinationIp}</p>
                        </div>
                        <div className="p-3 bg-panel/80 rounded-lg border border-line">
                          <p className="text-xs text-muted-foreground mb-1">Protocol</p>
                          <p className="text-foreground">{result.protocol}</p>
                        </div>
                        <div className="p-3 bg-panel/80 rounded-lg border border-line">
                          <p className="text-xs text-muted-foreground mb-1">Packet Size</p>
                          <p className="text-foreground">{result.packetSize} bytes</p>
                        </div>
                      </div>

                      {result.prediction === 'Malicious' && result.severity && (
                        <div className={`p-4 rounded-lg border ${
                          result.severity === 'High'
                            ? 'bg-sev-high/10 border-sev-high/40'
                            : result.severity === 'Medium'
                            ? 'bg-sev-med/10 border-sev-med/40'
                            : 'bg-sev-low/10 border-sev-low/40'
                        }`}>
                          <p className="text-sm text-muted-foreground mb-1">Threat Severity</p>
                          <p className={`text-xl font-bold ${
                            result.severity === 'High'
                              ? 'text-sev-high'
                              : result.severity === 'Medium'
                              ? 'text-sev-med'
                              : 'text-sev-low'
                          }`}>
                            {result.severity}
                          </p>
                        </div>
                      )}

                      <Button
                        onClick={() => navigate('/dashboard')}
                        className="w-full bg-sev-low/20 hover:bg-sev-low/30 text-sev-low border border-sev-low/50"
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