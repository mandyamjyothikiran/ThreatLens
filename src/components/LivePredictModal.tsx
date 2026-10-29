import React, { useState } from 'react';
import { X, Play, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { ApiService } from '../services/api';
import { PredictionResult } from '../types';

interface LivePredictModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const PRESETS = [
  {
    name: 'Benign HTTPS Web Flow',
    description: 'Standard TLS web browsing (Port 443, balanced packets)',
    flow: {
      'Destination Port': 443,
      'Flow Duration': 492312,
      'Total Fwd Packets': 12,
      'Total Backward Packets': 15,
      'Total Length of Fwd Packets': 742,
      'Total Length of Bwd Packets': 3984,
      'Flow Bytes/s': 9601.43,
      'Flow Packets/s': 54.84,
      'Flow IAT Mean': 18935.0,
      'Flow IAT Max': 124982,
      'Average Packet Size': 175.0,
      'SYN Flag Count': 1,
      'ACK Flag Count': 1
    }
  },
  {
    name: 'Zero-Day / Held-Out: Stealth Infiltration',
    description: 'Unseen attack mimicking normal traffic with abnormal duration & buffer',
    flow: {
      'Destination Port': 4444,
      'Flow Duration': 2841000,
      'Total Fwd Packets': 24,
      'Total Backward Packets': 20,
      'Total Length of Fwd Packets': 4120,
      'Total Length of Bwd Packets': 3890,
      'Flow Bytes/s': 2819.42,
      'Flow Packets/s': 15.48,
      'Flow IAT Mean': 66069.7,
      'Flow IAT Max': 840000,
      'Average Packet Size': 182.04,
      'SYN Flag Count': 1,
      'ACK Flag Count': 1
    }
  },
  {
    name: 'Zero-Day / Held-Out: Rapid PortScan Probe',
    description: 'Single-packet reconnaissance with sub-millisecond duration',
    flow: {
      'Destination Port': 445,
      'Flow Duration': 420,
      'Total Fwd Packets': 1,
      'Total Backward Packets': 1,
      'Total Length of Fwd Packets': 0,
      'Total Length of Bwd Packets': 0,
      'Flow Bytes/s': 0.0,
      'Flow Packets/s': 4761.9,
      'Flow IAT Mean': 420.0,
      'Flow IAT Max': 420,
      'Average Packet Size': 0.0,
      'SYN Flag Count': 1,
      'ACK Flag Count': 0
    }
  },
  {
    name: 'Known Attack: DoS Hulk Volumetric Flood',
    description: 'Massive flow duration and unidirectional packet imbalance',
    flow: {
      'Destination Port': 80,
      'Flow Duration': 11984210,
      'Total Fwd Packets': 18,
      'Total Backward Packets': 1,
      'Total Length of Fwd Packets': 360,
      'Total Length of Bwd Packets': 0,
      'Flow Bytes/s': 30.04,
      'Flow Packets/s': 1.58,
      'Flow IAT Mean': 665789.4,
      'Flow IAT Max': 2010000,
      'Average Packet Size': 18.95,
      'SYN Flag Count': 0,
      'ACK Flag Count': 1
    }
  }
];

export const LivePredictModal: React.FC<LivePredictModalProps> = ({
  isOpen,
  onClose
}) => {
  const [formData, setFormData] = useState<Record<string, any>>(PRESETS[0].flow);
  const [thresholdOverride, setThresholdOverride] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PredictionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleSelectPreset = (presetFlow: Record<string, any>) => {
    setFormData(presetFlow);
    setResult(null);
    setError(null);
  };

  const handlePredict = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const th = thresholdOverride.trim() !== '' ? parseFloat(thresholdOverride) : undefined;
      const res = await ApiService.predict(formData, th);
      setResult(res.result);
    } catch (err: any) {
      setError(err.message || 'Prediction request failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Play className="w-4 h-4 fill-current" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-sans">
                Real-Time Network Flow Inference
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Evaluates flow against learned benign traffic distribution via Isolation Forest
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-md hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Preset Buttons */}
          <div>
            <span className="text-xs font-medium text-slate-300 block mb-2">
              Select Network Flow Scenario:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {PRESETS.map((p, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleSelectPreset(p.flow)}
                  className="text-left p-2.5 rounded-lg border border-slate-800 bg-slate-950/40 hover:bg-slate-800/60 hover:border-cyan-500/30 transition-colors"
                >
                  <span className="text-xs font-semibold text-slate-200 block">
                    {p.name}
                  </span>
                  <span className="text-[11px] text-slate-400 block mt-0.5">
                    {p.description}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Form Fields */}
          <form onSubmit={handlePredict} className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-300">
                Flow Metric Parameters (CIC-IDS2017 Format):
              </span>
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400">Custom Threshold:</span>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  max="1"
                  placeholder="Auto (0.542)"
                  value={thresholdOverride}
                  onChange={(e) => setThresholdOverride(e.target.value)}
                  className="w-28 px-2 py-1 bg-slate-950 border border-slate-800 rounded text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {Object.entries(formData).map(([key, val]) => (
                <div key={key}>
                  <label className="block text-[11px] text-slate-400 mb-1 truncate" title={key}>
                    {key}
                  </label>
                  <input
                    type="text"
                    value={val}
                    onChange={(e) => handleInputChange(key, e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={loading}
                className="px-5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-md transition-colors shadow-sm flex items-center gap-2"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{loading ? 'Evaluating Model...' : 'Execute Model Inference'}</span>
              </button>
            </div>
          </form>

          {/* Error Message */}
          {error && (
            <div className="p-3 bg-rose-950/40 border border-rose-500/30 rounded-lg text-xs text-rose-300">
              {error}
            </div>
          )}

          {/* Real Prediction Result */}
          {result && (
            <div className={`p-5 rounded-xl border ${
              result.is_anomaly
                ? 'bg-rose-950/20 border-rose-500/30'
                : 'bg-emerald-950/20 border-emerald-500/30'
            }`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                <div className="flex items-center gap-3">
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                    result.is_anomaly ? 'bg-rose-950 text-rose-400' : 'bg-emerald-950 text-emerald-400'
                  }`}>
                    {result.is_anomaly ? <ShieldAlert className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
                  </div>
                  <div>
                    <span className="text-xs text-slate-400 uppercase tracking-wider font-mono">
                      Inference Verdict
                    </span>
                    <h4 className="text-base font-bold text-slate-100 font-sans">
                      {result.prediction}
                    </h4>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono">
                  <div>
                    <span className="text-slate-400 block text-[10px]">Anomaly Score</span>
                    <span className={`text-base font-bold tabular-nums ${
                      result.is_anomaly ? 'text-rose-400' : 'text-emerald-400'
                    }`}>
                      {(result.anomaly_score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Decision Threshold</span>
                    <span className="text-slate-300 font-semibold tabular-nums">
                      {(result.calibrated_threshold * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Risk Severity</span>
                    <span className={`font-semibold ${
                      result.risk_level === 'Critical' ? 'text-rose-400' :
                      result.risk_level === 'High' ? 'text-amber-400' :
                      result.risk_level === 'Medium' ? 'text-yellow-400' : 'text-emerald-400'
                    }`}>
                      {result.risk_level}
                    </span>
                  </div>
                </div>
              </div>

              {/* Feature Attribution */}
              <div className="mt-4">
                <span className="text-xs font-semibold text-slate-300 block mb-2">
                  Top Anomaly Contributing Features:
                </span>
                <div className="space-y-1.5">
                  {result.top_contributing_features.map((feat, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-2 bg-slate-950/60 rounded border border-slate-800 text-xs font-mono"
                    >
                      <span className="text-slate-300">{feat.feature}</span>
                      <div className="flex items-center gap-3">
                        <span className="text-slate-400 text-[11px]">Value: {feat.raw_value}</span>
                        <span className={`tabular-nums font-semibold ${
                          feat.is_outlier ? 'text-rose-400' : 'text-slate-400'
                        }`}>
                          Dev: +{feat.deviation_score.toFixed(2)}σ
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-4 p-3 bg-slate-950/80 rounded border border-slate-800 text-[11px] text-slate-400">
                <span className="text-slate-300 font-semibold">Academic Prototype Disclaimer: </span>
                An anomaly score exceeding threshold indicates structural divergence from learned normal traffic. Held-out zero-day attacks manifest as statistical outliers without prior training signatures.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
