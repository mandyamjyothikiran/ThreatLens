import React from 'react';
import { FlowRecord } from '../types';
import { X, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface FeatureInspectorModalProps {
  flow: FlowRecord | null;
  onClose: () => void;
}

export const FeatureInspectorModal: React.FC<FeatureInspectorModalProps> = ({
  flow,
  onClose
}) => {
  if (!flow) return null;

  const features = flow.features || {};
  const entries = Object.entries(features).filter(([k]) => k.toLowerCase() !== 'label');

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              flow.is_normal ? 'bg-emerald-950/80 text-emerald-400' : 'bg-rose-950/80 text-rose-400'
            }`}>
              {flow.is_normal ? <CheckCircle2 className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-sans">
                Network Flow Feature Inspector
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                {flow.id} · Port {flow.dest_port} ({flow.protocol}) · {flow.timestamp}
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

        {/* Status banner */}
        <div className="px-6 py-3 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Ground Truth:</span>
            <span className={flow.is_normal ? 'text-emerald-400' : 'text-rose-400'}>
              {flow.actual_label}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Anomaly Score:</span>
            <span className="text-cyan-400 font-semibold tabular-nums">
              {(flow.anomaly_score * 100).toFixed(1)}%
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Risk Assessment:</span>
            <span className={
              flow.risk_level === 'Critical' ? 'text-rose-400' :
              flow.risk_level === 'High' ? 'text-amber-400' :
              flow.risk_level === 'Medium' ? 'text-yellow-400' : 'text-emerald-400'
            }>
              {flow.risk_level}
            </span>
          </div>
        </div>

        {/* Feature Grid */}
        <div className="p-6 overflow-y-auto space-y-4">
          <div className="text-xs text-slate-400">
            Selected CIC-IDS2017 flow metrics evaluated against learned normal baseline:
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {entries.map(([key, val]) => (
              <div
                key={key}
                className="p-2.5 bg-slate-950/40 border border-slate-800/80 rounded flex items-center justify-between text-xs"
              >
                <span className="text-slate-400 truncate pr-2" title={key}>
                  {key}
                </span>
                <span className="font-mono text-slate-200 tabular-nums shrink-0">
                  {typeof val === 'number' ? (Number.isInteger(val) ? val : val.toFixed(2)) : String(val)}
                </span>
              </div>
            ))}
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-md text-[11px] text-slate-400 space-y-1">
            <span className="font-semibold text-slate-300">Feature Engineering & Leakage Protocol:</span>
            <p>
              Identifiers such as Source IP, Destination IP, and Timestamp were stripped during preprocessing.
              Predictions are generated solely from behavioral flow statistics (Inter-Arrival Times, Packet Length Moments, and TCP Flag distributions).
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
