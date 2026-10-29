import React from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend
} from 'recharts';

interface RocPrChartsProps {
  rocCurve: Array<{ fpr: number; tpr_iso: number; tpr_rf: number }>;
  prCurve: Array<{ recall: number; precision_iso: number; precision_rf: number }>;
}

export const RocPrCharts: React.FC<RocPrChartsProps> = ({ rocCurve, prCurve }) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* ROC Curve */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-slate-100">ROC Curve (Receiver Operating Characteristic)</h4>
          <p className="text-xs text-slate-400 mt-0.5">True Positive Rate vs False Positive Rate</p>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={rocCurve} margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="fpr"
                type="number"
                domain={[0, 1]}
                tickFormatter={(v) => v.toFixed(2)}
                stroke="#64748b"
                tick={{ fontSize: 11, fill: '#94a3b8' }}
                label={{ value: 'False Positive Rate (FPR)', position: 'insideBottom', offset: -5, fill: '#64748b', fontSize: 11 }}
              />
              <YAxis
                domain={[0, 1]}
                tickFormatter={(v) => v.toFixed(2)}
                stroke="#64748b"
                tick={{ fontSize: 11, fill: '#94a3b8' }}
                label={{ value: 'True Positive Rate (TPR)', angle: -90, position: 'insideLeft', fill: '#64748b', fontSize: 11 }}
              />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                formatter={(val: any) => [typeof val === 'number' ? val.toFixed(3) : val, '']}
              />
              <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
              <Line
                type="monotone"
                dataKey="tpr_iso"
                name="Isolation Forest (AUC = 0.961)"
                stroke="#06b6d4"
                strokeWidth={2}
                dot={{ r: 3, fill: '#06b6d4' }}
              />
              <Line
                type="monotone"
                dataKey="tpr_rf"
                name="Random Forest Baseline (AUC = 0.994)"
                stroke="#3b82f6"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                dot={{ r: 2, fill: '#3b82f6' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* PR Curve */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-slate-100">Precision-Recall Curve</h4>
          <p className="text-xs text-slate-400 mt-0.5">Evaluation across varying decision confidence thresholds</p>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={prCurve} margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="recall"
                type="number"
                domain={[0, 1]}
                tickFormatter={(v) => v.toFixed(2)}
                stroke="#64748b"
                tick={{ fontSize: 11, fill: '#94a3b8' }}
                label={{ value: 'Recall', position: 'insideBottom', offset: -5, fill: '#64748b', fontSize: 11 }}
              />
              <YAxis
                domain={[0.6, 1]}
                tickFormatter={(v) => v.toFixed(2)}
                stroke="#64748b"
                tick={{ fontSize: 11, fill: '#94a3b8' }}
                label={{ value: 'Precision', angle: -90, position: 'insideLeft', fill: '#64748b', fontSize: 11 }}
              />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                formatter={(val: any) => [typeof val === 'number' ? val.toFixed(3) : val, '']}
              />
              <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
              <Line
                type="monotone"
                dataKey="precision_iso"
                name="Isolation Forest (PR-AUC = 0.932)"
                stroke="#06b6d4"
                strokeWidth={2}
                dot={{ r: 3, fill: '#06b6d4' }}
              />
              <Line
                type="monotone"
                dataKey="precision_rf"
                name="Random Forest Baseline (PR-AUC = 0.989)"
                stroke="#3b82f6"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                dot={{ r: 2, fill: '#3b82f6' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
