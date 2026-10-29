import React, { useState } from 'react';
import { ConfusionMatrixValues } from '../types';

interface ConfusionMatrixProps {
  title: string;
  subtitle: string;
  matrix: ConfusionMatrixValues;
  accuracy: number;
  fpr: number;
  recall: number;
  precision: number;
}

export const ConfusionMatrix: React.FC<ConfusionMatrixProps> = ({
  title,
  subtitle,
  matrix,
  accuracy,
  fpr,
  recall,
  precision
}) => {
  const [viewNormalized, setViewNormalized] = useState(false);

  const tp = matrix.true_positive;
  const tn = matrix.true_negative;
  const fp = matrix.false_positive;
  const fn = matrix.false_negative;
  const total = tp + tn + fp + fn;

  const actualPos = tp + fn;
  const actualNeg = tn + fp;

  const formatVal = (count: number, rowTotal: number) => {
    if (viewNormalized) {
      const pct = rowTotal > 0 ? (count / rowTotal) * 100 : 0;
      return `${pct.toFixed(1)}%`;
    }
    return count.toLocaleString();
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <h4 className="text-sm font-semibold text-slate-100">{title}</h4>
          <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>
        </div>
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800 text-xs">
          <button
            onClick={() => setViewNormalized(false)}
            className={`px-2.5 py-1 rounded font-medium transition-colors ${
              !viewNormalized ? 'bg-slate-800 text-cyan-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw Counts
          </button>
          <button
            onClick={() => setViewNormalized(true)}
            className={`px-2.5 py-1 rounded font-medium transition-colors ${
              viewNormalized ? 'bg-slate-800 text-cyan-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Normalized %
          </button>
        </div>
      </div>

      {/* 2x2 Grid */}
      <div className="grid grid-cols-3 gap-2 text-xs">
        {/* Header row */}
        <div className="p-2 text-slate-400 font-mono text-[11px] flex items-end">
          Actual \ Predicted
        </div>
        <div className="p-2 text-center text-slate-300 font-mono font-medium bg-slate-950/40 rounded">
          Pred. Normal (0)
        </div>
        <div className="p-2 text-center text-slate-300 font-mono font-medium bg-slate-950/40 rounded">
          Pred. Anomaly (1)
        </div>

        {/* Row 1: Actual Benign */}
        <div className="p-2 flex items-center text-slate-300 font-mono font-medium bg-slate-950/40 rounded">
          Act. Benign
        </div>
        <div className="p-3 bg-emerald-950/30 border border-emerald-500/20 rounded flex flex-col items-center justify-center">
          <span className="text-[10px] text-emerald-400/80 font-mono">True Negative (TN)</span>
          <span className="text-base font-bold font-mono text-emerald-400 tabular-nums">
            {formatVal(tn, actualNeg)}
          </span>
        </div>
        <div className="p-3 bg-amber-950/30 border border-amber-500/20 rounded flex flex-col items-center justify-center">
          <span className="text-[10px] text-amber-400/80 font-mono">False Positive (FP)</span>
          <span className="text-base font-bold font-mono text-amber-400 tabular-nums">
            {formatVal(fp, actualNeg)}
          </span>
        </div>

        {/* Row 2: Actual Attack */}
        <div className="p-2 flex items-center text-slate-300 font-mono font-medium bg-slate-950/40 rounded">
          Act. Attack
        </div>
        <div className="p-3 bg-rose-950/30 border border-rose-500/20 rounded flex flex-col items-center justify-center">
          <span className="text-[10px] text-rose-400/80 font-mono">False Negative (FN)</span>
          <span className="text-base font-bold font-mono text-rose-400 tabular-nums">
            {formatVal(fn, actualPos)}
          </span>
        </div>
        <div className="p-3 bg-cyan-950/30 border border-cyan-500/20 rounded flex flex-col items-center justify-center">
          <span className="text-[10px] text-cyan-400/80 font-mono">True Positive (TP)</span>
          <span className="text-base font-bold font-mono text-cyan-400 tabular-nums">
            {formatVal(tp, actualPos)}
          </span>
        </div>
      </div>

      {/* Metric summary strip */}
      <div className="mt-4 pt-3 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
        <div className="flex flex-col">
          <span className="text-slate-400">Accuracy</span>
          <span className="text-slate-200 font-semibold tabular-nums">{(accuracy * 100).toFixed(2)}%</span>
        </div>
        <div className="flex flex-col">
          <span className="text-slate-400">Recall / TPR</span>
          <span className="text-cyan-400 font-semibold tabular-nums">{(recall * 100).toFixed(2)}%</span>
        </div>
        <div className="flex flex-col">
          <span className="text-slate-400">Precision</span>
          <span className="text-slate-200 font-semibold tabular-nums">{(precision * 100).toFixed(2)}%</span>
        </div>
        <div className="flex flex-col">
          <span className="text-slate-400">Measured FPR</span>
          <span className="text-amber-400 font-semibold tabular-nums">{(fpr * 100).toFixed(2)}%</span>
        </div>
      </div>
    </div>
  );
};
