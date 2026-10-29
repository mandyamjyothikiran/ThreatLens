import React, { useState } from 'react';
import {
  EvaluationReport,
  UnseenAttackReport,
  ThresholdComparisonItem,
  ModelInfoResponse
} from '../types';
import { ConfusionMatrix } from '../components/ConfusionMatrix';
import { RocPrCharts } from '../components/RocPrCharts';
import { MetricCard } from '../components/MetricCard';
import { Target, Activity, Zap, CheckCircle2 } from 'lucide-react';

interface MLModelPageProps {
  evaluationReport: EvaluationReport | null;
  unseenReport: UnseenAttackReport | null;
  thresholds: ThresholdComparisonItem[];
  modelInfo: ModelInfoResponse | null;
}

export const MLModelPage: React.FC<MLModelPageProps> = ({
  evaluationReport,
  unseenReport,
  thresholds,
  modelInfo
}) => {
  const [activeTab, setActiveTab] = useState<'metrics' | 'unseen' | 'curves' | 'thresholds'>('metrics');

  if (!evaluationReport) {
    return (
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-12 text-center">
        <p className="text-xs font-mono text-slate-400">No data available</p>
      </div>
    );
  }

  const iso = evaluationReport.models.isolation_forest;
  const rf = evaluationReport.models.random_forest;

  return (
    <div className="space-y-6">
      {/* Model Overview Header Card */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Isolation Forest Zero-Day Anomaly Detection
            </h2>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Unsupervised tree partition algorithm trained on benign traffic baselines
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-cyan-300">
              Threshold: {((evaluationReport.decision_threshold || 0.542) * 100).toFixed(1)}% (95th %ile)
            </span>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex flex-wrap items-center gap-2 mt-4 text-xs font-mono">
          <button
            onClick={() => setActiveTab('metrics')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'metrics'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 font-semibold'
                : 'text-slate-400 hover:text-white bg-slate-950/60'
            }`}
          >
            Model Metrics
          </button>
          <button
            onClick={() => setActiveTab('unseen')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'unseen'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 font-semibold'
                : 'text-slate-400 hover:text-white bg-slate-950/60'
            }`}
          >
            Zero-Day Experiment
          </button>
          <button
            onClick={() => setActiveTab('curves')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'curves'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 font-semibold'
                : 'text-slate-400 hover:text-white bg-slate-950/60'
            }`}
          >
            ROC / PR Curves
          </button>
          <button
            onClick={() => setActiveTab('thresholds')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'thresholds'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 font-semibold'
                : 'text-slate-400 hover:text-white bg-slate-950/60'
            }`}
          >
            Threshold Calibration
          </button>
        </div>
      </div>

      {/* Tab 1: Primary Metrics & Confusion Matrix */}
      {activeTab === 'metrics' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
            <MetricCard
              label="Accuracy"
              value={`${(iso.accuracy * 100).toFixed(1)}%`}
              sublabel="Test benchmark"
              icon={Target}
              accent={true}
            />
            <MetricCard
              label="Precision"
              value={`${(iso.precision * 100).toFixed(1)}%`}
              sublabel="True positives"
              icon={Target}
            />
            <MetricCard
              label="Recall"
              value={`${(iso.recall * 100).toFixed(1)}%`}
              sublabel="Threat detection"
              icon={CheckCircle2}
            />
            <MetricCard
              label="F1-Score"
              value={`${(iso.f1_score * 100).toFixed(1)}%`}
              sublabel="Harmonic mean"
              icon={Activity}
            />
            <MetricCard
              label="False-Positive Rate"
              value={`${(iso.false_positive_rate * 100).toFixed(2)}%`}
              sublabel="At 95th %ile cutoff"
              icon={Activity}
            />
            <MetricCard
              label="Inference Latency"
              value={`${iso.inference_latency_ms.toFixed(2)}ms`}
              sublabel="Per flow record"
              icon={Zap}
            />
          </div>

          {/* Confusion Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ConfusionMatrix
              title="Isolation Forest (Unsupervised)"
              subtitle="Semi-supervised anomaly isolation evaluated against test partition"
              matrix={iso.confusion_matrix}
              accuracy={iso.accuracy}
              fpr={iso.false_positive_rate}
              recall={iso.recall}
              precision={iso.precision}
            />
            <ConfusionMatrix
              title="Random Forest Baseline (Supervised)"
              subtitle="Supervised classifier benchmark on known training classes"
              matrix={rf.confusion_matrix}
              accuracy={rf.accuracy}
              fpr={rf.false_positive_rate}
              recall={rf.recall}
              precision={rf.precision}
            />
          </div>
        </div>
      )}

      {/* Tab 2: Zero-Day Held-Out Attack Experiment */}
      {activeTab === 'unseen' && unseenReport && (
        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-800/80">
            <div>
              <h3 className="text-sm font-semibold text-white">
                Held-Out Zero-Day Attack Benchmark
              </h3>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                Models evaluated on novel attack classes strictly excluded from training
              </p>
            </div>
            <div className="text-xs font-mono text-cyan-400">
              Isolation Forest Recall: {(unseenReport.overall_summary.isolation_forest_overall_unseen_recall * 100).toFixed(1)}% vs RF {(unseenReport.overall_summary.random_forest_overall_unseen_recall * 100).toFixed(1)}%
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="py-2.5 px-3">Attack Category</th>
                  <th className="py-2.5 px-3">Test Samples</th>
                  <th className="py-2.5 px-3">Isolation Forest Recall</th>
                  <th className="py-2.5 px-3">Random Forest Recall</th>
                  <th className="py-2.5 px-3">Finding</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {unseenReport.held_out_categories.map((cat) => (
                  <tr key={cat.category} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-2.5 px-3 font-semibold text-white">{cat.category}</td>
                    <td className="py-2.5 px-3 text-slate-400 tabular-nums">
                      {cat.sample_count.toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-300 font-bold tabular-nums">
                      {(cat.isolation_forest_recall * 100).toFixed(1)}%
                    </td>
                    <td className="py-2.5 px-3 text-rose-300 font-medium tabular-nums">
                      {(cat.random_forest_recall * 100).toFixed(1)}%
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">{cat.analysis}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: ROC & PR Curves */}
      {activeTab === 'curves' && (
        <RocPrCharts
          rocCurve={evaluationReport.roc_curve}
          prCurve={evaluationReport.precision_recall_curve}
        />
      )}

      {/* Tab 4: Adaptive Threshold Calibration */}
      {activeTab === 'thresholds' && (
        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-white">
              Validation Threshold Calibration Comparison
            </h3>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Evaluating precision vs false-positive trade-offs across cutoffs
            </p>
          </div>

          {thresholds.length === 0 ? (
            <div className="py-12 text-center text-slate-400 text-xs font-mono">
              <span>No data available</span>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                    <th className="py-2.5 px-3">Strategy</th>
                    <th className="py-2.5 px-3">Threshold</th>
                    <th className="py-2.5 px-3">FPR</th>
                    <th className="py-2.5 px-3">Recall</th>
                    <th className="py-2.5 px-3">Precision</th>
                    <th className="py-2.5 px-3">F1</th>
                    <th className="py-2.5 px-3">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-200">
                  {thresholds.map((th) => (
                    <tr key={th.strategy} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 font-medium text-white">{th.strategy}</td>
                      <td className="py-2.5 px-3 text-cyan-300 tabular-nums">
                        {(th.threshold * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 tabular-nums">
                        {(th.validation_fpr * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-200 tabular-nums">
                        {(th.validation_recall * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-200 tabular-nums">
                        {(th.validation_precision * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-200 tabular-nums">
                        {(th.validation_f1 * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">{th.verdict}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
