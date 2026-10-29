import React, { useState, useId } from 'react';
import {
  FileCheck,
  UploadCloud,
  FileText,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Download,
  Search,
  Filter,
  RefreshCw,
  Database,
  ArrowRight,
  ShieldAlert,
  Info,
  ShieldCheck,
  Eye,
  X,
  FileDown
} from 'lucide-react';
import { ApiService } from '../services/api';
import {
  DatasetInspectionResult,
  GroundTruthEvaluationResult,
  GroundTruthRecord
} from '../types';
import { generateExecutiveEvaluationPDF } from '../utils/executivePdfReport';

export const EvaluationPage: React.FC = () => {
  const fileInputId = useId();
  // Upload and inspection state
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [isSampleSource, setIsSampleSource] = useState<'heldout' | 'train' | null>(null);
  const [isInspecting, setIsInspecting] = useState(false);
  const [inspection, setInspection] = useState<DatasetInspectionResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Configuration state
  const [selectedLabelCol, setSelectedLabelCol] = useState<string>('Label');
  const [normalLabelInput, setNormalLabelInput] = useState<string>('BENIGN, normal, 0');
  const [modelType, setModelType] = useState<'isolation_forest' | 'random_forest'>('isolation_forest');
  const [threshold, setThreshold] = useState<number>(0.542);

  // Evaluation running & results
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [results, setResults] = useState<GroundTruthEvaluationResult | null>(null);

  // Executive PDF and modal state
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [showExecutiveModal, setShowExecutiveModal] = useState(false);
  const [pdfNotification, setPdfNotification] = useState<string | null>(null);

  // Table filters & pagination
  const [activeFilter, setActiveFilter] = useState<'ALL' | 'CORRECT' | 'FP' | 'FN' | 'TP' | 'TN'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  // Handle local CSV file selection
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setErrorMsg(null);
    setFileName(file.name);
    setIsSampleSource(null);
    setResults(null);

    const reader = new FileReader();
    reader.onload = async (evt) => {
      const content = evt.target?.result as string;
      setFileContent(content);
      await runInspect({ csv_content: content });
    };
    reader.onerror = () => {
      setErrorMsg('Failed to read the selected CSV file.');
    };
    reader.readAsText(file);
  };

  // Quick load built-in datasets
  const handleLoadBuiltin = async (source: 'heldout' | 'train') => {
    setErrorMsg(null);
    setFileContent(null);
    setIsSampleSource(source);
    setFileName(
      source === 'heldout'
        ? 'cicids2017_heldout_sample.csv (Held-Out Benchmark)'
        : 'cicids2017_sample.csv (Training Set Benchmark)'
    );
    setResults(null);
    await runInspect({ sample_file: source });
  };

  // Call inspect API
  const runInspect = async (payload: { csv_content?: string; sample_file?: 'heldout' | 'train' }) => {
    setIsInspecting(true);
    setErrorMsg(null);
    try {
      const res = await ApiService.inspectDataset(payload);
      setInspection(res);
      if (res.detected_label_column) {
        setSelectedLabelCol(res.detected_label_column);
      } else if (res.candidate_label_columns?.length > 0) {
        setSelectedLabelCol(res.candidate_label_columns[0]);
      } else if (res.columns?.length > 0) {
        setSelectedLabelCol(res.columns[res.columns.length - 1]);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Inspection failed. Ensure CSV format contains readable columns.');
      setInspection(null);
    } finally {
      setIsInspecting(false);
    }
  };

  // Run Ground Truth Evaluation
  const handleRunEvaluation = async () => {
    if (!inspection) return;
    setIsEvaluating(true);
    setErrorMsg(null);

    const normalLabels = normalLabelInput
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    try {
      const payload: any = {
        label_column: selectedLabelCol,
        normal_labels: normalLabels,
        model_type: modelType,
        threshold: threshold
      };

      if (isSampleSource) {
        payload.sample_file = isSampleSource;
      } else if (fileContent) {
        payload.csv_content = fileContent;
      } else {
        throw new Error('No dataset available to evaluate');
      }

      const res = await ApiService.runGroundTruthEvaluation(payload);
      setResults(res);
      setCurrentPage(1);
    } catch (err: any) {
      setErrorMsg(err.message || 'Evaluation failed to complete.');
    } finally {
      setIsEvaluating(false);
    }
  };

  // Download Executive PDF Report (simple and beautiful for non-cyber stakeholders)
  const handleDownloadPdf = () => {
    if (!results) return;
    setIsGeneratingPdf(true);
    setPdfNotification(null);
    try {
      generateExecutiveEvaluationPDF(results, {
        datasetName: fileName || 'Verified Flow Benchmark'
      });
      setPdfNotification('Executive PDF generated and downloaded successfully.');
      setTimeout(() => setPdfNotification(null), 5000);
    } catch (err: any) {
      console.error('PDF generation error:', err);
      setErrorMsg('Failed to generate executive PDF report: ' + (err?.message || 'Unknown error'));
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // Export Results to CSV
  const handleExportCsv = () => {
    if (!results || !results.records) return;

    const headers = [
      'Flow_ID',
      'Destination_Port',
      'Protocol',
      'Ground_Truth_Label',
      'Actual_Class',
      'Predicted_Class',
      'Status',
      'Is_Correct',
      'Anomaly_Score',
      'Risk_Level',
      'Training_Overlap'
    ];

    const rows = results.records.map((r) => [
      r.id,
      r.dest_port,
      r.protocol,
      `"${r.actual_label.replace(/"/g, '""')}"`,
      r.mapped_actual,
      r.predicted_label,
      r.status,
      r.is_correct ? 'TRUE' : 'FALSE',
      r.anomaly_score.toFixed(4),
      r.risk_level,
      r.is_training_overlap ? 'YES' : 'NO'
    ]);

    const csvString = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threatlens_evaluation_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Export Summary Report to JSON
  const handleExportJson = () => {
    if (!results) return;

    const exportData = {
      export_timestamp: new Date().toISOString(),
      dataset_name: fileName || 'Custom CSV',
      model_type: results.model_type,
      decision_threshold: results.metrics.decision_threshold,
      metrics: results.metrics,
      explanations: results.explanations,
      per_class_breakdown: results.per_class_breakdown,
      dataset_split_info: results.dataset_split_info,
      total_records_evaluated: results.records.length
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threatlens_evaluation_report_${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Filtering records
  const filteredRecords = (results?.records || []).filter((r: GroundTruthRecord) => {
    // Filter type
    if (activeFilter === 'CORRECT' && !r.is_correct) return false;
    if (activeFilter === 'FP' && r.status !== 'FP') return false;
    if (activeFilter === 'FN' && r.status !== 'FN') return false;
    if (activeFilter === 'TP' && r.status !== 'TP') return false;
    if (activeFilter === 'TN' && r.status !== 'TN') return false;

    // Search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = r.id.toLowerCase().includes(q);
      const matchLabel = r.actual_label.toLowerCase().includes(q);
      const matchPort = r.dest_port.toString().includes(q);
      const matchStatus = r.status.toLowerCase().includes(q);
      return matchId || matchLabel || matchPort || matchStatus;
    }

    return true;
  });

  const totalPages = Math.ceil(filteredRecords.length / pageSize) || 1;
  const paginatedRecords = filteredRecords.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
            <FileCheck className="w-4 h-4" />
            <span>GROUND TRUTH BENCHMARKING ENGINE</span>
          </div>
          <h2 className="text-xl font-semibold text-white tracking-tight">
            Ground Truth Evaluation
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Evaluate models against verified labelled datasets with automated schema alignment, strict feature isolation, and data leakage detection.
          </p>
        </div>

        {results && (
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleDownloadPdf}
              disabled={isGeneratingPdf}
              className="px-3.5 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold flex items-center gap-1.5 transition-all shadow-sm cursor-pointer disabled:opacity-50"
              title="Download clean executive PDF report for non-cyber stakeholders"
            >
              {isGeneratingPdf ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <FileDown className="w-3.5 h-3.5" />
              )}
              <span>Download PDF</span>
            </button>
            <button
              onClick={() => setShowExecutiveModal(true)}
              className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700/80 hover:border-cyan-500/50 text-xs text-cyan-300 flex items-center gap-1.5 transition-colors font-medium shadow-xs cursor-pointer"
              title="Preview executive summary in plain English"
            >
              <Eye className="w-3.5 h-3.5 text-cyan-400" />
              <span>Executive Brief</span>
            </button>
            <button
              onClick={handleExportCsv}
              className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700/80 hover:border-slate-600 text-xs text-slate-200 flex items-center gap-1.5 transition-colors font-medium shadow-xs cursor-pointer"
              title="Export prediction results as CSV"
            >
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              <span>Export CSV</span>
            </button>
            <button
              onClick={handleExportJson}
              className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700/80 hover:border-slate-600 text-xs text-slate-300 flex items-center gap-1.5 transition-colors font-medium shadow-xs cursor-pointer"
              title="Export JSON audit report"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>JSON</span>
            </button>
          </div>
        )}
      </div>

      {errorMsg && (
        <div className="p-3.5 rounded bg-rose-950/40 border border-rose-800/40 text-rose-300 text-xs flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Step 1: Upload or Load Benchmark Dataset */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-500/30 flex items-center justify-center text-[11px] font-mono font-bold">
              1
            </span>
            <h3 className="text-sm font-semibold text-white">Select or Upload Labelled Dataset</h3>
          </div>
          {fileName && (
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
              {fileName}
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* File Upload Box */}
          <div className="md:col-span-2 border-2 border-dashed border-slate-700/80 hover:border-cyan-500/50 rounded-lg p-6 flex flex-col items-center justify-center text-center transition-colors bg-slate-900/40">
            <UploadCloud className="w-8 h-8 text-slate-400 mb-2" />
            <p className="text-xs font-medium text-slate-200">
              Drag and drop a labelled network flow CSV, or click to browse
            </p>
            <p className="text-[11px] text-slate-400 mt-1">
              Supports standard CIC-IDS2017 schema with Destination Port, Flow Duration, and Label
            </p>
            <label
              htmlFor={fileInputId}
              className="mt-3 px-3.5 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold cursor-pointer transition-colors"
            >
              Select CSV File
            </label>
            <input
              id={fileInputId}
              type="file"
              accept=".csv"
              onChange={handleFileUpload}
              className="hidden"
            />
          </div>

          {/* Quick Benchmark Presets */}
          <div className="flex flex-col justify-between p-4 bg-slate-900/60 border border-slate-800 rounded-lg">
            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-1">
                Quick Benchmark Presets
              </span>
              <p className="text-[11px] text-slate-400 mb-3">
                Evaluate directly with pre-bundled academic datasets:
              </p>

              <div className="space-y-2">
                <button
                  onClick={() => handleLoadBuiltin('heldout')}
                  disabled={isInspecting}
                  className={`w-full text-left p-2.5 rounded border text-xs transition-colors flex items-center justify-between ${
                    isSampleSource === 'heldout'
                      ? 'bg-cyan-950/60 border-cyan-500/50 text-cyan-300'
                      : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Database className="w-3.5 h-3.5 text-cyan-400" />
                    <div>
                      <div className="font-medium text-white">Held-Out Test Set</div>
                      <div className="text-[10px] text-slate-400 font-mono">Unseen attack categories</div>
                    </div>
                  </div>
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                </button>

                <button
                  onClick={() => handleLoadBuiltin('train')}
                  disabled={isInspecting}
                  className={`w-full text-left p-2.5 rounded border text-xs transition-colors flex items-center justify-between ${
                    isSampleSource === 'train'
                      ? 'bg-amber-950/60 border-amber-500/50 text-amber-300'
                      : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                    <div>
                      <div className="font-medium text-white">Training Sample (Leakage Test)</div>
                      <div className="text-[10px] text-slate-400 font-mono">Simulates train-test overlap</div>
                    </div>
                  </div>
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                </button>
              </div>
            </div>

            <div className="mt-3 pt-3 border-t border-slate-800 text-[10px] text-slate-400 flex items-center gap-1.5">
              <Info className="w-3 h-3 text-cyan-400 shrink-0" />
              <span>Features are matched against model schema automatically.</span>
            </div>
          </div>
        </div>
      </div>

      {/* Step 2: Inspection Summary */}
      {isInspecting && (
        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-6 text-center">
          <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto mb-2" />
          <p className="text-xs text-slate-300">Inspecting CSV columns, feature compatibility, and label distributions...</p>
        </div>
      )}

      {inspection && (
        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-500/30 flex items-center justify-center text-[11px] font-mono font-bold">
                2
              </span>
              <h3 className="text-sm font-semibold text-white">Dataset Pre-Evaluation Inspection</h3>
            </div>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" /> Ready for Evaluation
            </span>
          </div>

          {/* Data Leakage Alert */}
          {inspection.data_leakage_warning && (
            <div className="p-3.5 rounded bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-amber-300 block mb-0.5">Data Leakage Warning</span>
                <p className="text-[11px] text-amber-200/90 leading-relaxed">
                  {inspection.data_leakage_warning}
                </p>
              </div>
            </div>
          )}

          {/* Summary Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-900/70 border border-slate-800 rounded">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Total Records</span>
              <span className="text-lg font-mono font-bold text-white tabular-nums">
                {inspection.total_records.toLocaleString()}
              </span>
            </div>

            <div className="p-3 bg-slate-900/70 border border-slate-800 rounded">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Columns Count</span>
              <span className="text-lg font-mono font-bold text-white tabular-nums">
                {inspection.columns.length}
              </span>
            </div>

            <div className="p-3 bg-slate-900/70 border border-slate-800 rounded">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Feature Compatibility</span>
              <div className="flex items-baseline gap-1.5">
                <span className="text-lg font-mono font-bold text-cyan-400 tabular-nums">
                  {inspection.feature_compatibility_percentage}%
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  ({inspection.matched_features.length}/22)
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-900/70 border border-slate-800 rounded">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Missing Values</span>
              <span className={`text-lg font-mono font-bold tabular-nums ${
                inspection.total_missing_values === 0 ? 'text-emerald-400' : 'text-amber-400'
              }`}>
                {inspection.total_missing_values}
              </span>
            </div>
          </div>

          {/* Label Distribution & Column Selector */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2">
            {/* Label Column Configuration */}
            <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-lg space-y-3">
              <span className="text-xs font-semibold text-slate-200 block">
                Target Ground Truth Column
              </span>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1">
                  Selected Label Column:
                </label>
                <select
                  value={selectedLabelCol}
                  onChange={(e) => setSelectedLabelCol(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-hidden focus:border-cyan-500 font-mono"
                >
                  {inspection.columns.map((col) => (
                    <option key={col} value={col}>
                      {col} {inspection.candidate_label_columns.includes(col) ? '(Detected Candidate)' : ''}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1">
                  Normal / Benign Labels (comma-separated):
                </label>
                <input
                  type="text"
                  value={normalLabelInput}
                  onChange={(e) => setNormalLabelInput(e.target.value)}
                  placeholder="BENIGN, normal, 0"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-hidden focus:border-cyan-500 font-mono"
                />
                <span className="text-[10px] text-slate-400 block mt-1">
                  All other labels in the column will be mapped to Attack (Positive Class = 1).
                </span>
              </div>
            </div>

            {/* Label Distribution Chips */}
            <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-lg">
              <span className="text-xs font-semibold text-slate-200 block mb-2">
                Ground Truth Class Breakdown
              </span>
              <div className="max-h-36 overflow-y-auto space-y-1.5 pr-1">
                {Object.entries(inspection.label_distribution || {}).map(([lbl, count]) => {
                  const isNormal = normalLabelInput
                    .split(',')
                    .map((s) => s.trim().toUpperCase())
                    .includes(lbl.toUpperCase());

                  return (
                    <div
                      key={lbl}
                      className="flex items-center justify-between px-2.5 py-1 rounded bg-slate-950 border border-slate-800/80 text-xs font-mono"
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            isNormal ? 'bg-cyan-400' : 'bg-rose-400'
                          }`}
                        />
                        <span className="text-slate-200">{lbl}</span>
                        <span className="text-[10px] text-slate-400">
                          ({isNormal ? 'Mapped Normal' : 'Mapped Attack'})
                        </span>
                      </div>
                      <span className="text-slate-300 font-bold tabular-nums">
                        {count.toLocaleString()}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Model & Threshold Controls */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-800/80">
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Evaluation Model:</label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setModelType('isolation_forest')}
                  className={`flex-1 py-1.5 px-3 rounded text-xs font-medium border transition-colors ${
                    modelType === 'isolation_forest'
                      ? 'bg-cyan-950/80 border-cyan-500/50 text-cyan-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  Isolation Forest (Outlier Detection)
                </button>
                <button
                  type="button"
                  onClick={() => setModelType('random_forest')}
                  className={`flex-1 py-1.5 px-3 rounded text-xs font-medium border transition-colors ${
                    modelType === 'random_forest'
                      ? 'bg-cyan-950/80 border-cyan-500/50 text-cyan-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  Random Forest (Supervised Baseline)
                </button>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[11px] text-slate-400">Decision Threshold:</label>
                <span className="text-xs font-mono font-bold text-cyan-400">{threshold.toFixed(3)}</span>
              </div>
              <input
                type="range"
                min="0.10"
                max="0.95"
                step="0.005"
                value={threshold}
                onChange={(e) => setThreshold(parseFloat(e.target.value))}
                className="w-full accent-cyan-400 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
              />
              <div className="flex justify-between text-[10px] font-mono text-slate-400 mt-0.5">
                <span>0.10 (High Sensitivity)</span>
                <span>0.542 (Calibrated 95th %ile)</span>
                <span>0.95 (Strict)</span>
              </div>
            </div>
          </div>

          {/* Action Trigger */}
          <div className="pt-2">
            <button
              onClick={handleRunEvaluation}
              disabled={isEvaluating}
              className="w-full sm:w-auto px-6 py-2.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-xs"
            >
              {isEvaluating ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Evaluating Dataset ({inspection.total_records.toLocaleString()} rows)...</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Execute Ground Truth Evaluation</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Step 3: Evaluation Results Dashboard */}
      {results && (
        <div className="space-y-6">
          {/* Top Metrics Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-4 bg-[#0c152e] border border-slate-800 rounded-lg">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Accuracy</span>
              <span className="text-xl font-mono font-bold text-white tabular-nums">
                {(results.metrics.accuracy * 100).toFixed(2)}%
              </span>
              <span className="text-[10px] text-slate-400 font-mono block mt-0.5">Overall Correct</span>
            </div>

            <div className="p-4 bg-[#0c152e] border border-slate-800 rounded-lg">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Precision</span>
              <span className="text-xl font-mono font-bold text-cyan-400 tabular-nums">
                {(results.metrics.precision * 100).toFixed(2)}%
              </span>
              <span className="text-[10px] text-slate-400 font-mono block mt-0.5">TP / (TP + FP)</span>
            </div>

            <div className="p-4 bg-[#0c152e] border border-slate-800 rounded-lg">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Recall (TPR)</span>
              <span className="text-xl font-mono font-bold text-emerald-400 tabular-nums">
                {(results.metrics.recall * 100).toFixed(2)}%
              </span>
              <span className="text-[10px] text-slate-400 font-mono block mt-0.5">Threat Catch Rate</span>
            </div>

            <div className="p-4 bg-[#0c152e] border border-slate-800 rounded-lg">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">F1-Score</span>
              <span className="text-xl font-mono font-bold text-cyan-300 tabular-nums">
                {results.metrics.f1_score.toFixed(4)}
              </span>
              <span className="text-[10px] text-slate-400 font-mono block mt-0.5">Harmonic Mean</span>
            </div>

            <div className="p-4 bg-[#0c152e] border border-slate-800 rounded-lg">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">False Alarm Rate</span>
              <span className="text-xl font-mono font-bold text-amber-400 tabular-nums">
                {(results.metrics.false_positive_rate * 100).toFixed(2)}%
              </span>
              <span className="text-[10px] text-slate-400 font-mono block mt-0.5">FPR (Benign Flagged)</span>
            </div>

            <div className="p-4 bg-[#0c152e] border border-slate-800 rounded-lg">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Specificity</span>
              <span className="text-xl font-mono font-bold text-slate-200 tabular-nums">
                {(results.metrics.specificity * 100).toFixed(2)}%
              </span>
              <span className="text-[10px] text-slate-400 font-mono block mt-0.5">True Negative Rate</span>
            </div>
          </div>

          {/* Confusion Matrix and Per-Class Breakdown Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Confusion Matrix 2x2 */}
            <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-white">Confusion Matrix</h3>
                  <span className="text-[10px] font-mono text-slate-400">
                    Threshold: {results.metrics.decision_threshold.toFixed(3)}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-4">
                  {/* True Positive */}
                  <div className="p-3.5 bg-emerald-950/30 border border-emerald-500/30 rounded">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-emerald-400">True Positive (TP)</span>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    </div>
                    <div className="text-2xl font-mono font-bold text-white tabular-nums">
                      {results.metrics.confusion_matrix.true_positive}
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 leading-tight">
                      Actual Attack correctly predicted as Attack.
                    </p>
                  </div>

                  {/* False Positive */}
                  <div className="p-3.5 bg-amber-950/30 border border-amber-500/30 rounded">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-amber-400">False Positive (FP)</span>
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    </div>
                    <div className="text-2xl font-mono font-bold text-white tabular-nums">
                      {results.metrics.confusion_matrix.false_positive}
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 leading-tight">
                      Normal benign flow mistakenly flagged as Attack (False Alarm).
                    </p>
                  </div>

                  {/* False Negative */}
                  <div className="p-3.5 bg-rose-950/30 border border-rose-500/30 rounded">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-rose-400">False Negative (FN)</span>
                      <XCircle className="w-3.5 h-3.5 text-rose-400" />
                    </div>
                    <div className="text-2xl font-mono font-bold text-white tabular-nums">
                      {results.metrics.confusion_matrix.false_negative}
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 leading-tight">
                      Actual Attack missed and labeled as Normal (Critical Risk).
                    </p>
                  </div>

                  {/* True Negative */}
                  <div className="p-3.5 bg-cyan-950/30 border border-cyan-500/30 rounded">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-cyan-400">True Negative (TN)</span>
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                    </div>
                    <div className="text-2xl font-mono font-bold text-white tabular-nums">
                      {results.metrics.confusion_matrix.true_negative}
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 leading-tight">
                      Normal benign traffic correctly classified as Normal.
                    </p>
                  </div>
                </div>
              </div>

              {/* Protocol Note */}
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded text-[11px] text-slate-400">
                <span className="font-semibold text-slate-300">Positive Class Definition: </span>
                {results.metrics.positive_class}. In cybersecurity monitoring, high recall minimizes missed breaches (FN), while low FPR prevents alert fatigue.
              </div>
            </div>

            {/* Per-Class Breakdown Table */}
            <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Per-Class Detection Breakdown</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase tracking-wider">
                      <th className="pb-2">Ground Truth Label</th>
                      <th className="pb-2 text-right">Samples</th>
                      <th className="pb-2 text-right">Class Acc</th>
                      <th className="pb-2 text-right">Pred Attack</th>
                      <th className="pb-2 text-right">Avg Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {results.per_class_breakdown.map((row) => (
                      <tr key={row.label} className="hover:bg-slate-900/40">
                        <td className="py-2 text-slate-200">
                          <div className="flex items-center gap-1.5 font-sans">
                            <span
                              className={`w-1.5 h-1.5 rounded-full ${
                                row.class_type === 'Normal' ? 'bg-cyan-400' : 'bg-rose-400'
                              }`}
                            />
                            <span>{row.label}</span>
                          </div>
                        </td>
                        <td className="py-2 text-right text-slate-300 tabular-nums">
                          {row.sample_count}
                        </td>
                        <td className="py-2 text-right font-bold tabular-nums">
                          <span
                            className={
                              row.accuracy_percentage >= 90
                                ? 'text-emerald-400'
                                : row.accuracy_percentage >= 70
                                ? 'text-cyan-400'
                                : 'text-amber-400'
                            }
                          >
                            {row.accuracy_percentage}%
                          </span>
                        </td>
                        <td className="py-2 text-right text-slate-400 tabular-nums">
                          {row.predicted_attack}
                        </td>
                        <td className="py-2 text-right text-slate-300 tabular-nums">
                          {row.avg_anomaly_score.toFixed(3)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Results Table Section */}
          <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-white">Itemized Flow Prediction Results</h3>
                <p className="text-[11px] text-slate-400">
                  Showing {filteredRecords.length} records matching current filter
                </p>
              </div>

              {/* Search */}
              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Search label, port, status..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="w-full bg-slate-900 border border-slate-700 rounded pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500 font-mono"
                />
              </div>
            </div>

            {/* Filter Buttons */}
            <div className="flex flex-wrap gap-1.5 border-b border-slate-800 pb-3">
              {[
                { id: 'ALL', label: `All (${results.records.length})` },
                {
                  id: 'CORRECT',
                  label: `Correct (${results.metrics.confusion_matrix.true_positive + results.metrics.confusion_matrix.true_negative})`
                },
                { id: 'FP', label: `False Positives (${results.metrics.confusion_matrix.false_positive})` },
                { id: 'FN', label: `False Negatives (${results.metrics.confusion_matrix.false_negative})` },
                { id: 'TP', label: `True Positives (${results.metrics.confusion_matrix.true_positive})` },
                { id: 'TN', label: `True Negatives (${results.metrics.confusion_matrix.true_negative})` }
              ].map((btn) => (
                <button
                  key={btn.id}
                  onClick={() => {
                    setActiveFilter(btn.id as any);
                    setCurrentPage(1);
                  }}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors ${
                    activeFilter === btn.id
                      ? 'bg-cyan-500 text-slate-950 font-bold'
                      : 'bg-slate-900 text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  {btn.label}
                </button>
              ))}
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase tracking-wider">
                    <th className="pb-2">Flow ID</th>
                    <th className="pb-2">Port / Proto</th>
                    <th className="pb-2">Actual Label</th>
                    <th className="pb-2">Mapped Actual</th>
                    <th className="pb-2">Predicted</th>
                    <th className="pb-2">Status</th>
                    <th className="pb-2">Score</th>
                    <th className="pb-2">Top Drivers</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {paginatedRecords.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-6 text-center text-slate-500">
                        No records match current filter criteria.
                      </td>
                    </tr>
                  ) : (
                    paginatedRecords.map((r) => {
                      let statusBadge = (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyan-950 border border-cyan-800 text-cyan-300">
                          TN
                        </span>
                      );
                      if (r.status === 'TP') {
                        statusBadge = (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 border border-emerald-800 text-emerald-300">
                            TP
                          </span>
                        );
                      } else if (r.status === 'FP') {
                        statusBadge = (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-950 border border-amber-800 text-amber-300">
                            FP (Alarm)
                          </span>
                        );
                      } else if (r.status === 'FN') {
                        statusBadge = (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950 border border-rose-800 text-rose-300">
                            FN (Missed)
                          </span>
                        );
                      }

                      return (
                        <tr key={r.id} className="hover:bg-slate-900/40">
                          <td className="py-2.5 font-bold text-slate-300">{r.id}</td>
                          <td className="py-2.5 text-slate-400">
                            {r.dest_port} / {r.protocol}
                          </td>
                          <td className="py-2.5 text-white font-sans font-medium">{r.actual_label}</td>
                          <td className="py-2.5">
                            <span
                              className={`text-[11px] ${
                                r.mapped_actual === 'Normal' ? 'text-slate-400' : 'text-rose-400'
                              }`}
                            >
                              {r.mapped_actual}
                            </span>
                          </td>
                          <td className="py-2.5">
                            <span
                              className={`text-[11px] font-semibold ${
                                r.predicted_label === 'Attack' ? 'text-rose-300' : 'text-slate-300'
                              }`}
                            >
                              {r.predicted_label}
                            </span>
                          </td>
                          <td className="py-2.5">{statusBadge}</td>
                          <td className="py-2.5">
                            <div className="flex items-center gap-1.5">
                              <span className="font-bold text-white tabular-nums">
                                {r.anomaly_score.toFixed(3)}
                              </span>
                              <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden hidden sm:block">
                                <div
                                  className={`h-full ${
                                    r.anomaly_score >= 0.542 ? 'bg-rose-500' : 'bg-cyan-500'
                                  }`}
                                  style={{ width: `${Math.min(100, r.anomaly_score * 100)}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="py-2.5 text-[10px] text-slate-400">
                            {r.top_features?.map((f) => f.feature.replace(/^(Total|Flow)\s+/, '')).join(', ') || 'Normal'}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-xs font-mono">
                <span className="text-slate-400">
                  Page {currentPage} of {totalPages}
                </span>
                <div className="flex gap-2">
                  <button
                    disabled={currentPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800"
                  >
                    Previous
                  </button>
                  <button
                    disabled={currentPage >= totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Dataset Split Protocol Section */}
          <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-2">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
                Dataset Partitioning & Leakage Prevention Protocol
              </h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              ThreatLens applies strict train-test separation: normalization centers and scales are fit strictly on benign training traffic. Identifiers (IP addresses, timestamps, flow IDs) and target labels are stripped prior to scoring.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 text-[11px] font-mono">
              <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-slate-400">
                <span className="text-slate-200 block mb-0.5 font-bold">Held-Out Experiment Protocol</span>
                Evaluates detection of zero-day classes that were completely absent from the training partition.
              </div>
              <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-slate-400">
                <span className="text-slate-200 block mb-0.5 font-bold">Fingerprint Overlap Check</span>
                {results.dataset_split_info.training_overlap_detected ? (
                  <span className="text-amber-400">
                    Overlap detected: {results.dataset_split_info.overlap_record_count} records overlap with training set.
                  </span>
                ) : (
                  <span className="text-emerald-400">
                    Zero overlap confirmed: All records are strictly external or held out from training.
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
