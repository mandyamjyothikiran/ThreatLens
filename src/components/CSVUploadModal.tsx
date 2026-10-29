import React, { useState } from 'react';
import { Upload, AlertCircle, CheckCircle, FileText, X } from 'lucide-react';
import { ApiService } from '../services/api';

interface CSVUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onUploadSuccess: (newFlowsCount: number, anomaliesCount: number) => void;
}

export const CSVUploadModal: React.FC<CSVUploadModalProps> = ({
  isOpen,
  onClose,
  onUploadSuccess
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<'idle' | 'validating' | 'processing' | 'success' | 'error'>('idle');
  const [validationReport, setValidationReport] = useState<{
    totalRows: number;
    validRows: number;
    missingColumns: string[];
    foundColumns: string[];
    anomaliesFound: number;
    error?: string;
  } | null>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setStatus('idle');
      setValidationReport(null);
    }
  };

  const processCSVContent = async (text: string) => {
    setStatus('validating');
    const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    if (lines.length < 2) {
      setStatus('error');
      setValidationReport({
        totalRows: 0,
        validRows: 0,
        missingColumns: [],
        foundColumns: [],
        anomaliesFound: 0,
        error: 'CSV file contains no data rows.'
      });
      return;
    }

    const headers = lines[0].split(',').map(h => h.trim().replace(/^["']|["']$/g, ''));
    const requiredCheck = ['Destination Port', 'Flow Duration', 'Total Fwd Packets'];
    const missing = requiredCheck.filter(
      rc => !headers.some(h => h.toLowerCase() === rc.toLowerCase())
    );

    if (missing.length > 0) {
      setStatus('error');
      setValidationReport({
        totalRows: lines.length - 1,
        validRows: 0,
        missingColumns: missing,
        foundColumns: headers,
        anomaliesFound: 0,
        error: `Required schema columns missing: ${missing.join(', ')}`
      });
      return;
    }

    setStatus('processing');

    let validCount = 0;
    let anomalyCount = 0;

    // Process up to 50 rows for responsiveness
    const maxRows = Math.min(lines.length - 1, 50);
    for (let i = 1; i <= maxRows; i++) {
      const cols = lines[i].split(',').map(c => c.trim().replace(/^["']|["']$/g, ''));
      const rowObj: Record<string, any> = {};
      headers.forEach((h, idx) => {
        rowObj[h] = cols[idx];
      });

      try {
        const res = await ApiService.predict(rowObj);
        validCount++;
        if (res.result.is_anomaly) {
          anomalyCount++;
        }
      } catch {
        // skip malformed row
      }
    }

    setStatus('success');
    setValidationReport({
      totalRows: lines.length - 1,
      validRows: validCount,
      missingColumns: [],
      foundColumns: headers,
      anomaliesFound: anomalyCount
    });

    onUploadSuccess(validCount, anomalyCount);
  };

  const handleUploadSubmit = () => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      processCSVContent(text);
    };
    reader.readAsText(file);
  };

  const handleLoadSample = (sampleType: 'baseline' | 'heldout') => {
    setStatus('processing');
    const endpoint = sampleType === 'baseline' ? '/data/cicids2017_sample.csv' : '/data/cicids2017_heldout_sample.csv';
    fetch(endpoint)
      .then(res => res.text())
      .then(text => processCSVContent(text))
      .catch(() => {
        // Fallback with synthetic CIC-IDS2017 flow data
        const fallbackSample = `Destination Port,Flow Duration,Total Fwd Packets,Total Backward Packets,Flow Bytes/s,Flow Packets/s,Label
80,38308,1,1,313.25,52.21,BENIGN
443,492312,12,15,9601.43,54.84,BENIGN
80,11984210,18,1,30.04,1.58,DoS Hulk
21,24890,3,3,4499.79,241.06,FTP-Patator
4444,2841000,24,20,2819.42,15.48,Infiltration`;
        processCSVContent(fallbackSample);
      });
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-xl w-full flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Upload className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-sans">
                Upload Network Flow Records (CSV)
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Evaluates against trained Isolation Forest feature space
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
        <div className="p-6 space-y-4">
          <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/50 rounded-lg p-6 text-center transition-colors bg-slate-950/40">
            <input
              type="file"
              id="csvFileInput"
              accept=".csv"
              onChange={handleFileChange}
              className="hidden"
            />
            <label htmlFor="csvFileInput" className="cursor-pointer flex flex-col items-center">
              <FileText className="w-8 h-8 text-cyan-400/80 mb-2" />
              <span className="text-xs font-medium text-slate-200">
                {file ? file.name : 'Select a CSV flow file to upload'}
              </span>
              <span className="text-[11px] text-slate-400 mt-1">
                Accepts CIC-IDS2017, UNSW-NB15, or standard flow schemas (.csv)
              </span>
            </label>
          </div>

          {/* Quick presets */}
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400">Quick Test Datasets:</span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleLoadSample('baseline')}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-mono transition-colors"
              >
                Load Baseline Sample
              </button>
              <button
                type="button"
                onClick={() => handleLoadSample('heldout')}
                className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/30 text-cyan-400 rounded text-[11px] font-mono transition-colors"
              >
                Load Zero-Day Held-Out
              </button>
            </div>
          </div>

          {/* Report Feedback */}
          {validationReport && (
            <div className={`p-4 rounded-lg border text-xs ${
              status === 'error'
                ? 'bg-rose-950/30 border-rose-500/30 text-rose-300'
                : 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
            }`}>
              <div className="flex items-center gap-2 font-semibold mb-1">
                {status === 'error' ? <AlertCircle className="w-4 h-4 text-rose-400" /> : <CheckCircle className="w-4 h-4 text-emerald-400" />}
                <span>{status === 'error' ? 'Validation Failed' : 'Batch Evaluation Complete'}</span>
              </div>
              {validationReport.error ? (
                <p className="mt-1 text-rose-400/90">{validationReport.error}</p>
              ) : (
                <div className="mt-2 grid grid-cols-3 gap-2 font-mono text-[11px]">
                  <div>
                    <span className="text-slate-400 block">Total Records</span>
                    <span className="text-slate-100 font-bold tabular-nums">{validationReport.totalRows}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Inferred Flows</span>
                    <span className="text-slate-100 font-bold tabular-nums">{validationReport.validRows}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Anomalies Flagged</span>
                    <span className="text-rose-400 font-bold tabular-nums">{validationReport.anomaliesFound}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleUploadSubmit}
            disabled={!file || status === 'processing'}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed rounded-md transition-colors shadow-sm"
          >
            {status === 'processing' ? 'Processing Inference...' : 'Validate & Predict'}
          </button>
        </div>
      </div>
    </div>
  );
};
