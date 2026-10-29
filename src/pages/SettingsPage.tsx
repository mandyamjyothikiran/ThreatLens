import React, { useState } from 'react';
import { getApiBaseUrl, setApiBaseUrl, ApiService } from '../services/api';
import { NetworkInterfaceInfo } from '../types';
import { Check, RefreshCw } from 'lucide-react';

interface SettingsPageProps {
  interfaces: NetworkInterfaceInfo[];
  apiConnected: boolean;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  interfaces,
  apiConnected
}) => {
  const [apiUrl, setApiUrl] = useState(getApiBaseUrl());
  const [connMessage, setConnMessage] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [sensitivity, setSensitivity] = useState<number>(54);

  const handleSaveUrl = () => {
    setApiBaseUrl(apiUrl);
    setConnMessage('API URL updated.');
    setTimeout(() => setConnMessage(null), 3000);
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setConnMessage(null);
    try {
      setApiBaseUrl(apiUrl);
      const res = await ApiService.getHealth();
      setConnMessage(`Connected: ${res.service} (${res.status})`);
    } catch (err: any) {
      setConnMessage(`Error: ${err.message}`);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* API Endpoint Configuration */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white">Backend Connection</h2>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            REST API and live EventSource endpoint
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <input
            type="text"
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            placeholder="/api or http://localhost:5000"
            className="flex-1 px-3 py-2 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={handleSaveUrl}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 rounded transition-colors whitespace-nowrap"
          >
            Apply
          </button>
          <button
            onClick={handleTestConnection}
            disabled={testing}
            className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 text-xs font-semibold rounded transition-colors whitespace-nowrap flex items-center justify-center gap-1.5 disabled:opacity-50"
          >
            {testing && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
            <span>{testing ? 'Testing...' : 'Test Connection'}</span>
          </button>
        </div>

        {connMessage && (
          <div className="text-xs font-mono px-3 py-2 bg-slate-950 border border-slate-800 rounded text-cyan-300">
            {connMessage}
          </div>
        )}
      </div>

      {/* Detection Sensitivity Calibration */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white">Detection Sensitivity</h2>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            Calibrate anomaly score cutoff threshold for live stream triage
          </p>
        </div>

        <div className="space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between text-slate-300">
            <span>Cutoff Threshold:</span>
            <span className="text-cyan-300 font-semibold">{sensitivity}%</span>
          </div>
          <input
            type="range"
            min="30"
            max="80"
            value={sensitivity}
            onChange={(e) => setSensitivity(Number(e.target.value))}
            className="w-full accent-cyan-400 bg-slate-950 h-1.5 rounded cursor-pointer"
          />
          <div className="flex items-center justify-between text-[11px] text-slate-500">
            <span>30% (High Recall / More Alerts)</span>
            <span>54% (95th %ile Benchmark)</span>
            <span>80% (Strict / Minimal Alerts)</span>
          </div>
        </div>
      </div>

      {/* Network Interfaces */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white">Discovered Network Interfaces</h2>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            Available interfaces detected by backend network service
          </p>
        </div>

        {interfaces.length === 0 ? (
          <div className="py-8 text-center text-slate-400 text-xs font-mono">
            <span>No interfaces discovered</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="py-2 px-3">Interface</th>
                  <th className="py-2 px-3">Description</th>
                  <th className="py-2 px-3">Loopback</th>
                  <th className="py-2 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {interfaces.map((iface) => (
                  <tr key={iface.id}>
                    <td className="py-2 px-3 font-medium text-white">{iface.name}</td>
                    <td className="py-2 px-3 text-slate-400">{iface.description}</td>
                    <td className="py-2 px-3 text-slate-400">{iface.is_loopback ? 'Yes' : 'No'}</td>
                    <td className="py-2 px-3">
                      <span className="text-emerald-400 font-medium">Ready</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
