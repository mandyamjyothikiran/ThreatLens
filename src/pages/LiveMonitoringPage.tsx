import React, { useState } from 'react';
import {
  LiveMonitoringStatus,
  LiveFlowRecord,
  NetworkInterfaceInfo,
  FlowRecord
} from '../types';
import { ApiService } from '../services/api';
import {
  Play,
  Square,
  Zap,
  ExternalLink,
  Info
} from 'lucide-react';

interface LiveMonitoringPageProps {
  status: LiveMonitoringStatus;
  liveFlows: LiveFlowRecord[];
  interfaces: NetworkInterfaceInfo[];
  onStartMonitoring: (iface: string, mode: 'live_interface' | 'synthetic_test_stream' | 'pcap_replay') => Promise<void>;
  onStopMonitoring: () => Promise<void>;
  monitoringLoading: boolean;
  onSelectFlow: (flow: FlowRecord) => void;
}

export const LiveMonitoringPage: React.FC<LiveMonitoringPageProps> = ({
  status,
  liveFlows,
  interfaces,
  onStartMonitoring,
  onStopMonitoring,
  monitoringLoading,
  onSelectFlow
}) => {
  const [selectedIface, setSelectedIface] = useState<string>(
    status.selected_interface || (interfaces.length > 0 ? interfaces[0].id : 'eth1')
  );
  const [captureMode, setCaptureMode] = useState<'synthetic_test_stream' | 'live_interface' | 'pcap_replay'>(
    (status.capture_mode as any) || 'synthetic_test_stream'
  );
  const [testPacketSending, setTestPacketSending] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const handleStart = async () => {
    await onStartMonitoring(selectedIface, captureMode);
  };

  const handleTestPacket = async () => {
    setTestPacketSending(true);
    setTestResult(null);
    try {
      const res = await ApiService.triggerTestPacket();
      setTestResult(res.message || 'Test flow injected successfully.');
      setTimeout(() => setTestResult(null), 3000);
    } catch (err: any) {
      setTestResult(`Failed: ${err.message}`);
    } finally {
      setTestPacketSending(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Control Panel */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-sm font-semibold text-white">Capture Configuration</h2>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Select network interface and execution mode
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleTestPacket}
              disabled={testPacketSending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-medium text-slate-300 hover:text-white bg-slate-900 border border-slate-700 rounded transition-colors disabled:opacity-50"
              title="Inject a test network flow record"
            >
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span>{testPacketSending ? 'Injecting...' : 'Inject Test Flow'}</span>
            </button>

            {status.is_monitoring ? (
              <button
                onClick={onStopMonitoring}
                disabled={monitoringLoading}
                className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold rounded bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800/60 transition-colors disabled:opacity-50"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>{monitoringLoading ? 'Stopping...' : 'Stop Monitoring'}</span>
              </button>
            ) : (
              <button
                onClick={handleStart}
                disabled={monitoringLoading}
                className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold rounded bg-cyan-400 hover:bg-cyan-300 text-slate-950 transition-colors disabled:opacity-50 shadow-xs"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{monitoringLoading ? 'Starting...' : 'Start Monitoring'}</span>
              </button>
            )}
          </div>
        </div>

        {testResult && (
          <div className="text-xs font-mono px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-cyan-300">
            {testResult}
          </div>
        )}

        {/* Form controls */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
          <div>
            <label className="block text-slate-400 mb-1.5 font-medium">Network Interface</label>
            <select
              value={selectedIface}
              onChange={(e) => setSelectedIface(e.target.value)}
              disabled={status.is_monitoring}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              {interfaces.map((iface) => (
                <option key={iface.id} value={iface.id}>
                  {iface.name} ({iface.description})
                </option>
              ))}
              {interfaces.length === 0 && (
                <option value="eth1">eth1 (Default Interface)</option>
              )}
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1.5 font-medium">Capture Mode</label>
            <select
              value={captureMode}
              onChange={(e) => setCaptureMode(e.target.value as any)}
              disabled={status.is_monitoring}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              <option value="synthetic_test_stream">Synthetic Test Stream (Safe Sandbox)</option>
              <option value="live_interface">Live Raw Interface (Scapy / Socket)</option>
              <option value="pcap_replay">PCAP File Replay</option>
            </select>
          </div>
        </div>
      </div>

      {/* Capture Mode & Permission Alert Banner */}
      {status.last_error && (
        <div className="bg-rose-950/60 border border-rose-800/80 rounded-lg p-4 font-mono text-xs text-rose-200 flex items-start gap-3">
          <Info className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold text-rose-300">Capture Session Notice:</span>
            <p className="text-slate-300">{status.last_error}</p>
          </div>
        </div>
      )}

      {/* Real-time Status Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-4 font-mono">
          <span className="text-[11px] text-slate-400">Capture Status</span>
          <div className="text-lg font-semibold text-white mt-1 flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${status.is_monitoring ? 'bg-cyan-400 animate-pulse' : 'bg-slate-600'}`} />
            <span>{status.is_monitoring ? 'Active' : 'Inactive'}</span>
          </div>
        </div>

        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-4 font-mono">
          <span className="text-[11px] text-slate-400">Execution Mode</span>
          <div className="text-xs font-semibold mt-1">
            {status.capture_mode === 'live_interface' ? (
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/80 inline-block">
                LIVE CAPTURE ({status.selected_interface || 'Raw'})
              </span>
            ) : status.capture_mode === 'pcap_replay' ? (
              <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800/80 inline-block">
                PCAP REPLAY
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/80 inline-block">
                SYNTHETIC DEMO
              </span>
            )}
          </div>
        </div>

        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-4 font-mono">
          <span className="text-[11px] text-slate-400">Packets Captured</span>
          <div className="text-lg font-semibold text-white mt-1 tabular-nums">
            {status.total_packets.toLocaleString()}
          </div>
        </div>

        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-4 font-mono">
          <span className="text-[11px] text-slate-400">Flows Extracted</span>
          <div className="text-lg font-semibold text-white mt-1 tabular-nums">
            {status.total_flows.toLocaleString()}
          </div>
        </div>

        <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-4 font-mono">
          <span className="text-[11px] text-slate-400">Anomalies Detected</span>
          <div className="text-lg font-semibold text-rose-400 mt-1 tabular-nums">
            {status.total_anomalies.toLocaleString()}
          </div>
        </div>
      </div>

      {/* Live Flow Table */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-white">Live Flow Stream</h2>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Auto-updating network flows with machine learning risk classification
            </p>
          </div>
          <span className="text-xs font-mono text-cyan-400">
            {liveFlows.length} buffered
          </span>
        </div>

        {liveFlows.length === 0 ? (
          <div className="py-16 text-center text-slate-400 text-xs font-mono border border-dashed border-slate-800/80 rounded">
            <span>No data available. Start monitoring to capture flows.</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Port / Protocol</th>
                  <th className="py-2.5 px-3">Origin</th>
                  <th className="py-2.5 px-3">Duration (μs)</th>
                  <th className="py-2.5 px-3">Packets</th>
                  <th className="py-2.5 px-3">Anomaly Score</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {liveFlows.map((flow) => {
                  const timeFormatted = flow.timestamp.includes('T')
                    ? flow.timestamp.split('T')[1].slice(0, 8)
                    : flow.timestamp;

                  return (
                    <tr
                      key={flow.id}
                      className={`hover:bg-slate-900/50 transition-colors ${
                        flow.is_anomaly ? 'bg-rose-950/10' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3 text-slate-400">{timeFormatted}</td>
                      <td className="py-2.5 px-3">
                        <span className="text-white font-medium">{flow.dest_port}</span>
                        <span className="text-slate-400 text-[11px] ml-1.5">({flow.protocol})</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${
                          flow.is_test_data
                            ? 'bg-amber-950 text-amber-400 border border-amber-800/40'
                            : 'bg-cyan-950 text-cyan-300 border border-cyan-800/40'
                        }`}>
                          {flow.is_test_data ? 'SYNTHETIC' : 'REAL CAPTURE'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 tabular-nums">
                        {flow.duration_us?.toLocaleString() || '0'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 tabular-nums">
                        {(flow.total_fwd_pkts || 0) + (flow.total_bwd_pkts || 0)}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-cyan-300 font-medium tabular-nums">
                          {(flow.anomaly_score * 100).toFixed(1)}%
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${
                            flow.is_anomaly
                              ? 'bg-rose-950/80 text-rose-300 border border-rose-800/50'
                              : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/50'
                          }`}
                        >
                          {flow.is_anomaly ? 'Anomaly' : 'Normal'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => {
                            const adaptedFlow: FlowRecord = {
                              id: flow.id,
                              timestamp: flow.timestamp,
                              dest_port: flow.dest_port,
                              protocol: flow.protocol,
                              duration_us: flow.duration_us,
                              total_fwd_pkts: flow.total_fwd_pkts,
                              total_bwd_pkts: flow.total_bwd_pkts,
                              flow_bytes_per_sec: flow.flow_bytes_per_sec,
                              flow_pkts_per_sec: flow.flow_pkts_per_sec,
                              actual_label: flow.prediction,
                              is_normal: !flow.is_anomaly,
                              anomaly_score: flow.anomaly_score,
                              risk_level: flow.risk_level,
                              features: flow.features
                            };
                            onSelectFlow(adaptedFlow);
                          }}
                          className="text-cyan-400 hover:text-cyan-300 p-1 rounded hover:bg-slate-800 transition-colors"
                          title="Inspect Features"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
