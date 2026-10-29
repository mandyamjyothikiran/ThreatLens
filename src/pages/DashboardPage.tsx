import React from 'react';
import {
  FlowRecord,
  LiveFlowRecord,
  AlertItem,
  EvaluationReport,
  LiveMonitoringStatus,
  PageId
} from '../types';
import { MetricCard } from '../components/MetricCard';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  Target,
  Play,
  Square,
  ArrowRight,
  ExternalLink
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip
} from 'recharts';

interface DashboardPageProps {
  flows: FlowRecord[];
  liveFlows: LiveFlowRecord[];
  alerts: AlertItem[];
  evaluationReport: EvaluationReport | null;
  status: LiveMonitoringStatus;
  onStartMonitoring: () => Promise<void>;
  onStopMonitoring: () => Promise<void>;
  monitoringLoading: boolean;
  onNavigate: (page: PageId) => void;
  onSelectFlow: (flow: FlowRecord) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  flows,
  liveFlows,
  alerts,
  evaluationReport,
  status,
  onStartMonitoring,
  onStopMonitoring,
  monitoringLoading,
  onNavigate,
  onSelectFlow
}) => {
  // 1. Total Traffic
  const totalTraffic = status.total_flows > 0 
    ? status.total_flows 
    : (flows.length + liveFlows.length);

  // 2. Normal Traffic
  const normalTraffic = flows.filter(f => f.is_normal).length + liveFlows.filter(f => !f.is_anomaly).length;

  // 3. Threats Detected
  const threatsDetected = alerts.length;

  // 4. Model Accuracy: Show only when actual evaluation results exist
  const modelAccuracy = evaluationReport?.models?.isolation_forest?.accuracy !== undefined
    ? `${(evaluationReport.models.isolation_forest.accuracy * 100).toFixed(1)}%`
    : null;

  // Build real-time traffic chart series from actual records
  const chartData = React.useMemo(() => {
    // Prefer live flows if available, otherwise historical flows
    const sourceRecords = liveFlows.length > 0 ? [...liveFlows].reverse() : [...flows].slice(0, 20).reverse();
    if (sourceRecords.length === 0) return [];

    return sourceRecords.map((r, idx) => {
      const timeStr = r.timestamp ? (r.timestamp.includes('T') ? r.timestamp.split('T')[1].slice(0, 8) : r.timestamp.slice(-8)) : `T-${idx}`;
      return {
        time: timeStr,
        pkts: (r as any).total_fwd_pkts ? (r as any).total_fwd_pkts + ((r as any).total_bwd_pkts || 0) : 1,
        rate: Math.round((r as any).flow_pkts_per_sec || (r as any).total_fwd_pkts || 10),
        bytes: Math.round(((r as any).flow_bytes_per_sec || 0) / 1024)
      };
    });
  }, [liveFlows, flows]);

  // Recent threats (up to 5 items)
  const recentAlerts = alerts.slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Top 4 Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Total Traffic"
          value={totalTraffic > 0 ? totalTraffic.toLocaleString() : '0'}
          sublabel={status.is_monitoring ? `${status.total_packets.toLocaleString()} packets captured` : 'Total flows recorded'}
          icon={Activity}
          accent={false}
        />
        <MetricCard
          label="Normal Traffic"
          value={normalTraffic > 0 ? normalTraffic.toLocaleString() : '0'}
          sublabel="Benign baseline flows"
          icon={ShieldCheck}
          accent={false}
        />
        <MetricCard
          label="Threats Detected"
          value={threatsDetected.toLocaleString()}
          sublabel="Anomalies flagged"
          icon={ShieldAlert}
          accent={threatsDetected > 0}
        />
        <MetricCard
          label="Model Accuracy"
          value={modelAccuracy !== null ? modelAccuracy : '—'}
          sublabel={modelAccuracy !== null ? 'Isolation Forest benchmark' : 'No evaluation run'}
          icon={Target}
          accent={modelAccuracy !== null}
        />
      </div>

      {/* Live Monitoring Status Bar with Start / Stop Controls */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${status.is_monitoring ? 'bg-cyan-400 animate-pulse' : 'bg-slate-600'}`} />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-white">
                Live Monitoring: {status.is_monitoring ? 'Active' : 'Inactive'}
              </span>
              {status.selected_interface && (
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300">
                  {status.selected_interface}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              {status.is_monitoring
                ? `${status.total_packets.toLocaleString()} packets · ${status.total_flows.toLocaleString()} flows · ${status.total_anomalies} anomalies`
                : 'Traffic capture is currently stopped.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {status.is_monitoring ? (
            <button
              onClick={onStopMonitoring}
              disabled={monitoringLoading}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800/60 transition-colors disabled:opacity-50"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span>{monitoringLoading ? 'Stopping...' : 'Stop Monitoring'}</span>
            </button>
          ) : (
            <button
              onClick={onStartMonitoring}
              disabled={monitoringLoading}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded bg-cyan-400 hover:bg-cyan-300 text-slate-950 transition-colors disabled:opacity-50 shadow-xs"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{monitoringLoading ? 'Starting...' : 'Start Monitoring'}</span>
            </button>
          )}

          <button
            onClick={() => onNavigate('live_monitoring')}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 border border-slate-800 rounded transition-colors"
          >
            <span>Live Stream</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Real-Time Network Traffic Chart */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-white">Network Traffic Volume</h2>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">Packets per flow over time</p>
          </div>
          {chartData.length > 0 && (
            <span className="text-xs font-mono text-cyan-400">
              {chartData.length} data points
            </span>
          )}
        </div>

        {chartData.length === 0 ? (
          <div className="h-64 flex flex-col items-center justify-center text-slate-400 text-xs font-mono border border-dashed border-slate-800/80 rounded">
            <span>No data available</span>
          </div>
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cyanArea" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  stroke="#475569"
                  fontSize={10}
                  tickLine={false}
                  fontFamily="monospace"
                />
                <YAxis
                  stroke="#475569"
                  fontSize={10}
                  tickLine={false}
                  fontFamily="monospace"
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#070d1e',
                    borderColor: '#334155',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontFamily: 'monospace'
                  }}
                  itemStyle={{ color: '#22d3ee' }}
                />
                <Area
                  type="monotone"
                  dataKey="pkts"
                  name="Packets"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#cyanArea)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Simple Recent Threats Table */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-white">Recent Threats</h2>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Detected network anomalies requiring security review
            </p>
          </div>
          <button
            onClick={() => onNavigate('alerts')}
            className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
          >
            <span>View all alerts ({alerts.length})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {recentAlerts.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs font-mono border border-dashed border-slate-800/80 rounded">
            <span>No data available</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="py-2.5 px-3">Time</th>
                  <th className="py-2.5 px-3">Port / Protocol</th>
                  <th className="py-2.5 px-3">Anomaly Score</th>
                  <th className="py-2.5 px-3">Risk Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {recentAlerts.map((alert) => {
                  const timeFormatted = alert.timestamp.includes('T')
                    ? alert.timestamp.split('T')[1].slice(0, 8)
                    : alert.timestamp;

                  return (
                    <tr key={alert.alert_id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 text-slate-400">{timeFormatted}</td>
                      <td className="py-2.5 px-3">
                        <span className="text-white font-medium">{alert.dest_port}</span>
                        <span className="text-slate-400 text-[11px] ml-1.5">({alert.protocol})</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-cyan-300 font-medium">
                          {(alert.anomaly_score * 100).toFixed(1)}%
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${
                            alert.risk_severity === 'Critical'
                              ? 'bg-rose-950/80 text-rose-300 border border-rose-800/50'
                              : alert.risk_severity === 'High'
                              ? 'bg-amber-950/80 text-amber-300 border border-amber-800/50'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {alert.risk_severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">{alert.investigation_status}</td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => {
                            // Find matching flow or create lightweight representation
                            const matchedFlow = flows.find(f => f.id === alert.flow_id) || {
                              id: alert.flow_id,
                              timestamp: alert.timestamp,
                              dest_port: alert.dest_port,
                              protocol: alert.protocol,
                              duration_us: 15000,
                              total_fwd_pkts: 12,
                              total_bwd_pkts: 8,
                              flow_bytes_per_sec: 14200,
                              flow_pkts_per_sec: 85,
                              actual_label: alert.prediction_category,
                              is_normal: false,
                              anomaly_score: alert.anomaly_score,
                              risk_level: alert.risk_severity
                            };
                            onSelectFlow(matchedFlow);
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
