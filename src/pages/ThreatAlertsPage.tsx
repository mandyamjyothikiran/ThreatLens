import React, { useState } from 'react';
import { AlertItem, FlowRecord } from '../types';
import { ExternalLink } from 'lucide-react';

interface ThreatAlertsPageProps {
  alerts: AlertItem[];
  flows: FlowRecord[];
  onSelectFlow: (flow: FlowRecord) => void;
  onUpdateAlertStatus: (alertId: string, newStatus: AlertItem['investigation_status']) => void;
}

export const ThreatAlertsPage: React.FC<ThreatAlertsPageProps> = ({
  alerts,
  flows,
  onSelectFlow,
  onUpdateAlertStatus
}) => {
  const [severityFilter, setSeverityFilter] = useState<'all' | 'Critical' | 'High' | 'Medium' | 'Low'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | AlertItem['investigation_status']>('all');

  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter !== 'all' && a.risk_severity !== severityFilter) return false;
    if (statusFilter !== 'all' && a.investigation_status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Controls & Summary */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-sm font-semibold text-white">Detection Alerts</h2>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Network anomalies flagged for triage and incident investigation
            </p>
          </div>
          <span className="text-xs font-mono text-cyan-400">
            {filteredAlerts.length} alerts matching filter
          </span>
        </div>

        {/* Filters */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4 text-xs font-mono">
          <div>
            <label className="block text-slate-400 mb-1.5 font-medium">Severity Filter</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as any)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1.5 font-medium">Investigation Status</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Statuses</option>
              <option value="Analyst Review Required">Analyst Review Required</option>
              <option value="Investigating">Investigating</option>
              <option value="Confirmed Incident">Confirmed Incident</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5">
        {filteredAlerts.length === 0 ? (
          <div className="py-16 text-center text-slate-400 text-xs font-mono border border-dashed border-slate-800/80 rounded">
            <span>No data available</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="py-2.5 px-3">Alert ID</th>
                  <th className="py-2.5 px-3">Time</th>
                  <th className="py-2.5 px-3">Port / Protocol</th>
                  <th className="py-2.5 px-3">Anomaly Score</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {filteredAlerts.map((alert) => {
                  const timeFormatted = alert.timestamp.includes('T')
                    ? alert.timestamp.split('T')[1].slice(0, 8)
                    : alert.timestamp;

                  return (
                    <tr key={alert.alert_id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 text-slate-400">{alert.alert_id}</td>
                      <td className="py-2.5 px-3 text-slate-400">{timeFormatted}</td>
                      <td className="py-2.5 px-3">
                        <span className="text-white font-medium">{alert.dest_port}</span>
                        <span className="text-slate-400 text-[11px] ml-1.5">({alert.protocol})</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-cyan-300 font-medium tabular-nums">
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
                      <td className="py-2.5 px-3 text-slate-300">{alert.prediction_category}</td>
                      <td className="py-2.5 px-3">
                        <select
                          value={alert.investigation_status}
                          onChange={(e) =>
                            onUpdateAlertStatus(
                              alert.alert_id,
                              e.target.value as AlertItem['investigation_status']
                            )
                          }
                          className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-[11px] text-slate-300 focus:outline-none focus:border-cyan-500"
                        >
                          <option value="Analyst Review Required">Review Required</option>
                          <option value="Investigating">Investigating</option>
                          <option value="Confirmed Incident">Confirmed</option>
                          <option value="False Positive">False Positive</option>
                        </select>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => {
                            const matchedFlow = flows.find((f) => f.id === alert.flow_id) || {
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
