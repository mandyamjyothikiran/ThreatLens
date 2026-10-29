import React, { useState, useEffect, useCallback } from 'react';
import {
  PageId,
  FlowRecord,
  LiveFlowRecord,
  AlertItem,
  EvaluationReport,
  UnseenAttackReport,
  ThresholdComparisonItem,
  LiveMonitoringStatus,
  NetworkInterfaceInfo,
  ModelInfoResponse
} from './types';
import { ApiService } from './services/api';
import { Sidebar } from './components/Sidebar';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { LiveMonitoringPage } from './pages/LiveMonitoringPage';
import { ThreatAlertsPage } from './pages/ThreatAlertsPage';
import { MLModelPage } from './pages/MLModelPage';
import { EvaluationPage } from './pages/EvaluationPage';
import { SettingsPage } from './pages/SettingsPage';
import { FeatureInspectorModal } from './components/FeatureInspectorModal';
import { LivePredictModal } from './components/LivePredictModal';

export default function App() {
  const [currentPage, setCurrentPage] = useState<PageId>('dashboard');
  const [isOpenMobile, setIsOpenMobile] = useState(false);

  // Core Data State
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [liveFlows, setLiveFlows] = useState<LiveFlowRecord[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [evaluationReport, setEvaluationReport] = useState<EvaluationReport | null>(null);
  const [unseenReport, setUnseenReport] = useState<UnseenAttackReport | null>(null);
  const [thresholds, setThresholds] = useState<ThresholdComparisonItem[]>([]);
  const [modelInfo, setModelInfo] = useState<ModelInfoResponse | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([]);

  // Monitoring & Connection Status
  const [status, setStatus] = useState<LiveMonitoringStatus>({
    is_monitoring: false,
    selected_interface: null,
    capture_mode: 'idle',
    started_at: null,
    uptime_seconds: 0,
    total_packets: 0,
    total_flows: 0,
    total_anomalies: 0,
    model_ready: true
  });
  const [apiConnected, setApiConnected] = useState(false);
  const [monitoringLoading, setMonitoringLoading] = useState(false);

  // Modals
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);
  const [isLivePredictOpen, setIsLivePredictOpen] = useState(false);

  // Load initial backend data
  const loadInitialData = useCallback(async () => {
    try {
      const health = await ApiService.getHealth();
      setApiConnected(health.status === 'healthy');
    } catch {
      setApiConnected(false);
    }

    try {
      const ifaceRes = await ApiService.getInterfaces();
      if (ifaceRes && ifaceRes.interfaces) {
        setInterfaces(ifaceRes.interfaces);
      }
    } catch (e) {
      console.warn('Could not load interfaces:', e);
    }

    try {
      const statusRes = await ApiService.getMonitoringStatus();
      if (statusRes) {
        setStatus(statusRes);
      }
    } catch (e) {
      console.warn('Could not load monitoring status:', e);
    }

    try {
      const flowsRes = await ApiService.getMonitoringFlows(50);
      if (flowsRes && flowsRes.flows) {
        setLiveFlows(flowsRes.flows);
      }
    } catch (e) {
      console.warn('Could not load initial live flows:', e);
    }

    try {
      const trafficRes = await ApiService.getTraffic(100, 0);
      if (trafficRes && trafficRes.records) {
        setFlows(trafficRes.records);
      }
    } catch (e) {
      console.warn('Could not load traffic records:', e);
    }

    try {
      const alertRes = await ApiService.getAlerts();
      if (alertRes && alertRes.alerts) {
        setAlerts(alertRes.alerts);
      }
    } catch (e) {
      console.warn('Could not load alerts:', e);
    }

    try {
      const metricsRes = await ApiService.getMetrics();
      if (metricsRes && metricsRes.models) {
        setEvaluationReport(metricsRes);
      }
    } catch (e) {
      console.warn('Could not load metrics:', e);
    }

    try {
      const unseenRes = await ApiService.getUnseenEvaluation();
      if (unseenRes && unseenRes.held_out_categories) {
        setUnseenReport(unseenRes);
      }
    } catch (e) {
      console.warn('Could not load unseen evaluation:', e);
    }

    try {
      const thRes = await ApiService.getAdaptiveThresholds();
      if (Array.isArray(thRes)) {
        setThresholds(thRes);
      }
    } catch (e) {
      console.warn('Could not load adaptive thresholds:', e);
    }

    try {
      const infoRes = await ApiService.getModelInfo();
      if (infoRes) {
        setModelInfo(infoRes);
      }
    } catch (e) {
      console.warn('Could not load model info:', e);
    }
  }, []);

  useEffect(() => {
    loadInitialData();

    // Connect to Server-Sent Events stream for real-time live capture & alerts
    const cleanup = ApiService.connectLiveEventStream(
      (newFlow) => {
        setLiveFlows((prev) => [newFlow, ...prev.slice(0, 49)]);
      },
      (newAlert) => {
        setAlerts((prev) => [newAlert, ...prev]);
      },
      (newStatus) => {
        setStatus(newStatus);
      }
    );

    return () => cleanup();
  }, [loadInitialData]);

  // Start monitoring handler
  const handleStartMonitoring = async (
    iface?: string,
    mode: 'live_interface' | 'synthetic_test_stream' | 'pcap_replay' = 'synthetic_test_stream'
  ) => {
    setMonitoringLoading(true);
    try {
      const chosenIface = iface || status.selected_interface || (interfaces[0]?.id || 'eth1');
      await ApiService.startMonitoring(chosenIface, mode);
      setStatus((prev) => ({
        ...prev,
        is_monitoring: true,
        selected_interface: chosenIface,
        capture_mode: mode
      }));
    } catch (err) {
      console.error('Error starting monitoring:', err);
    } finally {
      setMonitoringLoading(false);
    }
  };

  // Stop monitoring handler
  const handleStopMonitoring = async () => {
    setMonitoringLoading(true);
    try {
      await ApiService.stopMonitoring();
      setStatus((prev) => ({
        ...prev,
        is_monitoring: false
      }));
    } catch (err) {
      console.error('Error stopping monitoring:', err);
    } finally {
      setMonitoringLoading(false);
    }
  };

  const handleUpdateAlertStatus = (alertId: string, newStatus: AlertItem['investigation_status']) => {
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === alertId ? { ...a, investigation_status: newStatus } : a))
    );
  };

  return (
    <div className="min-h-screen bg-[#070d1e] text-slate-100 flex flex-col md:flex-row font-sans selection:bg-cyan-500 selection:text-slate-950">
      {/* Sidebar (Exact 5 items) */}
      <Sidebar
        currentPage={currentPage}
        onNavigate={setCurrentPage}
        alertCount={alerts.length}
        isMonitoringActive={status.is_monitoring}
        isOpenMobile={isOpenMobile}
        onCloseMobile={() => setIsOpenMobile(false)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        <Navbar
          currentPage={currentPage}
          apiConnected={apiConnected}
          isMonitoringActive={status.is_monitoring}
          onOpenMobileSidebar={() => setIsOpenMobile(true)}
          onOpenLivePredict={() => setIsLivePredictOpen(true)}
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto overflow-y-auto">
          {currentPage === 'dashboard' && (
            <DashboardPage
              flows={flows}
              liveFlows={liveFlows}
              alerts={alerts}
              evaluationReport={evaluationReport}
              status={status}
              onStartMonitoring={() => handleStartMonitoring()}
              onStopMonitoring={handleStopMonitoring}
              monitoringLoading={monitoringLoading}
              onNavigate={setCurrentPage}
              onSelectFlow={setSelectedFlow}
            />
          )}

          {currentPage === 'live_monitoring' && (
            <LiveMonitoringPage
              status={status}
              liveFlows={liveFlows}
              interfaces={interfaces}
              onStartMonitoring={handleStartMonitoring}
              onStopMonitoring={handleStopMonitoring}
              monitoringLoading={monitoringLoading}
              onSelectFlow={setSelectedFlow}
            />
          )}

          {currentPage === 'alerts' && (
            <ThreatAlertsPage
              alerts={alerts}
              flows={flows}
              onSelectFlow={setSelectedFlow}
              onUpdateAlertStatus={handleUpdateAlertStatus}
            />
          )}

          {currentPage === 'ml_model' && (
            <MLModelPage
              evaluationReport={evaluationReport}
              unseenReport={unseenReport}
              thresholds={thresholds}
              modelInfo={modelInfo}
            />
          )}

          {currentPage === 'evaluation' && (
            <EvaluationPage />
          )}

          {currentPage === 'settings' && (
            <SettingsPage
              interfaces={interfaces}
              apiConnected={apiConnected}
            />
          )}
        </main>
      </div>

      {/* Feature Inspector Modal */}
      <FeatureInspectorModal
        flow={selectedFlow}
        onClose={() => setSelectedFlow(null)}
      />

      {/* Test Flow Modal */}
      <LivePredictModal
        isOpen={isLivePredictOpen}
        onClose={() => setIsLivePredictOpen(false)}
      />
    </div>
  );
}
