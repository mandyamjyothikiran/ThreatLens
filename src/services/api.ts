/**
 * ThreatLens — Typed API Client Service
 * Connects to REST API and real-time Server-Sent Events (SSE) stream.
 */

import {
  ModelInfoResponse,
  PredictionResult,
  EvaluationReport,
  UnseenAttackReport,
  ThresholdComparisonItem,
  AlertItem,
  FlowRecord,
  NetworkInterfaceInfo,
  LiveMonitoringStatus,
  LiveFlowRecord,
  DatasetInspectionResult,
  GroundTruthEvaluationResult
} from '../types';

function sanitizeBaseUrl(raw?: string): string {
  if (!raw || typeof raw !== 'string') return '/api';

  // Strip accidental prefix like "VITE_API_BASE_URL="
  let cleaned = raw.replace(/^VITE_API_BASE_URL\s*=\s*/i, '').trim();
  // Strip surrounding quotes
  cleaned = cleaned.replace(/^['"]|['"]$/g, '').trim();
  // Strip trailing slashes
  cleaned = cleaned.replace(/\/+$/, '');

  // If running in browser and NOT on localhost / 127.0.0.1,
  // pointing to http://127.0.0.1:5000 or http://localhost:5000 is blocked by Mixed Content or unreachable.
  // Fall back to same-origin '/api' on the current host.
  if (typeof window !== 'undefined' && window.location) {
    const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    if (!isLocal && (cleaned.includes('127.0.0.1') || cleaned.includes('localhost'))) {
      return '/api';
    }
  }

  if (!cleaned || cleaned === '/') return '/api';
  return cleaned;
}

let currentBaseUrl: string = sanitizeBaseUrl((import.meta as any).env?.VITE_API_BASE_URL);

export function getApiBaseUrl(): string {
  return currentBaseUrl;
}

export function setApiBaseUrl(url: string): void {
  currentBaseUrl = sanitizeBaseUrl(url);
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;

  // Candidate URLs to try in order:
  const candidates: string[] = [];

  const base = currentBaseUrl.replace(/\/+$/, '');
  candidates.push(`${base}${cleanEndpoint}`);

  if (base !== '/api') {
    candidates.push(`/api${cleanEndpoint}`);
  }
  if (!candidates.includes(cleanEndpoint)) {
    candidates.push(cleanEndpoint);
  }

  let lastError: any = null;

  for (const url of candidates) {
    try {
      const res = await fetch(url, {
        ...options,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          ...(options.headers || {})
        }
      });

      const contentType = res.headers.get('content-type') || '';
      // If server returned HTML (Vite SPA fallback for an unmatched route), this candidate failed
      if (contentType.includes('text/html')) {
        throw new Error(`Endpoint returned HTML page instead of JSON API response`);
      }

      if (!res.ok) {
        let errorMsg = `HTTP Error ${res.status}: ${res.statusText}`;
        try {
          const errJson = await res.json();
          if (errJson.error) errorMsg = errJson.error;
        } catch {
          // ignore JSON parse fail
        }
        throw new Error(errorMsg);
      }

      const text = await res.text();
      // Guard against any leading '<' (HTML / DOCTYPE) returned without text/html header
      if (text.trim().startsWith('<')) {
        throw new Error(`Endpoint returned non-JSON markup starting with '<'`);
      }

      return JSON.parse(text) as T;
    } catch (err: any) {
      lastError = err;
      // Try next candidate if available
      continue;
    }
  }

  console.error(`API request failed [${candidates[0]}]:`, lastError);
  throw lastError;
}

export const ApiService = {
  async getHealth(): Promise<{ status: string; service: string; timestamp: string; model_loaded: boolean }> {
    return request('/health');
  },

  async getModelInfo(): Promise<ModelInfoResponse> {
    return request('/model-info');
  },

  async predict(flow: Record<string, any>, thresholdOverride?: number): Promise<{ result: PredictionResult }> {
    return request('/predict', {
      method: 'POST',
      body: JSON.stringify({
        flow,
        threshold_override: thresholdOverride
      })
    });
  },

  async getMetrics(): Promise<EvaluationReport> {
    return request('/metrics');
  },

  async getUnseenEvaluation(): Promise<UnseenAttackReport> {
    return request('/evaluate/unseen');
  },

  async getAdaptiveThresholds(): Promise<ThresholdComparisonItem[]> {
    return request('/adaptive-thresholds');
  },

  async getTraffic(limit = 25, offset = 0, filter = 'all', search = ''): Promise<{ total: number; records: FlowRecord[] }> {
    const params = new URLSearchParams({
      limit: limit.toString(),
      offset: offset.toString(),
      filter,
      search
    });
    return request(`/traffic?${params.toString()}`);
  },

  async getAlerts(): Promise<{ total_alerts: number; unreviewed_count: number; alerts: AlertItem[] }> {
    return request('/alerts');
  },

  async getDatasetInspection(): Promise<any> {
    return request('/dataset/inspection');
  },

  async getDatasetPreprocessing(): Promise<any> {
    return request('/dataset/preprocessing');
  },

  async inspectDataset(payload: { csv_content?: string; sample_file?: 'heldout' | 'train' }): Promise<DatasetInspectionResult> {
    return request('/evaluate/inspect', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  async runGroundTruthEvaluation(payload: {
    csv_content?: string;
    sample_file?: 'heldout' | 'train';
    label_column?: string;
    normal_labels?: string[];
    model_type?: 'isolation_forest' | 'random_forest';
    threshold?: number;
  }): Promise<GroundTruthEvaluationResult> {
    return request('/evaluate/run', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  // --- REAL-TIME MONITORING ENDPOINTS ---

  async getInterfaces(): Promise<{ interfaces: NetworkInterfaceInfo[]; raw_socket_permission: boolean; permission_note: string }> {
    return request('/interfaces');
  },

  async startMonitoring(
    interfaceName: string,
    mode: 'live_interface' | 'synthetic_test_stream' | 'pcap_replay' = 'synthetic_test_stream',
    flowTimeoutSec = 3.0,
    thresholdOverride?: number
  ): Promise<any> {
    return request('/monitoring/start', {
      method: 'POST',
      body: JSON.stringify({
        interface: interfaceName,
        mode,
        flow_timeout_sec: flowTimeoutSec,
        threshold_override: thresholdOverride
      })
    });
  },

  async stopMonitoring(): Promise<any> {
    return request('/monitoring/stop', {
      method: 'POST',
      body: JSON.stringify({})
    });
  },

  async getMonitoringStatus(): Promise<LiveMonitoringStatus> {
    return request('/monitoring/status');
  },

  async getMonitoringFlows(limit = 50): Promise<{ total: number; flows: LiveFlowRecord[] }> {
    return request(`/monitoring/flows?limit=${limit}`);
  },

  async triggerTestPacket(): Promise<any> {
    return request('/monitoring/test-packet', {
      method: 'POST',
      body: JSON.stringify({})
    });
  },

  /**
   * Connects to Server-Sent Events stream for real-time live flow and alert updates.
   * Returns a cleanup function to close the stream.
   */
  connectLiveEventStream(
    onFlow: (flow: LiveFlowRecord) => void,
    onAlert: (alert: AlertItem) => void,
    onStatus: (status: LiveMonitoringStatus) => void,
    onError?: (err: any) => void
  ): () => void {
    const base = currentBaseUrl.replace(/\/+$/, '') || '/api';
    const sseUrl = `${base}/monitoring/events`;
    let eventSource: EventSource | null = null;

    try {
      eventSource = new EventSource(sseUrl);

      eventSource.onmessage = (e) => {
        try {
          const payload = JSON.parse(e.data);
          if (payload.event === 'flow' && payload.data) {
            onFlow(payload.data);
          } else if (payload.event === 'alert' && payload.data) {
            onAlert(payload.data);
          } else if (payload.event === 'status' && payload.data) {
            onStatus(payload.data);
          }
        } catch {
          // ignore non-json ping comments
        }
      };

      eventSource.addEventListener('flow', (e: any) => {
        try {
          const flow = JSON.parse(e.data);
          onFlow(flow);
        } catch {}
      });

      eventSource.addEventListener('alert', (e: any) => {
        try {
          const alert = JSON.parse(e.data);
          onAlert(alert);
        } catch {}
      });

      eventSource.addEventListener('status', (e: any) => {
        try {
          const status = JSON.parse(e.data);
          onStatus(status);
        } catch {}
      });

      eventSource.onerror = (err) => {
        if (onError) onError(err);
      };
    } catch (err) {
      if (onError) onError(err);
    }

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }
};
