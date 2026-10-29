/**
 * ThreatLens — Domain Type Definitions
 */

export type OperatingMode = 'live_monitoring' | 'dataset_analysis';

export type PageId =
  | 'dashboard'
  | 'live_monitoring'
  | 'alerts'
  | 'ml_model'
  | 'evaluation'
  | 'settings';

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export interface NetworkInterfaceInfo {
  id: string;
  name: string;
  index: number;
  is_loopback: boolean;
  description: string;
  supported: boolean;
}

export interface LiveMonitoringStatus {
  is_monitoring: boolean;
  selected_interface: string | null;
  capture_mode: string;
  started_at: string | null;
  uptime_seconds: number;
  total_packets: number;
  total_flows: number;
  total_anomalies: number;
  malformed_packets_dropped?: number;
  last_error?: string | null;
  active_subscribers?: number;
  model_ready: boolean;
}

export interface LiveFlowRecord {
  id: string;
  timestamp: string;
  dest_port: number;
  protocol: string;
  src_ip?: string;
  dst_ip?: string;
  duration_us: number;
  total_fwd_pkts: number;
  total_bwd_pkts: number;
  flow_bytes_per_sec: number;
  flow_pkts_per_sec: number;
  anomaly_score: number;
  calibrated_threshold: number;
  risk_level: RiskLevel;
  prediction: string;
  is_anomaly: boolean;
  is_test_data?: boolean;
  top_features?: FeatureContribution[];
  features?: Record<string, any>;
}

export interface FlowRecord {
  id: string;
  timestamp: string;
  dest_port: number;
  protocol: string;
  duration_us: number;
  total_fwd_pkts: number;
  total_bwd_pkts: number;
  flow_bytes_per_sec: number;
  flow_pkts_per_sec: number;
  actual_label: string;
  is_normal: boolean;
  anomaly_score: number;
  risk_level: RiskLevel;
  features?: Record<string, any>;
}

export interface FeatureContribution {
  feature: string;
  raw_value: any;
  deviation_score: number;
  is_outlier: boolean;
}

export interface PredictionResult {
  prediction: string;
  is_anomaly: boolean;
  anomaly_score: number;
  calibrated_threshold: number;
  risk_level: RiskLevel;
  confidence: number;
  top_contributing_features: FeatureContribution[];
  analyzed_feature_count: number;
}

export interface AlertItem {
  alert_id: string;
  flow_id: string;
  timestamp: string;
  dest_port: number;
  protocol: string;
  anomaly_score: number;
  risk_severity: 'Low' | 'Medium' | 'High' | 'Critical';
  prediction_category: string;
  finding_type: string;
  investigation_status: 'Analyst Review Required' | 'Investigating' | 'Confirmed Incident' | 'False Positive';
  trigger_category: string;
  academic_disclaimer: string;
  top_contributing_features?: FeatureContribution[];
}

export interface ConfusionMatrixValues {
  true_positive: number;
  true_negative: number;
  false_positive: number;
  false_negative: number;
}

export interface ModelMetricsItem {
  model_name: string;
  approach: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  true_positive_rate: number;
  specificity: number;
  roc_auc: number;
  pr_auc?: number;
  inference_latency_ms: number;
  training_time_seconds: number;
  confusion_matrix: ConfusionMatrixValues;
}

export interface HeldOutCategoryItem {
  category: string;
  sample_count: number;
  isolation_forest_recall: number;
  isolation_forest_avg_score: number;
  random_forest_recall: number;
  analysis: string;
}

export interface UnseenAttackReport {
  experiment_title: string;
  timestamp: string;
  protocol_description: string;
  held_out_categories: HeldOutCategoryItem[];
  overall_summary: {
    unseen_attack_total_records: number;
    isolation_forest_overall_unseen_recall: number;
    random_forest_overall_unseen_recall: number;
    unseen_detection_gap_percentage: string;
    academic_conclusion: string;
  };
  limitations: string[];
}

export interface EvaluationReport {
  timestamp: string;
  dataset_name: string;
  test_sample_size: number;
  positive_class: string;
  decision_threshold: number;
  threshold_calibration_method: string;
  models: {
    isolation_forest: ModelMetricsItem;
    random_forest: ModelMetricsItem;
  };
  roc_curve: Array<{ fpr: number; tpr_iso: number; tpr_rf: number }>;
  precision_recall_curve: Array<{ recall: number; precision_iso: number; precision_rf: number }>;
}

export interface ThresholdComparisonItem {
  strategy: string;
  threshold: number;
  validation_fpr: number;
  validation_recall: number;
  validation_precision: number;
  validation_f1: number;
  verdict: string;
}

export interface ModelInfoResponse {
  status: 'ready' | 'not_trained';
  message?: string;
  model_architecture?: string;
  calibrated_threshold?: number;
  feature_count?: number;
  selected_features?: string[];
  top_features?: Array<{ feature: string; weight: number; median: number }>;
  training_duration_seconds?: number;
  trained_at?: string;
  dataset?: {
    source: string;
    total_samples: number;
    train_samples: number;
    val_samples: number;
    test_samples: number;
  };
}

export interface DatasetInspectionResult {
  status: string;
  total_records: number;
  columns: string[];
  candidate_label_columns: string[];
  detected_label_column: string | null;
  label_distribution: Record<string, number>;
  missing_values_by_column: Record<string, number>;
  total_missing_values: number;
  feature_compatibility_percentage: number;
  matched_features: string[];
  missing_expected_features: string[];
  training_overlap_count: number;
  training_overlap_percentage: number;
  data_leakage_warning: string | null;
}

export interface GroundTruthRecord {
  id: string;
  dest_port: number;
  protocol: string;
  actual_label: string;
  mapped_actual: 'Normal' | 'Attack';
  predicted_label: 'Normal' | 'Attack';
  status: 'TP' | 'TN' | 'FP' | 'FN';
  is_correct: boolean;
  anomaly_score: number;
  risk_level: RiskLevel;
  is_training_overlap: boolean;
  top_features: Array<{ feature: string; deviation: number; raw: any }>;
}

export interface PerClassMetricItem {
  label: string;
  sample_count: number;
  class_type: 'Normal' | 'Attack';
  accuracy_percentage: number;
  predicted_attack: number;
  predicted_normal: number;
  avg_anomaly_score: number;
}

export interface GroundTruthEvaluationResult {
  status: string;
  model_type: string;
  metrics: {
    total_samples: number;
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    false_positive_rate: number;
    specificity: number;
    decision_threshold: number;
    positive_class: string;
    negative_class: string;
    confusion_matrix: {
      true_positive: number;
      true_negative: number;
      false_positive: number;
      false_negative: number;
    };
  };
  explanations: {
    true_positive: string;
    true_negative: string;
    false_positive: string;
    false_negative: string;
  };
  per_class_breakdown: PerClassMetricItem[];
  dataset_split_info: {
    evaluation_mode: string;
    protocol: string;
    description: string;
    training_overlap_detected: boolean;
    overlap_record_count: number;
    overlap_percentage: number;
    recommendation: string;
  };
  records: GroundTruthRecord[];
}
