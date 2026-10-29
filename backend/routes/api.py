"""
ThreatLens — Flask API Routes Blueprint
Implements REST API endpoints with robust validation, appropriate HTTP error codes,
and logging. Prevents ground-truth label leakage and exposes real-time monitoring and inference.
"""

import os
import sys
import json
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, Response

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from backend.schemas.traffic_schema import validate_flow_payload
from backend.services.model_service import ModelService
from backend.services.preprocessing_service import PreprocessingService
from backend.services.capture_service import NetworkCaptureService
from ml.ground_truth_eval import inspect_dataset_content, evaluate_ground_truth_dataset, load_training_fingerprints

logger = logging.getLogger("ThreatLens.ApiRoutes")
api_bp = Blueprint("api", __name__)

model_service = ModelService()
prep_service = PreprocessingService()
capture_service = NetworkCaptureService()


@api_bp.route("/health", methods=["GET"])
def health_check():
    """Health status and service availability."""
    return jsonify({
        "status": "healthy",
        "service": "ThreatLens Zero-Day Detection Engine",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "model_loaded": model_service.predictor.is_ready()
    }), 200


@api_bp.route("/model-info", methods=["GET"])
def model_info():
    """Returns loaded model architecture, feature metadata, and threshold."""
    info = model_service.get_model_info()
    return jsonify(info), 200


@api_bp.route("/predict", methods=["POST"])
def predict():
    """
    Executes real anomaly inference on incoming network flow record.
    Rejects invalid types, NaNs, and provides feature contributions.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    payload = request.get_json()
    is_valid, cleaned_data, err_msg = validate_flow_payload(payload)
    if not is_valid:
        return jsonify({"error": err_msg}), 422

    threshold_override = payload.get("threshold_override")
    if threshold_override is not None:
        try:
            threshold_override = float(threshold_override)
            if not (0.0 <= threshold_override <= 1.0):
                return jsonify({"error": "threshold_override must be between 0.0 and 1.0"}), 422
        except (ValueError, TypeError):
            return jsonify({"error": "threshold_override must be a numeric float"}), 422

    try:
        prediction_result = model_service.predict(cleaned_data, threshold_override=threshold_override)
        return jsonify({
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "result": prediction_result
        }), 200
    except RuntimeError as ex:
        logger.error("Inference failed: %s", str(ex))
        return jsonify({"error": str(ex)}), 503
    except Exception as ex:
        logger.exception("Unexpected error during inference")
        return jsonify({"error": "Internal inference error occurred"}), 500


@api_bp.route("/metrics", methods=["GET"])
def metrics():
    """Retrieves verified model evaluation metrics and confusion matrices."""
    metrics_data = model_service.get_metrics()
    return jsonify(metrics_data), 200


@api_bp.route("/alerts", methods=["GET"])
def alerts():
    """
    Returns detected threat alerts. All scores come from actual model inference.
    NEVER leaks ground-truth labels into alert scores or trigger conditions.
    """
    limit = request.args.get("limit", default=50, type=int)

    # 1. First return real live alerts if monitoring has captured any
    live_alerts = capture_service.get_recent_alerts(limit=limit)
    if live_alerts:
        return jsonify({
            "total_alerts": len(live_alerts),
            "unreviewed_count": len(live_alerts),
            "alerts": live_alerts,
            "source": "live_monitoring"
        }), 200

    # 2. If no live alerts yet exist, evaluate dataset flows using REAL model inference
    flows = prep_service.get_traffic_flows(limit=100)["records"]
    alert_list = []

    for f in flows:
        flow_features = f.get("features", {})
        try:
            # Genuine inference — no ground truth knowledge used
            pred = model_service.predict(flow_features)
            if pred["is_anomaly"]:
                alert_list.append({
                    "alert_id": f"ALT-{len(alert_list)+1:04d}",
                    "flow_id": f["id"],
                    "timestamp": f["timestamp"],
                    "dest_port": f["dest_port"],
                    "protocol": "TCP" if f["dest_port"] != 53 else "UDP",
                    "anomaly_score": pred["anomaly_score"],
                    "decision_function": pred.get("decision_function", 0.0),
                    "risk_severity": pred["risk_level"],
                    "finding_type": "Model-Generated Anomaly",
                    "investigation_status": "Analyst Review Required",
                    "trigger_category": f"Behavioral Deviation (Score: {pred['anomaly_score']})",
                    "top_contributing_features": pred.get("top_contributing_features", []),
                    "annotated_dataset_label": f.get("actual_label", "UNSPECIFIED"),
                    "academic_disclaimer": "Flagged as anomalous behavioral divergence; not a confirmed zero-day until analyst verification."
                })
        except Exception as ex:
            logger.debug("Could not score dataset flow for alerts: %s", ex)

    return jsonify({
        "total_alerts": len(alert_list),
        "unreviewed_count": len(alert_list),
        "alerts": alert_list[:limit],
        "source": "dataset_scored_by_model"
    }), 200


@api_bp.route("/traffic", methods=["GET"])
def traffic():
    """Returns paginated analyzed network flow records."""
    limit = request.args.get("limit", default=25, type=int)
    offset = request.args.get("offset", default=0, type=int)
    filter_type = request.args.get("filter", default="all", type=str)

    data = prep_service.get_traffic_flows(limit=limit, offset=offset, filter_type=filter_type)
    return jsonify(data), 200


@api_bp.route("/evaluate/unseen", methods=["GET", "POST"])
def unseen_evaluation():
    """Returns the held-out attack category zero-day simulation experiment."""
    report = model_service.get_unseen_attack_metrics()
    return jsonify(report), 200


@api_bp.route("/adaptive-thresholds", methods=["GET"])
def adaptive_thresholds():
    """Returns empirical threshold comparison strategies."""
    report = model_service.get_adaptive_threshold_metrics()
    # If the report has a "comparison" list, return that directly for frontend table
    if isinstance(report, dict) and "comparison" in report:
        return jsonify(report["comparison"]), 200
    return jsonify(report), 200


@api_bp.route("/dataset/inspection", methods=["GET"])
def dataset_inspection():
    """Returns schema and dataset inspection statistics."""
    report = prep_service.get_dataset_inspection()
    return jsonify(report), 200


@api_bp.route("/dataset/preprocessing", methods=["GET"])
def dataset_preprocessing():
    """Returns data hygiene, leakage prevention, and transformation audit."""
    report = prep_service.get_preprocessing_report()
    return jsonify(report), 200


@api_bp.route("/evaluate/inspect", methods=["POST"])
def evaluate_inspect():
    """Inspects an uploaded or sample CSV file for schema compatibility and data leakage."""
    payload = request.get_json(silent=True) or {}
    sample_file = payload.get("sample_file")
    csv_content = payload.get("csv_content")

    records = []
    if sample_file == "heldout":
        import csv
        path = os.path.join(prep_service.data_dir, "cicids2017_heldout_sample.csv")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8-sig") as f:
                records = list(csv.DictReader(f))
    elif sample_file == "train":
        import csv
        path = os.path.join(prep_service.data_dir, "cicids2017_sample.csv")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8-sig") as f:
                records = list(csv.DictReader(f))
    elif csv_content:
        import csv
        import io
        reader = csv.DictReader(io.StringIO(csv_content))
        records = list(reader)

    expected_features = (
        model_service.predictor.preprocessor.selected_features
        if model_service.predictor.is_ready()
        else []
    )
    training_fps = load_training_fingerprints(os.path.join(prep_service.data_dir, "cicids2017_sample.csv"))
    inspection_result = inspect_dataset_content(records, expected_features, training_fingerprints=training_fps)
    return jsonify(inspection_result), 200


@api_bp.route("/evaluate/run", methods=["POST"])
def evaluate_run():
    """Executes ground truth evaluation on an uploaded or sample dataset using genuine inference."""
    payload = request.get_json(silent=True) or {}
    sample_file = payload.get("sample_file")
    csv_content = payload.get("csv_content")
    label_col = payload.get("label_column", "Label")
    normal_labels = payload.get("normal_labels", ["BENIGN", "normal", "0"])
    model_type = payload.get("model_type", "isolation_forest")
    threshold = float(payload.get("threshold", model_service.predictor.calibrated_threshold))

    records = []
    if sample_file == "heldout":
        import csv
        path = os.path.join(prep_service.data_dir, "cicids2017_heldout_sample.csv")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8-sig") as f:
                records = list(csv.DictReader(f))
    elif sample_file == "train":
        import csv
        path = os.path.join(prep_service.data_dir, "cicids2017_sample.csv")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8-sig") as f:
                records = list(csv.DictReader(f))
    elif csv_content:
        import csv
        import io
        reader = csv.DictReader(io.StringIO(csv_content))
        records = list(reader)

    if not records:
        return jsonify({"error": "No dataset records provided for evaluation"}), 400

    prep_data = {
        "selected_features": model_service.predictor.preprocessor.selected_features if model_service.predictor.is_ready() else [],
        "centers": model_service.predictor.preprocessor.centers if model_service.predictor.is_ready() else {},
        "scales": model_service.predictor.preprocessor.scales if model_service.predictor.is_ready() else {}
    }
    training_fps = load_training_fingerprints(os.path.join(prep_service.data_dir, "cicids2017_sample.csv"))

    eval_result = evaluate_ground_truth_dataset(
        records=records,
        label_column=label_col,
        preprocessor_data=prep_data,
        normal_labels=normal_labels,
        model_type=model_type,
        decision_threshold=threshold,
        training_fingerprints=training_fps
    )
    return jsonify(eval_result), 200


# --- REAL-TIME NETWORK MONITORING ENDPOINTS ---

@api_bp.route("/interfaces", methods=["GET"])
def list_interfaces():
    """Discovers available local network interfaces and capture permissions."""
    result = capture_service.get_available_interfaces()
    return jsonify(result), 200


@api_bp.route("/monitoring/start", methods=["POST"])
def start_monitoring():
    """Starts background packet capture and flow extraction with explicit error handling."""
    payload = request.get_json(silent=True) or {}
    interface = payload.get("interface", "lo")
    mode = payload.get("mode", "synthetic_test_stream")
    flow_timeout = float(payload.get("flow_timeout_sec", 3.0))
    threshold_override = payload.get("threshold_override")
    pcap_path = payload.get("pcap_path")

    if threshold_override is not None:
        threshold_override = float(threshold_override)

    result = capture_service.start_monitoring(
        interface=interface,
        mode=mode,
        flow_timeout_sec=flow_timeout,
        threshold_override=threshold_override,
        pcap_path=pcap_path
    )

    if result.get("status") == "error":
        status_code = 403 if result.get("error") == "PERMISSION_DENIED" else 400
        return jsonify(result), status_code

    return jsonify(result), 200


@api_bp.route("/monitoring/stop", methods=["POST"])
def stop_monitoring():
    """Stops the active monitoring session and flushes buffers."""
    result = capture_service.stop_monitoring()
    return jsonify(result), 200


@api_bp.route("/monitoring/status", methods=["GET"])
def monitoring_status():
    """Returns real-time capture metrics, packet counts, uptime, and model state."""
    status = capture_service.get_status()
    return jsonify(status), 200


@api_bp.route("/monitoring/flows", methods=["GET"])
def monitoring_flows():
    """Returns recently captured live flows."""
    limit = request.args.get("limit", default=50, type=int)
    flows = capture_service.get_recent_flows(limit=limit)
    return jsonify({"total": len(flows), "flows": flows}), 200


@api_bp.route("/monitoring/test-packet", methods=["POST"])
def trigger_test_packet():
    """Injects an authorized test packet to verify the capture-to-SSE pipeline."""
    result = capture_service.inject_test_flow()
    return jsonify(result), 200


@api_bp.route("/monitoring/events", methods=["GET"])
def monitoring_events():
    """Server-Sent Events (SSE) stream for real-time live flow and alert push."""
    def event_stream():
        q = capture_service.subscribe_events()
        try:
            # Yield initial status
            init_data = json.dumps({"event": "status", "data": capture_service.get_status()})
            yield f"data: {init_data}\n\n"

            while True:
                try:
                    msg = q.get(timeout=25.0)
                    yield f"data: {json.dumps(msg)}\n\n"
                except Exception:
                    # Heartbeat comment to keep SSE alive
                    yield ": ping\n\n"
        finally:
            capture_service.unsubscribe_events(q)

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
