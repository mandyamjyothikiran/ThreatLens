"""
ThreatLens — Unit and Integration Tests for REST API Endpoints and Schema Validation
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.app import create_app
from backend.schemas.traffic_schema import validate_flow_payload
from ml.predict import ThreatPredictor


class TestApiSchemas(unittest.TestCase):
    def setUp(self):
        self.predictor = ThreatPredictor()
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_schema_valid_payload(self):
        payload = {
            "flow": {
                "Destination Port": 80,
                "Flow Duration": 50000,
                "Total Fwd Packets": 2,
                "Total Backward Packets": 2,
                "Flow Bytes/s": 1200.0,
                "Flow Packets/s": 40.0
            }
        }
        is_valid, cleaned, err = validate_flow_payload(payload)
        self.assertTrue(is_valid)
        self.assertIsNone(err)
        self.assertIn("Destination Port", cleaned)

    def test_schema_rejects_nan(self):
        payload = {
            "flow": {
                "Destination Port": float("nan"),
                "Flow Duration": 50000
            }
        }
        is_valid, cleaned, err = validate_flow_payload(payload)
        self.assertFalse(is_valid)
        self.assertIn("NaN", err)

    def test_schema_rejects_empty(self):
        payload = {"flow": {}}
        is_valid, cleaned, err = validate_flow_payload(payload)
        self.assertFalse(is_valid)

    def test_predictor_inference(self):
        if self.predictor.is_ready():
            sample_flow = {
                "Destination Port": 80,
                "Flow Duration": 38000,
                "Total Fwd Packets": 1,
                "Total Backward Packets": 1,
                "Total Length of Fwd Packets": 6,
                "Total Length of Bwd Packets": 6,
                "Flow Bytes/s": 313.25,
                "Flow Packets/s": 52.21
            }
            res = self.predictor.predict_flow(sample_flow)
            self.assertIn("prediction", res)
            self.assertIn("anomaly_score", res)
            self.assertIn("risk_level", res)
            self.assertTrue(0.0 <= res["anomaly_score"] <= 1.0)

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("model_loaded", data)

    def test_model_info_endpoint(self):
        resp = self.client.get("/model-info")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("status", data)
        self.assertIn("model_architecture", data)

    def test_predict_endpoint_success(self):
        payload = {
            "flow": {
                "Destination Port": 443,
                "Flow Duration": 200000,
                "Total Fwd Packets": 10,
                "Total Backward Packets": 8,
                "Flow Bytes/s": 5000.0,
                "Flow Packets/s": 90.0
            }
        }
        resp = self.client.post("/predict", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("result", data)
        self.assertIn("anomaly_score", data["result"])

    def test_alerts_endpoint_no_label_leakage(self):
        """Verifies /alerts computes scores through real model inference, not stored attack names."""
        resp = self.client.get("/alerts")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("alerts", data)

        for alert in data["alerts"]:
            # Score must be continuous float from model inference
            self.assertIsInstance(alert["anomaly_score"], float)
            self.assertTrue(0.0 <= alert["anomaly_score"] <= 1.0)
            # Scores must NOT be the old leaked constants (0.82, 0.88, 0.76)
            self.assertNotIn(alert["anomaly_score"], [0.82, 0.88, 0.76])
            self.assertEqual(alert["finding_type"], "Model-Generated Anomaly")
            self.assertEqual(alert["investigation_status"], "Analyst Review Required")

    def test_test_packet_endpoint(self):
        """Verifies on-demand test packet injection."""
        resp = self.client.post("/monitoring/test-packet")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "injected")
        self.assertEqual(data["packets_processed"], 1)

    def test_adaptive_thresholds_endpoint(self):
        resp = self.client.get("/adaptive-thresholds")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_evaluate_inspect_endpoint(self):
        resp = self.client.post("/evaluate/inspect", json={"sample_file": "heldout"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total_records", data)
        self.assertGreater(data["total_records"], 0)
        self.assertIn("feature_compatibility_percentage", data)

    def test_evaluate_run_endpoint(self):
        resp = self.client.post("/evaluate/run", json={"sample_file": "heldout"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("metrics", data)
        self.assertIn("records", data)


if __name__ == "__main__":
    unittest.main()
