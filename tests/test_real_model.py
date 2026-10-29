"""
ThreatLens — Unit Tests for Real scikit-learn Isolation Forest Inference & Thresholding
"""

import os
import sys
import unittest
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.predict import ThreatPredictor
from ml.thresholding import calibrate_threshold, compare_threshold_strategies


class TestRealModelInference(unittest.TestCase):
    def setUp(self):
        self.predictor = ThreatPredictor()

    def test_model_is_ready_with_real_estimator(self):
        """Ensures that the model predictor loads real IsolationForest and Preprocessor."""
        self.assertTrue(self.predictor.is_ready(), "Predictor should be ready after training")
        self.assertIsNotNone(self.predictor.iso_model)
        self.assertTrue(hasattr(self.predictor.iso_model, "score_samples"))
        self.assertTrue(hasattr(self.predictor.iso_model, "decision_function"))

    def test_inference_returns_required_schema(self):
        """Verifies prediction returns complete, un-fabricated structure."""
        flow = {
            "Destination Port": 80,
            "Flow Duration": 45000,
            "Total Fwd Packets": 2,
            "Total Backward Packets": 2,
            "Total Length of Fwd Packets": 100,
            "Total Length of Bwd Packets": 200,
            "Flow Bytes/s": 6666.6,
            "Flow Packets/s": 88.8,
            "SYN Flag Count": 0,
            "ACK Flag Count": 1
        }
        res = self.predictor.predict_flow(flow)

        self.assertIn("prediction", res)
        self.assertIn("is_anomaly", res)
        self.assertIn("anomaly_score", res)
        self.assertIn("decision_function", res)
        self.assertIn("calibrated_threshold", res)
        self.assertIn("risk_level", res)
        self.assertIn("top_contributing_features", res)
        self.assertIn("model_architecture", res)

        self.assertEqual(res["model_architecture"], "Isolation Forest (scikit-learn)")
        self.assertIsInstance(res["anomaly_score"], float)
        self.assertIsInstance(res["is_anomaly"], bool)
        self.assertTrue(0.0 <= res["anomaly_score"] <= 1.0)
        self.assertGreater(len(res["top_contributing_features"]), 0)

        # Check feature contribution format
        first_feat = res["top_contributing_features"][0]
        self.assertIn("feature", first_feat)
        self.assertIn("deviation_score", first_feat)
        self.assertIn("is_outlier", first_feat)

    def test_threshold_override_behavior(self):
        """Tests that threshold override strictly governs the is_anomaly verdict."""
        flow = {
            "Destination Port": 80,
            "Flow Duration": 10000,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Flow Bytes/s": 100.0,
            "Flow Packets/s": 10.0
        }
        # With threshold = 0.0, all flows are anomalous
        res_zero = self.predictor.predict_flow(flow, threshold_override=0.0)
        self.assertTrue(res_zero["is_anomaly"])

        # With threshold = 1.0, no flows are anomalous
        res_one = self.predictor.predict_flow(flow, threshold_override=1.0)
        self.assertFalse(res_one["is_anomaly"])

    def test_missing_model_raises_runtime_error(self):
        """Verifies that an uninitialized predictor raises clear RuntimeError."""
        empty_predictor = ThreatPredictor(model_dir="/tmp/non_existent_threatlens_dir")
        self.assertFalse(empty_predictor.is_ready())
        with self.assertRaises(RuntimeError) as ctx:
            empty_predictor.predict_flow({"Destination Port": 80})
        self.assertIn("model artifacts are not loaded", str(ctx.exception).lower())

    def test_adaptive_threshold_calibration(self):
        """Verifies percentile thresholding on validation normal scores."""
        scores = [0.38, 0.40, 0.41, 0.42, 0.43, 0.44, 0.45, 0.46, 0.47, 0.50]
        t95 = calibrate_threshold(scores, percentile=95.0)
        # 95th percentile should be between 0.47 and 0.50
        self.assertGreater(t95, 0.45)
        self.assertLessEqual(t95, 0.50)


if __name__ == "__main__":
    unittest.main()
