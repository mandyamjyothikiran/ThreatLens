"""
ThreatLens — Unit Tests for Evaluation Metrics, Zero-Day Protocol, and Ground Truth Evaluation Engine
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.evaluate import calculate_metrics, run_evaluation_suite
from ml.ground_truth_eval import (
    inspect_dataset_content,
    evaluate_ground_truth_dataset,
    load_training_fingerprints
)

class TestEvaluation(unittest.TestCase):
    def test_metrics_calculation(self):
        y_true = [1, 1, 1, 0, 0, 0, 0, 0]
        y_pred = [1, 1, 0, 0, 0, 0, 0, 1]
        
        m = calculate_metrics(y_true, y_pred)
        self.assertEqual(m["confusion_matrix"]["true_positive"], 2)
        self.assertEqual(m["confusion_matrix"]["false_negative"], 1)
        self.assertEqual(m["confusion_matrix"]["true_negative"], 4)
        self.assertEqual(m["confusion_matrix"]["false_positive"], 1)
        self.assertAlmostEqual(m["accuracy"], 6 / 8, places=3)
        self.assertAlmostEqual(m["recall"], 2 / 3, places=3)
        self.assertAlmostEqual(m["precision"], 2 / 3, places=3)

    def test_zero_division_metrics(self):
        # Case where there are 0 predicted positives
        y_true = [1, 1]
        y_pred = [0, 0]
        m = calculate_metrics(y_true, y_pred)
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["recall"], 0.0)
        self.assertEqual(m["f1_score"], 0.0)

    def test_csv_inspection(self):
        sample_records = [
            {"Destination Port": "80", "Flow Duration": "1000", "Label": "BENIGN", "Flow ID": "1"},
            {"Destination Port": "443", "Flow Duration": "2000", "Label": "PortScan", "Flow ID": "2"},
            {"Destination Port": "22", "Flow Duration": "", "Label": "SSH-Patator", "Flow ID": "3"}
        ]
        expected_features = ["Destination Port", "Flow Duration", "Total Fwd Packets"]
        inspection = inspect_dataset_content(sample_records, expected_features)

        self.assertEqual(inspection["total_records"], 3)
        self.assertEqual(inspection["detected_label_column"], "Label")
        self.assertIn("BENIGN", inspection["label_distribution"])
        self.assertIn("PortScan", inspection["label_distribution"])
        self.assertEqual(inspection["label_distribution"]["BENIGN"], 1)
        self.assertEqual(inspection["label_distribution"]["PortScan"], 1)
        self.assertTrue(inspection["missing_values_by_column"]["Flow Duration"] >= 1)
        self.assertEqual(len(inspection["matched_features"]), 2)
        self.assertIn("Total Fwd Packets", inspection["missing_expected_features"])

    def test_ground_truth_evaluation_pipeline(self):
        sample_records = [
            {"Destination Port": 80, "Flow Duration": 512800, "Label": "BENIGN"},
            {"Destination Port": 80, "Flow Duration": 512800, "Label": "BENIGN"},
            {"Destination Port": 4444, "Flow Duration": 99999999, "Label": "Infiltration"}
        ]
        preprocessor_mock = {
            "selected_features": ["Destination Port", "Flow Duration"],
            "centers": {"Destination Port": 80.0, "Flow Duration": 512800.0},
            "scales": {"Destination Port": 58.0, "Flow Duration": 11477100.0}
        }

        eval_res = evaluate_ground_truth_dataset(
            records=sample_records,
            label_column="Label",
            preprocessor_data=preprocessor_mock,
            normal_labels=["BENIGN"],
            decision_threshold=0.542
        )

        metrics = eval_res["metrics"]
        self.assertEqual(metrics["total_samples"], 3)
        cm = metrics["confusion_matrix"]
        self.assertIn("true_positive", cm)
        self.assertIn("true_negative", cm)
        self.assertIn("false_positive", cm)
        self.assertIn("false_negative", cm)
        self.assertGreaterEqual(metrics["accuracy"], 0.0)
        self.assertLessEqual(metrics["accuracy"], 1.0)
        self.assertTrue(len(eval_res["records"]) == 3)
        self.assertIn("per_class_breakdown", eval_res)

    def test_evaluation_suite_generates_reports(self):
        eval_report, unseen_report = run_evaluation_suite()
        self.assertIn("models", eval_report)
        self.assertIn("isolation_forest", eval_report["models"])
        self.assertIn("random_forest", eval_report["models"])
        self.assertIn("held_out_categories", unseen_report)
        self.assertTrue(len(unseen_report["held_out_categories"]) >= 3)

if __name__ == "__main__":
    unittest.main()
