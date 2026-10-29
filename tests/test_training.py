"""
ThreatLens — Unit Tests for Model Training and Tree Isolation
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.train import PurePythonIsolationForest, train_pipeline

class TestTraining(unittest.TestCase):
    def test_isolation_forest_scoring(self):
        # 10 normal 2D points centered at 0, 1 clear outlier at (50, 50)
        X = [[0.1, -0.2], [0.0, 0.1], [-0.1, 0.0], [0.2, -0.1], [0.0, 0.0],
             [0.15, 0.1], [-0.2, -0.1], [0.05, 0.2], [-0.1, 0.15], [0.0, -0.1]]
        outlier = [[50.0, 50.0]]
        
        iso = PurePythonIsolationForest(n_estimators=30, max_samples=10, seed=42)
        iso.fit(X)
        
        normal_scores = iso.score_samples(X)
        outlier_score = iso.score_samples(outlier)[0]
        
        avg_normal_score = sum(normal_scores) / len(normal_scores)
        # Outlier path length is much shorter, hence anomaly score is significantly higher
        self.assertGreater(outlier_score, avg_normal_score)

    def test_pipeline_execution(self):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "data", "cicids2017_sample.csv")
        models_dir = os.path.join(os.path.dirname(__file__), "..", "models")
        meta, model, prep = train_pipeline(data_path=sample_path, output_dir=models_dir)
        
        self.assertIn("framework", meta)
        self.assertIn("calibrated_threshold", meta["isolation_forest"])
        self.assertTrue(os.path.exists(os.path.join(models_dir, "metadata.json")))
        self.assertTrue(os.path.exists(os.path.join(models_dir, "preprocessor.json")))

if __name__ == "__main__":
    unittest.main()
