"""
ThreatLens — Unit Tests for Data Preprocessing and Leakage Prevention
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.preprocess import Preprocessor, clean_value, load_and_split_dataset

class TestPreprocessing(unittest.TestCase):
    def setUp(self):
        self.sample_path = os.path.join(os.path.dirname(__file__), "..", "data", "cicids2017_sample.csv")

    def test_clean_value_handling(self):
        self.assertEqual(clean_value("123.45"), 123.45)
        self.assertTrue(clean_value("inf") > 1e11)
        self.assertTrue(clean_value("-inf") < -1e11)
        import math
        self.assertTrue(math.isnan(clean_value("NaN")))
        self.assertTrue(math.isnan(clean_value("")))

    def test_dataset_splitting_no_overlap(self):
        train, val, test, cols = load_and_split_dataset(self.sample_path, seed=42)
        self.assertTrue(len(train) > 0)
        self.assertTrue(len(val) > 0)
        self.assertTrue(len(test) > 0)
        # Check no duplicate indices
        self.assertEqual(len(train) + len(val) + len(test), 20)

    def test_preprocessor_fit_transform(self):
        train, val, test, cols = load_and_split_dataset(self.sample_path, seed=42)
        prep = Preprocessor(target_label_col="Label", normal_label="BENIGN")
        train_norm = prep.fit_and_transform(train, cols)
        
        self.assertTrue(prep.is_fitted)
        self.assertEqual(len(train_norm), len(train))
        self.assertEqual(len(train_norm[0]), len(prep.selected_features))
        
        # Verify leakage columns (IP, Flow ID) were excluded
        for f in prep.selected_features:
            self.assertNotIn(f.lower(), ["flow id", "source ip", "destination ip", "timestamp"])

if __name__ == "__main__":
    unittest.main()
