"""
ThreatLens — Model Training Engine
Trains:
1. Isolation Forest (Unsupervised/Semi-supervised Anomaly Detector fitted strictly on Benign traffic)
2. Random Forest (Supervised Classification Baseline fitted on training data with known labels)

Saves real fitted estimator artifacts (.joblib), preprocessor parameters (.json),
and experiment metadata (.json). Zero test data leakage.
"""

import os
import sys
import json
import math
import time
import random
import logging
from datetime import datetime, timezone
from typing import Tuple, Any, Dict
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.preprocess import Preprocessor, load_and_split_dataset
from ml.thresholding import calibrate_threshold

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ThreatLens.Train")


def c_factor(n: int) -> float:
    """Average path length of unsuccessful searches in BST."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    euler_gamma = 0.5772156649
    return 2.0 * (math.log(n - 1) + euler_gamma) - (2.0 * (n - 1) / n)


class IsolationTreeNode:
    def __init__(self, feature_idx=None, split_val=None, left=None, right=None, size=1):
        self.feature_idx = feature_idx
        self.split_val = split_val
        self.left = left
        self.right = right
        self.size = size


class PurePythonIsolationForest:
    """Pure-Python implementation of Liu et al. Isolation Forest kept for reference and testing."""
    def __init__(self, n_estimators=100, max_samples=256, contamination=0.05, seed=42):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.seed = seed
        self.trees = []
        self.c_val = 1.0

    def fit(self, X):
        random.seed(self.seed)
        n_samples = len(X)
        sample_size = min(self.max_samples, n_samples)
        self.c_val = c_factor(sample_size)
        max_depth = math.ceil(math.log2(max(sample_size, 2)))

        self.trees = []
        for _ in range(self.n_estimators):
            subsample = random.sample(X, sample_size)
            tree = self._build_tree(subsample, 0, max_depth)
            self.trees.append(tree)
        return self

    def _build_tree(self, X, current_depth, max_depth):
        n = len(X)
        if n <= 1 or current_depth >= max_depth:
            return IsolationTreeNode(size=n)

        n_features = len(X[0])
        feat_idx = random.randint(0, n_features - 1)
        vals = [row[feat_idx] for row in X]
        min_v, max_v = min(vals), max(vals)

        if min_v == max_v:
            return IsolationTreeNode(size=n)

        split_val = random.uniform(min_v, max_v)
        left_x = [row for row in X if row[feat_idx] < split_val]
        right_x = [row for row in X if row[feat_idx] >= split_val]

        if not left_x or not right_x:
            return IsolationTreeNode(size=n)

        left_node = self._build_tree(left_x, current_depth + 1, max_depth)
        right_node = self._build_tree(right_x, current_depth + 1, max_depth)
        return IsolationTreeNode(feature_idx=feat_idx, split_val=split_val, left=left_node, right=right_node, size=n)

    def _path_length(self, x, node, current_depth):
        if node.left is None or node.right is None:
            return current_depth + c_factor(node.size)
        if x[node.feature_idx] < node.split_val:
            return self._path_length(x, node.left, current_depth + 1)
        return self._path_length(x, node.right, current_depth + 1)

    def score_samples(self, X):
        """Returns anomaly risk score between 0.0 (normal) and 1.0 (anomalous)."""
        scores = []
        for x in X:
            avg_path = sum(self._path_length(x, t, 0) for t in self.trees) / max(len(self.trees), 1)
            if self.c_val <= 0:
                s = 0.5
            else:
                s = 2.0 ** (-avg_path / self.c_val)
            scores.append(s)
        return scores


def train_pipeline(data_path="data/cicids2017_sample.csv", output_dir="models", random_state=42) -> Tuple[Dict[str, Any], Any, Any]:
    """
    Executes the complete training workflow:
    1. Loads dataset and splits with zero leakage (Train 60%, Val 20%, Test 20%)
    2. Fits Preprocessor strictly on training split
    3. Fits Isolation Forest strictly on Benign training traffic
    4. Calibrates decision threshold on validation set (95th percentile of normal validation scores)
    5. Fits Random Forest baseline on train set with known labels
    6. Serializes actual fitted model estimators and metadata
    Returns: (metadata, iso_model, preprocessor)
    """
    os.makedirs(output_dir, exist_ok=True)
    logger.info("Initiating ThreatLens training pipeline from: %s", data_path)
    start_time = time.time()

    train_rows, val_rows, test_rows, columns = load_and_split_dataset(data_path, seed=random_state)

    benign_train = [r for r in train_rows if r.get("Label", "").strip().upper() == "BENIGN"]
    logger.info("Train rows: %d (%d pure benign)", len(train_rows), len(benign_train))

    # 1. Fit Preprocessor strictly on training data
    preprocessor = Preprocessor(target_label_col="Label", normal_label="BENIGN")
    train_norm = preprocessor.fit_and_transform(train_rows, columns)
    preprocessor_path = os.path.join(output_dir, "preprocessor.json")
    preprocessor.save(preprocessor_path)

    # 2. Extract benign feature vectors for Isolation Forest
    benign_indices = [i for i, r in enumerate(train_rows) if r.get("Label", "").strip().upper() == "BENIGN"]
    if benign_indices:
        X_train_benign = np.array([train_norm[i] for i in benign_indices], dtype=float)
    else:
        logger.warning("No BENIGN labels found in training split; using all train rows.")
        X_train_benign = np.array(train_norm, dtype=float)

    n_samples = len(X_train_benign)
    sample_size = min(256, n_samples) if n_samples > 0 else 1

    logger.info("Fitting scikit-learn IsolationForest on %d benign instances (max_samples=%d)...", n_samples, sample_size)
    iso_model = IsolationForest(
        n_estimators=100,
        max_samples=sample_size,
        contamination=0.05,
        random_state=random_state
    )
    iso_model.fit(X_train_benign)

    # Save fitted IsolationForest estimator
    iso_model_path = os.path.join(output_dir, "isolation_forest.joblib")
    joblib.dump(iso_model, iso_model_path)
    logger.info("Fitted Isolation Forest saved to: %s", iso_model_path)

    # 3. Fit Random Forest supervised baseline
    y_train = np.array([0 if r.get("Label", "").strip().upper() == "BENIGN" else 1 for r in train_rows], dtype=int)
    X_train_all = np.array(train_norm, dtype=float)

    rf_model = RandomForestClassifier(
        n_estimators=50,
        max_depth=8,
        random_state=random_state
    )
    rf_model.fit(X_train_all, y_train)

    rf_model_path = os.path.join(output_dir, "random_forest.joblib")
    joblib.dump(rf_model, rf_model_path)
    logger.info("Fitted Random Forest baseline saved to: %s", rf_model_path)

    # 4. Calibrate anomaly threshold on validation benign partition
    val_norm = preprocessor.transform(val_rows)
    X_val = np.array(val_norm, dtype=float)
    val_benign_indices = [i for i, r in enumerate(val_rows) if r.get("Label", "").strip().upper() == "BENIGN"]

    if val_benign_indices:
        X_val_benign = X_val[val_benign_indices]
        val_benign_scores = (-iso_model.score_samples(X_val_benign)).tolist()
    else:
        val_benign_scores = (-iso_model.score_samples(X_val)).tolist()

    calibrated_threshold = calibrate_threshold(val_benign_scores, percentile=95.0)

    # 5. Feature sensitivity estimation
    feature_importance = []
    for feat_idx, feat_name in enumerate(preprocessor.selected_features):
        vals_benign = X_train_benign[:, feat_idx]
        var = float(np.var(vals_benign)) if len(vals_benign) > 0 else 0.0
        feature_importance.append({
            "feature": feat_name,
            "weight": round(min(1.0, math.sqrt(var) / 10.0 + 0.1), 4),
            "median": round(float(preprocessor.centers.get(feat_name, 0.0)), 3)
        })
    feature_importance.sort(key=lambda x: x["weight"], reverse=True)

    elapsed = round(time.time() - start_time, 3)

    metadata = {
        "framework": "ThreatLens Zero-Day Detection Engine",
        "version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat() + "Z",
        "training_duration_seconds": elapsed,
        "dataset": {
            "source": "CIC-IDS2017",
            "total_samples": len(train_rows) + len(val_rows) + len(test_rows),
            "train_samples": len(train_rows),
            "val_samples": len(val_rows),
            "test_samples": len(test_rows),
            "benign_train_samples": len(benign_train)
        },
        "isolation_forest": {
            "estimator": "sklearn.ensemble.IsolationForest",
            "artifact_path": "models/isolation_forest.joblib",
            "n_estimators": 100,
            "max_samples": sample_size,
            "contamination": 0.05,
            "calibrated_threshold": round(float(calibrated_threshold), 4),
            "score_formulation": "score = -score_samples(X). Range ~ [0.35, 0.90]. Higher = more anomalous. Flagged when score >= calibrated_threshold.",
            "decision_rule": f"is_anomaly = (anomaly_score >= {round(float(calibrated_threshold), 4)})"
        },
        "random_forest": {
            "estimator": "sklearn.ensemble.RandomForestClassifier",
            "artifact_path": "models/random_forest.joblib",
            "n_estimators": 50
        },
        "features": {
            "count": len(preprocessor.selected_features),
            "names": preprocessor.selected_features,
            "top_features": feature_importance[:10]
        }
    }

    metadata_path = os.path.join(output_dir, "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Training complete in %.2f seconds. Metadata saved to %s", elapsed, metadata_path)
    return metadata, iso_model, preprocessor


if __name__ == "__main__":
    train_pipeline()
