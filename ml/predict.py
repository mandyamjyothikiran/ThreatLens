"""
ThreatLens — Inference and Prediction Engine
Applies saved Preprocessor, runs genuine scikit-learn Isolation Forest inference,
evaluates against calibrated validation threshold, and computes feature-level deviations.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional
import joblib
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.preprocess import Preprocessor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ThreatLens.Predict")


class ThreatPredictor:
    def __init__(self, model_dir="models"):
        self.model_dir = model_dir
        self.metadata = {}
        self.preprocessor: Optional[Preprocessor] = None
        self.iso_model = None
        self.rf_model = None
        self.calibrated_threshold = 0.50
        self.load_artifacts()

    def load_artifacts(self):
        """Loads serialized model estimators, preprocessor, and calibration metadata."""
        metadata_path = os.path.join(self.model_dir, "metadata.json")
        prep_path = os.path.join(self.model_dir, "preprocessor.json")
        iso_path = os.path.join(self.model_dir, "isolation_forest.joblib")
        rf_path = os.path.join(self.model_dir, "random_forest.joblib")

        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                self.calibrated_threshold = float(
                    self.metadata.get("isolation_forest", {}).get("calibrated_threshold", 0.50)
                )
            except Exception as e:
                logger.warning("Could not parse metadata.json: %s", e)

        if os.path.exists(prep_path):
            try:
                self.preprocessor = Preprocessor.load(prep_path)
            except Exception as e:
                logger.error("Failed to load preprocessor artifact: %s", e)
                self.preprocessor = None

        if os.path.exists(iso_path):
            try:
                self.iso_model = joblib.load(iso_path)
                logger.info("Loaded Isolation Forest estimator from %s", iso_path)
            except Exception as e:
                logger.error("Failed to load Isolation Forest artifact: %s", e)
                self.iso_model = None

        if os.path.exists(rf_path):
            try:
                self.rf_model = joblib.load(rf_path)
            except Exception as e:
                logger.debug("Optional Random Forest baseline not loaded: %s", e)
                self.rf_model = None

    def is_ready(self) -> bool:
        """Returns True only when both the preprocessor and the Isolation Forest model are loaded."""
        return (
            self.preprocessor is not None
            and getattr(self.preprocessor, "is_fitted", False)
            and self.iso_model is not None
        )

    def predict_flow(self, flow_dict: Dict[str, Any], threshold_override: Optional[float] = None) -> Dict[str, Any]:
        """
        Executes genuine Isolation Forest inference on raw network flow record.
        - Transforms flow features with trained RobustScaler parameters.
        - Evaluates sample path length using fitted scikit-learn IsolationForest.
        - Compares score against calibrated threshold.
        - Computes feature explanations grounded in robust standard deviation.
        """
        if not self.is_ready():
            raise RuntimeError(
                f"ThreatLens model artifacts are not loaded from '{self.model_dir}'. Run ml/train.py first."
            )

        threshold = threshold_override if threshold_override is not None else self.calibrated_threshold

        # Transform single record using saved training parameters
        transformed_rows = self.preprocessor.transform([flow_dict])
        x_norm = np.array(transformed_rows, dtype=float)

        # Genuine scikit-learn IsolationForest scoring
        # In scikit-learn: score_samples returns -2^(-E(h)/c(n)).
        # Therefore, -score_samples(X) directly gives Liu et al. anomaly score in (0, 1).
        # Higher score = shorter average path length = higher anomaly risk.
        raw_score = float(-self.iso_model.score_samples(x_norm)[0])
        decision_val = float(self.iso_model.decision_function(x_norm)[0])

        is_anomaly = bool(raw_score >= threshold)

        # Feature explanation: measure robust z-score deviation from learned benign median
        feature_contributions = []
        vec = x_norm[0]
        for idx, feat_name in enumerate(self.preprocessor.selected_features):
            dev = abs(float(vec[idx]))
            raw_val = flow_dict.get(feat_name, flow_dict.get(feat_name.strip()))
            feature_contributions.append({
                "feature": feat_name,
                "raw_value": raw_val,
                "deviation_score": round(dev, 3),
                "is_outlier": dev > 3.0
            })

        feature_contributions.sort(key=lambda item: item["deviation_score"], reverse=True)

        # Risk classification grounded in score distance from threshold
        if raw_score >= 0.80:
            risk_level = "Critical"
        elif raw_score >= threshold:
            risk_level = "High"
        elif raw_score >= (threshold - 0.08):
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Objective anomaly verdict (no confirmed attack claims without analyst review)
        if is_anomaly:
            prediction_label = "Anomalous Traffic (Statistical Outlier — Investigate)"
        else:
            prediction_label = "Normal (Benign Baseline)"

        return {
            "prediction": prediction_label,
            "is_anomaly": is_anomaly,
            "anomaly_score": round(raw_score, 4),
            "decision_function": round(decision_val, 4),
            "calibrated_threshold": round(threshold, 4),
            "risk_level": risk_level,
            "top_contributing_features": feature_contributions[:5],
            "analyzed_feature_count": len(self.preprocessor.selected_features),
            "model_architecture": "Isolation Forest (scikit-learn)"
        }


if __name__ == "__main__":
    predictor = ThreatPredictor()
    test_flow = {
        "Destination Port": 80,
        "Flow Duration": 12000000,
        "Total Fwd Packets": 20,
        "Total Backward Packets": 1,
        "Total Length of Fwd Packets": 400,
        "Total Length of Bwd Packets": 0,
        "Flow Bytes/s": 33.3,
        "Flow Packets/s": 1.75
    }
    print("Ready:", predictor.is_ready())
    if predictor.is_ready():
        res = predictor.predict_flow(test_flow)
        print(json.dumps(res, indent=2))
