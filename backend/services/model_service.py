"""
ThreatLens — Model Service
Manages lazy-loading of trained artifacts, model predictions, and caching of evaluation metrics.
"""

import os
import sys
import json
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from ml.predict import ThreatPredictor

logger = logging.getLogger("ThreatLens.ModelService")

class ModelService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelService, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "initialized", False):
            return
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.models_dir = os.path.join(self.base_dir, "models")
        self.reports_dir = os.path.join(self.base_dir, "reports")
        self.predictor = ThreatPredictor(model_dir=self.models_dir)
        self.initialized = True
        logger.info("ModelService initialized. Model ready: %s", self.predictor.is_ready())

    def get_model_info(self) -> dict:
        is_ready = self.predictor.is_ready()
        metadata = self.predictor.metadata if is_ready else {}
        return {
            "status": "ready" if is_ready else "not_trained",
            "model_architecture": "Isolation Forest (Semi-Supervised Outlier Detection)",
            "calibrated_threshold": self.predictor.calibrated_threshold,
            "feature_count": len(self.predictor.preprocessor.selected_features) if is_ready else 0,
            "selected_features": self.predictor.preprocessor.selected_features if is_ready else [],
            "metadata": metadata
        }

    def predict(self, flow: dict, threshold_override: float = None) -> dict:
        if not self.predictor.is_ready():
            raise RuntimeError("No model is currently loaded. Please run ml/train.py first.")
        return self.predictor.predict_flow(flow, threshold_override=threshold_override)

    def get_metrics(self) -> dict:
        eval_path = os.path.join(self.reports_dir, "model_evaluation_report.json")
        if not os.path.exists(eval_path):
            return {"status": "no_results", "message": "No evaluation results available yet. Run ml/evaluate.py to compute."}
        with open(eval_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_unseen_attack_metrics(self) -> dict:
        unseen_path = os.path.join(self.reports_dir, "unseen_attack_report.json")
        if not os.path.exists(unseen_path):
            return {"status": "no_results", "message": "No held-out experiment results available yet."}
        with open(unseen_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_adaptive_threshold_metrics(self) -> dict:
        adap_path = os.path.join(self.reports_dir, "adaptive_threshold_report.json")
        if not os.path.exists(adap_path):
            return {"status": "no_results", "message": "No threshold comparison report found."}
        with open(adap_path, "r", encoding="utf-8") as f:
            return json.load(f)
