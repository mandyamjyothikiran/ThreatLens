"""
ThreatLens — Data Preprocessing and Leakage Prevention Module
Handles cleaning, feature selection, normalization, and strict dataset splitting.
Fit-on-train only guarantees zero test leakage.
"""

import os
import csv
import json
import math
import random
import logging
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ThreatLens.Preprocess")

# Irrelevant identifier features prone to data leakage
LEAKAGE_FEATURES = {
    "flow id", "source ip", "src ip", "destination ip", "dst ip",
    "timestamp", "simillarhttp", "source port"
}

def clean_value(val_str: Any) -> float:
    """Parses numeric string or number, handling inf, -inf, and nan safely."""
    if val_str is None:
        return float("nan")
    if isinstance(val_str, (int, float)):
        if math.isnan(val_str):
            return float("nan")
        if math.isinf(val_str):
            return 1e12 if val_str > 0 else -1e12
        return float(val_str)
    s = str(val_str).strip().lower()
    if s in ("", "nan", "null", "none"):
        return float("nan")
    if s in ("inf", "+inf", "infinity", "+infinity"):
        return 1e12
    if s in ("-inf", "-infinity"):
        return -1e12
    try:
        return float(s)
    except ValueError:
        return float("nan")

class Preprocessor:
    def __init__(self, target_label_col: str = "Label", normal_label: str = "BENIGN"):
        self.target_label_col = target_label_col
        self.normal_label = normal_label
        self.selected_features = []
        self.medians = {}
        self.scales = {}  # IQR or std deviation
        self.centers = {} # Median or mean
        self.is_fitted = False

    def fit_and_transform(self, rows: list, column_names: list):
        """
        Fits centers and scales ONLY on training data rows, then transforms them.
        """
        # Determine features to keep (exclude leakage columns and label)
        self.selected_features = [
            c for c in column_names
            if c.strip().lower() != self.target_label_col.lower()
            and c.strip().lower() not in LEAKAGE_FEATURES
        ]

        logger.info("Fitting preprocessor on %d train rows over %d features", len(rows), len(self.selected_features))

        # Collect values per feature
        feature_values = {f: [] for f in self.selected_features}
        for row in rows:
            for feat in self.selected_features:
                val = clean_value(row.get(feat, ""))
                if not math.isnan(val) and not math.isinf(val):
                    feature_values[feat].append(val)

        # Compute median & IQR (RobustScaler approach)
        for feat in self.selected_features:
            vals = sorted(feature_values[feat])
            if vals:
                n = len(vals)
                med = vals[n // 2]
                q1 = vals[n // 4]
                q3 = vals[(3 * n) // 4]
                iqr = q3 - q1 if (q3 - q1) > 1e-6 else 1.0
                self.centers[feat] = med
                self.scales[feat] = iqr
                self.medians[feat] = med
            else:
                self.centers[feat] = 0.0
                self.scales[feat] = 1.0
                self.medians[feat] = 0.0

        self.is_fitted = True
        return self.transform(rows)

    def transform(self, rows: list) -> list:
        """Transforms rows into normalized numerical feature vectors."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transform() is called.")

        transformed = []
        for row in rows:
            vec = []
            for feat in self.selected_features:
                raw = clean_value(str(row.get(feat, "")))
                if math.isnan(raw):
                    raw = self.medians.get(feat, 0.0)
                # Robust scaling: (x - median) / IQR
                center = self.centers.get(feat, 0.0)
                scale = self.scales.get(feat, 1.0)
                norm_val = (raw - center) / scale
                # Clip extreme outliers to prevent gradient / numerical instability
                norm_val = max(-100.0, min(100.0, norm_val))
                vec.append(norm_val)
            transformed.append(vec)
        return transformed

    def save(self, filepath: str):
        """Saves preprocessing parameters to a JSON artifact."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        data = {
            "target_label_col": self.target_label_col,
            "normal_label": self.normal_label,
            "selected_features": self.selected_features,
            "centers": self.centers,
            "scales": self.scales,
            "medians": self.medians,
            "is_fitted": self.is_fitted
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Preprocessor saved to: %s", filepath)

    @classmethod
    def load(cls, filepath: str):
        """Loads preprocessing parameters from a JSON artifact."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Preprocessor artifact not found at {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        p = cls(data.get("target_label_col", "Label"), data.get("normal_label", "BENIGN"))
        p.selected_features = data.get("selected_features", [])
        p.centers = data.get("centers", {})
        p.scales = data.get("scales", {})
        p.medians = data.get("medians", {})
        p.is_fitted = data.get("is_fitted", False)
        return p

def load_and_split_dataset(csv_path: str, seed: int = 42, train_ratio: float = 0.6, val_ratio: float = 0.2):
    """
    Loads dataset, parses rows, removes exact duplicates, and splits into train/val/test partitions.
    """
    random.seed(seed)
    with open(csv_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = [row for row in reader]

    total_loaded = len(rows)
    # Deduplication
    seen = set()
    deduped = []
    for r in rows:
        key = tuple(r.items())
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    logger.info("Loaded %d rows; %d unique after duplicate removal.", total_loaded, len(deduped))

    random.shuffle(deduped)
    n = len(deduped)
    train_end = int(n * train_ratio)
    val_end = train_end + int(n * val_ratio)

    train_data = deduped[:train_end]
    val_data = deduped[train_end:val_end]
    test_data = deduped[val_end:]

    return train_data, val_data, test_data, list(rows[0].keys()) if rows else []
