"""
ThreatLens — Adaptive Anomaly Threshold Calibration Module
Implements both fixed thresholding and validation-calibrated percentile thresholding.
Crucial rule: Thresholds are NEVER calibrated using test-set data.
"""

import math
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ThreatLens.Thresholding")

def calibrate_threshold(val_scores: list, percentile: float = 95.0) -> float:
    """
    Computes an empirical threshold based on validation normal traffic scores.
    For Isolation Forest, lower raw score means more anomalous.
    Standardized score in ThreatLens: 0 (most normal) to 1.0 (most anomalous).
    Or for raw decision_function: negative is anomaly.
    
    Here we assume input scores where HIGHER values mean HIGHER anomaly risk.
    A threshold at the 95th percentile will flag top 5% of benign as potential anomalies (FPR ~ 5%).
    """
    if not val_scores:
        logger.warning("Empty validation scores supplied. Falling back to default threshold 0.5.")
        return 0.50

    sorted_scores = sorted(val_scores)
    k = (len(sorted_scores) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        threshold = sorted_scores[int(k)]
    else:
        d0 = sorted_scores[int(f)] * (c - k)
        d1 = sorted_scores[int(c)] * (k - f)
        threshold = d0 + d1

    logger.info("Calibrated threshold at %.1fth percentile: %.4f (from %d validation samples)",
                percentile, threshold, len(val_scores))
    return float(threshold)

def compare_threshold_strategies(val_scores: list, val_labels: list, fixed_th: float = 0.50, percentiles: list = [90.0, 95.0, 98.0]):
    """
    Compares fixed threshold against validation-calibrated percentiles.
    Returns comparison dictionary.
    """
    results = []

    # Fixed threshold evaluation
    fp = sum(1 for s, y in zip(val_scores, val_labels) if s >= fixed_th and y == 0)
    tp = sum(1 for s, y in zip(val_scores, val_labels) if s >= fixed_th and y == 1)
    tn = sum(1 for s, y in zip(val_scores, val_labels) if s < fixed_th and y == 0)
    fn = sum(1 for s, y in zip(val_scores, val_labels) if s < fixed_th and y == 1)

    fpr_fixed = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    recall_fixed = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    prec_fixed = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1_fixed = (2 * prec_fixed * recall_fixed / (prec_fixed + recall_fixed)) if (prec_fixed + recall_fixed) > 0 else 0.0

    results.append({
        "strategy": "Fixed Threshold",
        "threshold": fixed_th,
        "validation_fpr": round(fpr_fixed, 4),
        "validation_recall": round(recall_fixed, 4),
        "validation_precision": round(prec_fixed, 4),
        "validation_f1": round(f1_fixed, 4)
    })

    # Calibrate on normal validation scores (y == 0)
    normal_val_scores = [s for s, y in zip(val_scores, val_labels) if y == 0]
    for p in percentiles:
        calib_th = calibrate_threshold(normal_val_scores, percentile=p)
        fp_c = sum(1 for s, y in zip(val_scores, val_labels) if s >= calib_th and y == 0)
        tp_c = sum(1 for s, y in zip(val_scores, val_labels) if s >= calib_th and y == 1)
        tn_c = sum(1 for s, y in zip(val_scores, val_labels) if s < calib_th and y == 0)
        fn_c = sum(1 for s, y in zip(val_scores, val_labels) if s < calib_th and y == 1)

        fpr_c = fp_c / (fp_c + tn_c) if (fp_c + tn_c) > 0 else 0.0
        rec_c = tp_c / (tp_c + fn_c) if (tp_c + fn_c) > 0 else 0.0
        prec_c = tp_c / (tp_c + fp_c) if (tp_c + fp_c) > 0 else 0.0
        f1_c = (2 * prec_c * rec_c / (prec_c + rec_c)) if (prec_c + rec_c) > 0 else 0.0

        results.append({
            "strategy": f"Adaptive ({p}th %ile of Normal)",
            "threshold": round(calib_th, 4),
            "validation_fpr": round(fpr_c, 4),
            "validation_recall": round(rec_c, 4),
            "validation_precision": round(prec_c, 4),
            "validation_f1": round(f1_c, 4)
        })

    return results
