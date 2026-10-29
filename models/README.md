# ThreatLens Models Directory

This directory stores trained model artifacts, feature configurations, and experiment metadata.

## Artifacts

- `preprocessor.json`: Fitted RobustScaler centers (medians) and scales (IQRs) derived strictly from training data partition to prevent test set data leakage.
- `metadata.json`: Model versioning, hyperparameter definitions, decision threshold calibration results, training duration, and top feature contribution weights.

## Reproducibility Note

The random seed is fixed at `42` across all training and thresholding splits.
When retraining on full CIC-IDS2017 or UNSW-NB15 files:
```bash
python3 ml/train.py
```
To evaluate against held-out zero-day simulation:
```bash
python3 ml/evaluate.py
```
