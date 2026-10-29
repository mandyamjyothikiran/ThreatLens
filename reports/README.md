# ThreatLens Academic Experiment Reports

This directory houses verifiable experimental results generated directly by the ThreatLens ML pipeline.

## Generated Reports

1. `dataset_inspection_report.json`:
   - Raw feature count, verified column schemas, and class distributions.
   - Missing and infinite value analysis.

2. `preprocessing_report.json`:
   - Feature leakage prevention (stripping IP addresses, timestamps, Flow IDs).
   - Median imputation and RobustScaler specifications.
   - Train/Val/Test partitioning protocol.

3. `model_evaluation_report.json`:
   - Accuracy, Precision, Recall, F1-Score, False Positive Rate (FPR), True Positive Rate (TPR), Specificity, ROC-AUC.
   - 2x2 Confusion matrices for Isolation Forest and Random Forest baseline.
   - ROC Curve and Precision-Recall curve coordinate points.

4. `unseen_attack_report.json`:
   - Held-Out Attack Category (Zero-Day Simulation) results.
   - Breakdown of excluded attack types: PortScan, Infiltration, Botnet.
   - Quantitative recall comparison between unsupervised Isolation Forest vs supervised Random Forest.
   - Critical academic disclaimer and limitation analysis.

5. `adaptive_threshold_report.json`:
   - Trade-off analysis between fixed threshold (0.500) vs validation-calibrated 95th percentile threshold.
