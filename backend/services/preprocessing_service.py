"""
ThreatLens — Preprocessing & Traffic Data Service
Provides access to inspected flow datasets, alert generation, and dataset statistics.
"""

import os
import sys
import csv
import json
import logging
from datetime import datetime

logger = logging.getLogger("ThreatLens.PreprocessingService")

class PreprocessingService:
    def __init__(self):
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.data_dir = os.path.join(self.base_dir, "data")
        self.reports_dir = os.path.join(self.base_dir, "reports")

    def get_traffic_flows(self, limit: int = 50, offset: int = 0, filter_type: str = "all") -> dict:
        """Loads sample traffic flows from CSV, formatted for frontend table display."""
        sample_path = os.path.join(self.data_dir, "cicids2017_sample.csv")
        heldout_path = os.path.join(self.data_dir, "cicids2017_heldout_sample.csv")

        all_records = []

        for p in [sample_path, heldout_path]:
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for idx, row in enumerate(reader):
                        lbl = row.get("Label", "UNKNOWN")
                        is_normal = lbl.strip().upper() == "BENIGN"
                        all_records.append({
                            "id": f"FLOW-{len(all_records)+1:04d}",
                            "timestamp": f"2026-10-28T08:{(len(all_records)%60):02d}:15Z",
                            "dest_port": int(row.get("Destination Port", 80)),
                            "duration_us": float(row.get("Flow Duration", 0)),
                            "total_fwd_pkts": int(row.get("Total Fwd Packets", 0)),
                            "total_bwd_pkts": int(row.get("Total Backward Packets", 0)),
                            "flow_bytes_per_sec": float(row.get("Flow Bytes/s", 0)),
                            "flow_pkts_per_sec": float(row.get("Flow Packets/s", 0)),
                            "actual_label": lbl,
                            "is_normal": is_normal,
                            "features": row
                        })

        # Apply filtering
        if filter_type == "normal":
            filtered = [r for r in all_records if r["is_normal"]]
        elif filter_type == "anomaly":
            filtered = [r for r in all_records if not r["is_normal"]]
        else:
            filtered = all_records

        paginated = filtered[offset : offset + limit]
        return {
            "total": len(filtered),
            "offset": offset,
            "limit": limit,
            "records": paginated
        }

    def get_dataset_inspection(self) -> dict:
        inspect_path = os.path.join(self.reports_dir, "dataset_inspection_report.json")
        if not os.path.exists(inspect_path):
            return {"status": "error", "message": "Dataset inspection report not generated yet."}
        with open(inspect_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_preprocessing_report(self) -> dict:
        prep_path = os.path.join(self.reports_dir, "preprocessing_report.json")
        if not os.path.exists(prep_path):
            return {"status": "error", "message": "Preprocessing report not found."}
        with open(prep_path, "r", encoding="utf-8") as f:
            return json.load(f)
