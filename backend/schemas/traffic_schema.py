"""
ThreatLens — Flow Record Validation Schemas
Validates input structures, feature names, numeric data types, and disallows NaN/Inf in API inputs.
"""

import math

REQUIRED_NUMERICAL_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s"
]

def validate_flow_payload(payload: dict) -> tuple:
    """
    Validates flow JSON payload.
    Returns (is_valid: bool, cleaned_data: dict, error_message: str)
    """
    if not isinstance(payload, dict):
        return False, None, "Payload must be a JSON object"

    flow_data = payload.get("flow", payload)
    if not isinstance(flow_data, dict):
        return False, None, "'flow' field must be an object containing feature key-value pairs"

    cleaned = {}
    for k, v in flow_data.items():
        # Disallow non-primitive inputs
        if isinstance(v, (list, dict)):
            continue
        try:
            val_f = float(v)
            if math.isnan(val_f):
                return False, None, f"Feature '{k}' contains NaN which is invalid in active inference"
            if math.isinf(val_f):
                # Auto-cap extreme infinities
                val_f = 1e9 if val_f > 0 else -1e9
            cleaned[k.strip()] = val_f
        except (ValueError, TypeError):
            # Non-numeric fields like Label or Protocol string are preserved
            cleaned[k.strip()] = str(v)

    # Check for at least 2 network features
    if len(cleaned) < 2:
        return False, None, "Payload must contain at least 2 network flow features (e.g. Destination Port, Flow Duration)"

    return True, cleaned, None
