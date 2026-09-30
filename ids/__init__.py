"""Defensive network IDS simulation primitives; all examples are data-only."""

from .network_ids import (
    DEFAULT_RULES,
    analyze_flow,
    calculate_anomaly_score,
    calculate_risk_score,
    correlate_alerts,
    extract_network_features,
    generate_alert,
    validate_flow,
)

__all__ = [
    "DEFAULT_RULES",
    "analyze_flow",
    "calculate_anomaly_score",
    "calculate_risk_score",
    "correlate_alerts",
    "extract_network_features",
    "generate_alert",
    "validate_flow",
]