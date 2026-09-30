"""Small, explainable, defensive IDS engine for synthetic flow records.

No function in this module opens a socket, sends a packet, scans a host, or
contacts an address. Its inputs and outputs are ordinary Python dictionaries.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import math
from statistics import fmean, pstdev
from typing import Any
from uuid import uuid4

DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}
COMMON_SERVICE_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995,
    1433, 3306, 5432, 6379, 8080, 8443,
}
FEATURE_NAMES = (
    "bytes_per_second",
    "packets_per_second",
    "connection_rate",
    "failure_ratio",
    "syn_ratio",
    "unique_destination_ports",
    "unique_destination_ips",
)

DEFAULT_RULES: tuple[dict[str, Any], ...] = (
    {"rule_id": "IDS-001", "name": "High connection rate", "severity": "HIGH", "threshold": 10.0},
    {"rule_id": "IDS-002", "name": "Repeated failed connections", "severity": "HIGH", "threshold": 0.45},
    {"rule_id": "IDS-003", "name": "Destination-port diversity", "severity": "MEDIUM", "threshold": 8},
    {"rule_id": "IDS-004", "name": "SYN-heavy pattern", "severity": "HIGH", "threshold": 0.8},
    {"rule_id": "IDS-005", "name": "Unusual service port", "severity": "MEDIUM", "threshold": 1},
    {"rule_id": "IDS-006", "name": "High traffic volume", "severity": "HIGH", "threshold": 1_500_000},
    {"rule_id": "IDS-007", "name": "Statistical baseline deviation", "severity": "MEDIUM", "threshold": 58},
)

DEFAULT_BASELINE: dict[str, tuple[float, float]] = {
    "bytes_per_second": (7_000.0, 18_000.0),
    "packets_per_second": (7.0, 11.0),
    "connection_rate": (1.2, 2.0),
    "failure_ratio": (0.03, 0.12),
    "syn_ratio": (0.16, 0.2),
    "unique_destination_ports": (1.1, 0.5),
    "unique_destination_ips": (1.05, 0.3),
}

REQUIRED_FLOW_FIELDS = (
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "unique_destination_ports",
    "unique_destination_ips",
    "label",
    "scenario_type",
)


def validate_flow(flow: dict[str, Any], *, require_documentation_ips: bool = True) -> None:
    """Reject malformed records rather than silently treating them as safe."""
    missing = [field for field in REQUIRED_FLOW_FIELDS if field not in flow]
    if missing:
        raise ValueError(f"Missing required flow fields: {', '.join(missing)}")

    for field in ("source_ip", "destination_ip"):
        try:
            address = ipaddress.ip_address(str(flow[field]))
        except ValueError as error:
            raise ValueError(f"{field} is not a valid IP address") from error
        if require_documentation_ips and not any(address in network for network in DOCUMENTATION_NETWORKS):
            raise ValueError(f"{field} must use a reserved documentation IP in this simulation")

    for field in ("source_port", "destination_port"):
        value = flow[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError(f"{field} must be an integer from 1 to 65535")
    if flow["protocol"] not in VALID_PROTOCOLS:
        raise ValueError("protocol must be TCP, UDP, or ICMP")

    for field in (
        "packet_count",
        "byte_count",
        "connection_count",
        "failed_connection_count",
        "syn_count",
        "rst_count",
        "unique_destination_ports",
        "unique_destination_ips",
    ):
        value = flow[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
    try:
        duration = float(flow["duration_seconds"])
    except (TypeError, ValueError) as error:
        raise ValueError("duration_seconds must be numeric") from error
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("duration_seconds must be a finite non-negative number")
    if flow["label"] not in {"NORMAL", "SUSPICIOUS"}:
        raise ValueError("label must be NORMAL or SUSPICIOUS")


def extract_network_features(flow: dict[str, Any]) -> dict[str, float]:
    """Compute rates and ratios, guarding zero duration and missing counters."""
    duration = max(0.001, float(flow.get("duration_seconds") or 0))
    packets = max(0, int(flow.get("packet_count") or 0))
    byte_count = max(0, int(flow.get("byte_count") or 0))
    connections = max(0, int(flow.get("connection_count") or 0))
    failed = max(0, int(flow.get("failed_connection_count") or 0))
    syns = max(0, int(flow.get("syn_count") or 0))
    return {
        "packet_count": float(packets),
        "byte_count": float(byte_count),
        "duration_seconds": duration,
        "bytes_per_second": byte_count / duration,
        "packets_per_second": packets / duration,
        "average_packet_size": byte_count / max(1, packets),
        "connection_count": float(connections),
        "failed_connection_count": float(failed),
        "failure_ratio": min(1.0, failed / connections) if connections else 0.0,
        "syn_count": float(syns),
        "rst_count": float(max(0, int(flow.get("rst_count") or 0))),
        "syn_ratio": min(1.0, syns / packets) if packets else 0.0,
        "unique_destination_ports": float(max(1, int(flow.get("unique_destination_ports") or 1))),
        "unique_destination_ips": float(max(1, int(flow.get("unique_destination_ips") or 1))),
        "connection_rate": connections / duration,
    }


def calculate_baseline(normal_flows: list[dict[str, Any]]) -> dict[str, tuple[float, float]]:
    """Build population mean/deviation values from NORMAL-labelled records."""
    normal = [flow for flow in normal_flows if flow.get("label") == "NORMAL"]
    if len(normal) < 8:
        return dict(DEFAULT_BASELINE)
    feature_rows = [extract_network_features(flow) for flow in normal]
    baseline: dict[str, tuple[float, float]] = {}
    for name in FEATURE_NAMES:
        values = [row[name] for row in feature_rows]
        default_deviation = DEFAULT_BASELINE[name][1]
        baseline[name] = (fmean(values), max(pstdev(values), default_deviation * 0.15))
    return baseline


def calculate_anomaly_score(
    features: dict[str, float],
    baseline: dict[str, tuple[float, float]] | None = None,
) -> int:
    """Return a bounded 0-100 score from positive z-score deviations."""
    baseline = baseline or DEFAULT_BASELINE
    z_scores = []
    for name in FEATURE_NAMES:
        mean, deviation = baseline[name]
        z_scores.append(max(0.0, (features.get(name, 0.0) - mean) / max(deviation, 0.001)))
    if not z_scores:
        return 0
    score = round(max(z_scores) * 16 + fmean(z_scores) * 12)
    return max(0, min(100, score))


def _matching_rules(
    flow: dict[str, Any],
    features: dict[str, float],
    anomaly_score: int,
    rules: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    matches = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        rule_id = rule["rule_id"]
        threshold = float(rule["threshold"])
        matched = {
            "IDS-001": features["connection_rate"] >= threshold,
            "IDS-002": flow["failed_connection_count"] >= 5 and features["failure_ratio"] >= threshold,
            "IDS-003": features["unique_destination_ports"] >= threshold,
            "IDS-004": flow["syn_count"] >= 12 and features["syn_ratio"] >= threshold,
            "IDS-005": int(flow["destination_port"]) not in COMMON_SERVICE_PORTS,
            "IDS-006": flow["byte_count"] >= threshold,
            "IDS-007": anomaly_score >= threshold,
        }.get(rule_id, False)
        if matched:
            matches.append(rule)
    return matches


def calculate_risk_score(
    matches: list[dict[str, Any]],
    anomaly_score: int,
) -> int:
    """Combine signature severity (70%) and anomaly score (30%)."""
    severity_weight = {"INFO": 12, "LOW": 30, "MEDIUM": 48, "HIGH": 72, "CRITICAL": 92}
    rule_score = (
        min(100, max(severity_weight.get(rule.get("severity", "MEDIUM"), 48) for rule in matches) + (len(matches) - 1) * 6)
        if matches
        else 0
    )
    return max(0, min(100, round(rule_score * 0.7 + anomaly_score * 0.3)))


def analyze_flow(
    flow: dict[str, Any],
    rules: tuple[dict[str, Any], ...] | list[dict[str, Any]] = DEFAULT_RULES,
    baseline: dict[str, tuple[float, float]] | None = None,
) -> dict[str, Any]:
    """Validate one record and return explainable detection results."""
    validate_flow(flow)
    features = extract_network_features(flow)
    anomaly_score = calculate_anomaly_score(features, baseline)
    matches = _matching_rules(flow, features, anomaly_score, rules)
    risk_score = calculate_risk_score(matches, anomaly_score)
    classification = (
        "POTENTIAL_INTRUSION" if risk_score >= 61 else "SUSPICIOUS" if risk_score >= 21 else "NORMAL"
    )
    return {
        **flow,
        "features": features,
        "rules_matched": [rule["rule_id"] for rule in matches],
        "anomaly_score": anomaly_score,
        "risk_score": risk_score,
        "classification": classification,
        "severity": severity_for_risk(risk_score),
    }


def severity_for_risk(risk_score: int) -> str:
    if risk_score >= 81:
        return "CRITICAL"
    if risk_score >= 61:
        return "HIGH"
    if risk_score >= 41:
        return "MEDIUM"
    if risk_score >= 21:
        return "LOW"
    return "INFO"


def generate_alert(analysis: dict[str, Any], rule_id: str) -> dict[str, Any]:
    """Format a triage alert from an analyzed synthetic flow."""
    matching_rule = next(
        (rule for rule in DEFAULT_RULES if rule["rule_id"] == rule_id),
        {"name": "Statistical baseline deviation"},
    )
    return {
        "alert_id": f"ALT-{uuid4().hex[:12].upper()}",
        "timestamp": analysis["timestamp"],
        "flow_id": analysis.get("flow_id", ""),
        "source_ip": analysis["source_ip"],
        "destination_ip": analysis["destination_ip"],
        "protocol": analysis["protocol"],
        "source_port": analysis["source_port"],
        "destination_port": analysis["destination_port"],
        "rule_id": rule_id,
        "alert_type": matching_rule["name"],
        "severity": analysis["severity"],
        "risk_score": analysis["risk_score"],
        "anomaly_score": analysis["anomaly_score"],
        "description": "Synthetic flow matched a configured detection; investigate before drawing conclusions.",
        "status": "NEW",
    }


def correlate_alerts(alerts: list[dict[str, Any]], window_seconds: int = 60) -> list[dict[str, Any]]:
    """Group repeated same-source, same-rule alerts within a rolling time window."""
    ordered = sorted(alerts, key=lambda alert: _as_datetime(alert["timestamp"]))
    groups: list[dict[str, Any]] = []
    for alert in ordered:
        moment = _as_datetime(alert["timestamp"])
        match = next(
            (
                group
                for group in reversed(groups)
                if group["source_ip"] == alert["source_ip"]
                and group["rule_id"] == alert["rule_id"]
                and (moment - group["last_seen"]).total_seconds() <= window_seconds
            ),
            None,
        )
        if match:
            match["count"] += 1
            match["last_seen"] = moment
            match["alert_ids"].append(alert["alert_id"])
        else:
            groups.append(
                {
                    "source_ip": alert["source_ip"],
                    "rule_id": alert["rule_id"],
                    "count": 1,
                    "first_seen": moment,
                    "last_seen": moment,
                    "alert_ids": [alert["alert_id"]],
                }
            )
    return [group for group in groups if group["count"] > 1]


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)