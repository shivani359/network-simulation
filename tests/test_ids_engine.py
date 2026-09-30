from __future__ import annotations

import copy
import csv
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from ids.network_ids import (
    DEFAULT_BASELINE,
    analyze_flow,
    calculate_anomaly_score,
    calculate_baseline,
    calculate_risk_score,
    correlate_alerts,
    extract_network_features,
    generate_alert,
    validate_flow,
)
from simulator.generate_dataset import FIELDNAMES, generate_dataset, write_dataset


def make_flow(**overrides):
    flow = {
        "flow_id": "flow-test-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "192.0.2.15",
        "destination_ip": "198.51.100.20",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 50,
        "byte_count": 25_000,
        "duration_seconds": 10.0,
        "connection_count": 6,
        "failed_connection_count": 0,
        "syn_count": 6,
        "rst_count": 0,
        "unique_destination_ports": 1,
        "unique_destination_ips": 1,
        "label": "NORMAL",
        "scenario_type": "NORMAL_WEB",
    }
    flow.update(overrides)
    return flow


class FlowValidationTests(unittest.TestCase):
    def test_01_accepts_normal_tcp_flow(self):
        validate_flow(make_flow())

    def test_02_accepts_normal_udp_dns_flow(self):
        validate_flow(make_flow(protocol="UDP", destination_port=53, scenario_type="NORMAL_DNS"))

    def test_03_rejects_malformed_source_ip(self):
        with self.assertRaisesRegex(ValueError, "source_ip"):
            validate_flow(make_flow(source_ip="not-an-ip"))

    def test_04_rejects_malformed_destination_ip(self):
        with self.assertRaisesRegex(ValueError, "destination_ip"):
            validate_flow(make_flow(destination_ip="300.1.1.1"))

    def test_05_rejects_non_documentation_network(self):
        with self.assertRaisesRegex(ValueError, "reserved documentation"):
            validate_flow(make_flow(source_ip="8.8.8.8"))

    def test_06_rejects_source_port_zero(self):
        with self.assertRaisesRegex(ValueError, "source_port"):
            validate_flow(make_flow(source_port=0))

    def test_07_rejects_destination_port_above_range(self):
        with self.assertRaisesRegex(ValueError, "destination_port"):
            validate_flow(make_flow(destination_port=65536))

    def test_08_rejects_unsupported_protocol(self):
        with self.assertRaisesRegex(ValueError, "protocol"):
            validate_flow(make_flow(protocol="HTTP"))

    def test_09_rejects_missing_packet_count(self):
        flow = make_flow()
        del flow["packet_count"]
        with self.assertRaisesRegex(ValueError, "packet_count"):
            validate_flow(flow)

    def test_10_rejects_negative_packet_count(self):
        with self.assertRaisesRegex(ValueError, "packet_count"):
            validate_flow(make_flow(packet_count=-1))

    def test_11_rejects_negative_duration(self):
        with self.assertRaisesRegex(ValueError, "duration_seconds"):
            validate_flow(make_flow(duration_seconds=-1))

    def test_12_zero_duration_is_guarded_in_feature_extraction(self):
        features = extract_network_features(make_flow(duration_seconds=0))
        self.assertTrue(features["bytes_per_second"] < float("inf"))
        self.assertAlmostEqual(features["bytes_per_second"], 25_000_000)


class FeatureAndDetectionTests(unittest.TestCase):
    def test_13_calculates_byte_rate(self):
        self.assertEqual(extract_network_features(make_flow())["bytes_per_second"], 2_500)

    def test_14_calculates_packet_rate(self):
        self.assertEqual(extract_network_features(make_flow())["packets_per_second"], 5)

    def test_15_calculates_failed_connection_ratio(self):
        features = extract_network_features(make_flow(connection_count=10, failed_connection_count=5))
        self.assertEqual(features["failure_ratio"], 0.5)

    def test_16_zero_connections_have_zero_failure_ratio(self):
        self.assertEqual(
            extract_network_features(make_flow(connection_count=0, failed_connection_count=0))["failure_ratio"],
            0,
        )

    def test_17_calculates_syn_ratio(self):
        self.assertAlmostEqual(extract_network_features(make_flow(syn_count=25))["syn_ratio"], 0.5)

    def test_18_zero_packets_have_zero_syn_ratio(self):
        self.assertEqual(extract_network_features(make_flow(packet_count=0, syn_count=0))["syn_ratio"], 0)

    def test_19_zero_packet_average_size_does_not_divide_by_zero(self):
        self.assertEqual(extract_network_features(make_flow(packet_count=0))["average_packet_size"], 25_000)

    def test_20_empty_baseline_uses_documented_defaults(self):
        self.assertEqual(calculate_baseline([]), DEFAULT_BASELINE)

    def test_21_baseline_uses_normal_examples_only(self):
        normals = [make_flow(flow_id=f"normal-{i}") for i in range(9)]
        baseline = calculate_baseline(normals + [make_flow(label="SUSPICIOUS", byte_count=90_000_000)])
        self.assertLess(baseline["bytes_per_second"][0], 3_000)

    def test_22_normal_web_flow_is_not_flagged(self):
        analysis = analyze_flow(make_flow())
        self.assertEqual(analysis["classification"], "NORMAL")
        self.assertEqual(analysis["rules_matched"], [])

    def test_23_high_connection_rate_matches_rule(self):
        flow = make_flow(connection_count=60, duration_seconds=1)
        self.assertIn("IDS-001", analyze_flow(flow)["rules_matched"])

    def test_24_repeated_failures_match_rule(self):
        flow = make_flow(connection_count=20, failed_connection_count=14)
        self.assertIn("IDS-002", analyze_flow(flow)["rules_matched"])

    def test_25_destination_port_diversity_matches_rule(self):
        self.assertIn("IDS-003", analyze_flow(make_flow(unique_destination_ports=12))["rules_matched"])

    def test_26_syn_heavy_flow_matches_rule(self):
        self.assertIn("IDS-004", analyze_flow(make_flow(packet_count=50, syn_count=45))["rules_matched"])

    def test_27_unusual_service_port_matches_rule(self):
        self.assertIn("IDS-005", analyze_flow(make_flow(destination_port=4444))["rules_matched"])

    def test_28_large_byte_volume_matches_rule(self):
        self.assertIn("IDS-006", analyze_flow(make_flow(byte_count=2_000_000))["rules_matched"])

    def test_29_anomaly_score_is_bounded(self):
        features = extract_network_features(make_flow(byte_count=10**12, packet_count=10**8))
        self.assertLessEqual(calculate_anomaly_score(features), 100)

    def test_30_risk_score_is_bounded(self):
        matches = [{"severity": "CRITICAL"}] * 100
        self.assertEqual(calculate_risk_score(matches, 100), 100)

    def test_31_rule_hit_classifies_flow_as_suspicious(self):
        analysis = analyze_flow(make_flow(destination_port=4444))
        self.assertIn(analysis["classification"], {"SUSPICIOUS", "POTENTIAL_INTRUSION"})

    def test_32_alert_contains_triage_fields(self):
        analysis = analyze_flow(make_flow(destination_port=4444))
        alert = generate_alert(analysis, "IDS-005")
        self.assertTrue(alert["alert_id"].startswith("ALT-"))
        self.assertEqual(alert["status"], "NEW")
        self.assertEqual(alert["source_ip"], "192.0.2.15")

    def test_33_correlates_same_source_and_rule_in_window(self):
        alerts = [
            {"alert_id": "a", "source_ip": "192.0.2.15", "rule_id": "IDS-003", "timestamp": "2026-09-30T10:00:00Z"},
            {"alert_id": "b", "source_ip": "192.0.2.15", "rule_id": "IDS-003", "timestamp": "2026-09-30T10:00:30Z"},
        ]
        groups = correlate_alerts(alerts)
        self.assertEqual(groups[0]["count"], 2)

    def test_34_does_not_correlate_different_sources(self):
        alerts = [
            {"alert_id": "a", "source_ip": "192.0.2.15", "rule_id": "IDS-003", "timestamp": "2026-09-30T10:00:00Z"},
            {"alert_id": "b", "source_ip": "192.0.2.16", "rule_id": "IDS-003", "timestamp": "2026-09-30T10:00:30Z"},
        ]
        self.assertEqual(correlate_alerts(alerts), [])


class DatasetTests(unittest.TestCase):
    def test_35_generator_returns_requested_number_of_rows(self):
        self.assertEqual(len(generate_dataset(25, seed=42)), 25)

    def test_36_generator_is_reproducible_for_scenario_and_features(self):
        first = generate_dataset(5, seed=7)
        second = generate_dataset(5, seed=7)
        for left, right in zip(first, second):
            self.assertEqual(left["scenario_type"], right["scenario_type"])
            self.assertEqual(left["source_ip"], right["source_ip"])
            self.assertEqual(left["packet_count"], right["packet_count"])

    def test_37_dataset_uses_reserved_documentation_addresses(self):
        for row in generate_dataset(50, seed=33):
            validate_flow(row)

    def test_38_dataset_has_normal_and_suspicious_labels(self):
        labels = {row["label"] for row in generate_dataset(300, seed=12)}
        self.assertEqual(labels, {"NORMAL", "SUSPICIOUS"})

    def test_39_csv_has_required_schema_and_row_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows.csv"
            written = write_dataset(path, rows=17, seed=12)
            with path.open(newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                records = list(reader)
            self.assertEqual(written, 17)
            self.assertEqual(tuple(reader.fieldnames or ()), FIELDNAMES)
            self.assertEqual(len(records), 17)

    def test_40_dataset_rejects_zero_rows(self):
        with self.assertRaisesRegex(ValueError, "at least 1"):
            generate_dataset(0)


if __name__ == "__main__":
    unittest.main(verbosity=2)