"""Create a reproducible CSV of synthetic records; this script sends no traffic."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
import random
from typing import Any
from uuid import uuid4

NORMAL = {
    "NORMAL_WEB": (443, "TCP"),
    "NORMAL_DNS": (53, "UDP"),
    "NORMAL_SSH": (22, "TCP"),
    "NORMAL_EMAIL": (587, "TCP"),
    "NORMAL_DATABASE": (5432, "TCP"),
}
SUSPICIOUS = (
    "HIGH_CONNECTION_RATE",
    "REPEATED_FAILED_CONNECTIONS",
    "MULTI_PORT_PROBING_PATTERN",
    "SYN_HEAVY_PATTERN",
    "UNUSUAL_PORT_ACTIVITY",
    "HIGH_TRAFFIC_VOLUME",
)
NETWORKS = ("192.0.2", "198.51.100", "203.0.113")
FIELDNAMES = (
    "flow_id",
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
    "average_packet_size",
    "unique_destination_ports",
    "unique_destination_ips",
    "label",
    "scenario_type",
)


def _make_row(rng: random.Random, scenario: str, observed_at: datetime) -> dict[str, Any]:
    normal = scenario in NORMAL
    destination_port, protocol = NORMAL.get(scenario, (443, "TCP"))
    packets = rng.randint(8, 45)
    byte_count = rng.randint(3_000, 70_000)
    duration = round(rng.uniform(2, 20), 2)
    connections = rng.randint(1, 8)
    failures = rng.randint(0, 1)
    syn_count = rng.randint(1, max(2, int(packets * 0.35)))
    rst_count = rng.randint(0, 2)
    port_diversity = 1

    if scenario == "HIGH_CONNECTION_RATE":
        packets, connections = rng.randint(70, 180), rng.randint(40, 120)
        duration = round(rng.uniform(0.25, 1.0), 2)
        failures = rng.randint(3, 20)
        syn_count = rng.randint(int(packets * 0.65), packets)
    elif scenario == "REPEATED_FAILED_CONNECTIONS":
        connections = rng.randint(12, 35)
        failures = rng.randint(8, connections)
        duration = round(rng.uniform(5, 15), 2)
        packets = rng.randint(18, 75)
        syn_count, rst_count = rng.randint(8, 28), rng.randint(5, 20)
    elif scenario == "MULTI_PORT_PROBING_PATTERN":
        connections = rng.randint(14, 38)
        port_diversity = rng.randint(10, 28)
        destination_port = rng.randint(1_024, 60_000)
        duration, packets = round(rng.uniform(1, 13), 2), rng.randint(25, 100)
        failures, syn_count = rng.randint(5, 22), rng.randint(18, 70)
    elif scenario == "SYN_HEAVY_PATTERN":
        packets = rng.randint(70, 180)
        syn_count = rng.randint(int(packets * 0.84), packets)
        connections, failures = rng.randint(18, 55), rng.randint(3, 16)
        duration, rst_count = round(rng.uniform(0.5, 4.5), 2), rng.randint(3, 18)
    elif scenario == "UNUSUAL_PORT_ACTIVITY":
        destination_port = rng.choice((4444, 1337, 31337, 49152, 55000))
        connections, failures = rng.randint(8, 26), rng.randint(2, 10)
    elif scenario == "HIGH_TRAFFIC_VOLUME":
        byte_count, packets = rng.randint(2_000_000, 12_000_000), rng.randint(2_000, 18_000)
        duration, connections = round(rng.uniform(10, 70), 2), rng.randint(2, 12)
    elif scenario == "NORMAL_DNS":
        packets, byte_count = rng.randint(1, 8), rng.randint(80, 1_400)
        duration, protocol = round(rng.uniform(0.05, 0.85), 2), "UDP"
    elif scenario == "NORMAL_SSH":
        packets, byte_count = rng.randint(18, 90), rng.randint(2_500, 55_000)
        duration, connections = round(rng.uniform(15, 125), 2), 1
    elif scenario == "NORMAL_EMAIL":
        byte_count, duration = rng.randint(2_000, 180_000), round(rng.uniform(1, 8), 2)
    elif scenario == "NORMAL_DATABASE":
        byte_count, connections = rng.randint(5_000, 140_000), rng.randint(1, 4)
        duration = round(rng.uniform(0.2, 3.2), 2)

    src_network, dst_network = rng.sample(NETWORKS, 2)
    src = f"{src_network}.{rng.randint(1, 253)}"
    dst = f"{dst_network}.{rng.randint(1, 253)}"
    return {
        "flow_id": str(uuid4()),
        "timestamp": (observed_at - timedelta(seconds=rng.randint(0, 86_400))).isoformat(),
        "source_ip": src,
        "destination_ip": dst,
        "source_port": rng.randint(32_768, 65_000),
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packets,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": connections,
        "failed_connection_count": failures,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": round(byte_count / max(1, packets), 2),
        "unique_destination_ports": port_diversity,
        "unique_destination_ips": 1,
        "label": "NORMAL" if normal else "SUSPICIOUS",
        "scenario_type": scenario,
    }


def generate_dataset(rows: int = 5_000, seed: int = 2026) -> list[dict[str, Any]]:
    if rows < 1:
        raise ValueError("rows must be at least 1")
    rng = random.Random(seed)
    normal_scenarios = tuple(NORMAL)
    scenarios = []
    for index in range(rows):
        # Keep the data useful for training without making it artificially balanced.
        if rng.random() < 0.72:
            scenarios.append(rng.choice(normal_scenarios))
        else:
            scenarios.append(rng.choice(SUSPICIOUS))
    observed_at = datetime.now(timezone.utc)
    return [_make_row(rng, scenario, observed_at) for scenario in scenarios]


def write_dataset(path: str | Path, rows: int = 5_000, seed: int = 2026) -> int:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    records = generate_dataset(rows, seed)
    with destination.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)
    return len(records)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=5_000)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--output", default="data/network_traffic.csv")
    args = parser.parse_args()
    count = write_dataset(args.output, args.rows, args.seed)
    print(f"Wrote {count:,} synthetic flow records to {args.output}")
    print("Only reserved documentation IP ranges are used; no packets were sent.")


if __name__ == "__main__":
    main()