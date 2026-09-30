"""Print synthetic network-flow records as JSON; no network traffic is sent."""

from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timezone

from simulator.generate_dataset import NORMAL, SUSPICIOUS, _make_row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("normal", "mixed", "suspicious"), default="mixed")
    parser.add_argument("--speed", choices=("slow", "fast"), default="slow")
    parser.add_argument("--count", type=int, default=0, help="0 keeps generating data until interrupted")
    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be non-negative")

    rng = random.Random()
    scenarios = tuple(NORMAL) if args.mode == "normal" else SUSPICIOUS
    delay = 1.5 if args.speed == "slow" else 0.25
    generated = 0
    try:
        while args.count == 0 or generated < args.count:
            if args.mode == "mixed":
                scenario = rng.choice(tuple(NORMAL)) if rng.random() < 0.72 else rng.choice(SUSPICIOUS)
            else:
                scenario = rng.choice(scenarios)
            flow = _make_row(rng, scenario, datetime.now(timezone.utc))
            print(json.dumps(flow, separators=(",", ":")), flush=True)
            generated += 1
            if args.count == 0 or generated < args.count:
                time.sleep(delay)
    except KeyboardInterrupt:
        print("\nStopped synthetic record generation.", flush=True)


if __name__ == "__main__":
    main()