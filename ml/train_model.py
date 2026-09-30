"""Optional supervised baseline; reports metrics computed on a held-out split."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


FEATURES = (
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
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/network_traffic.csv")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import make_pipeline
        from sklearn.impute import SimpleImputer
    except ImportError as error:
        raise SystemExit(
            "Optional ML dependencies are missing. Install them with: "
            "python -m pip install -r requirements-ml.txt"
        ) from error

    with Path(args.input).open(newline="", encoding="utf-8") as file:
        records = list(csv.DictReader(file))
    if len(records) < 20:
        raise SystemExit("At least 20 CSV records are required for a useful held-out evaluation.")
    x = [[float(record[name]) for name in FEATURES] for record in records]
    y = [record["label"] for record in records]
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    model = make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(n_estimators=160, class_weight="balanced", random_state=args.seed),
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predictions, average="binary", pos_label="SUSPICIOUS", zero_division=0
    )
    print(f"Training rows: {len(y_train)}")
    print(f"Test rows: {len(y_test)}")
    print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 score:  {f1:.4f}")
    print("Confusion matrix (rows=true, columns=predicted; order NORMAL, SUSPICIOUS):")
    print(confusion_matrix(y_test, predictions, labels=["NORMAL", "SUSPICIOUS"]))
    print("These are synthetic hold-out metrics and do not estimate production detection performance.")


if __name__ == "__main__":
    main()