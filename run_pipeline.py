"""
run_pipeline.py
===============
Master orchestrator for the full 5G Slice Security pipeline.

Wires together:
  Layer 1 — data_pipeline.py    (data prep + slice CSVs)
  Layer 2 — fl_trainer.py       (federated learning)
  Layer 3 — detection_engine.py (real-time inference)
  Layer 4 — response_engine.py  (SDN isolation + recovery)

Usage:
  # Full pipeline — train then detect
  python run_pipeline.py

  # Skip training (use existing model)
  python run_pipeline.py --skip-train

  # Kafka live mode (requires running Kafka + Open5GS)
  python run_pipeline.py --skip-train --mode kafka

  # Training only
  python run_pipeline.py --train-only

Install:
  pip install flwr torch scikit-learn pandas numpy requests colorama
  pip install kafka-python          # only for Kafka live mode
  pip install opacus                # only for DP-SGD privacy
"""

import os
import sys
import time
import argparse
import threading
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║     Edge AI for 5G Network Slice Security — ISP81            ║
║                    Dept. of ISE                              ║
║     Team: Hemanth · Aakash · Nikhath · Sakhi                 ║ 
╚══════════════════════════════════════════════════════════════╝
"""

PIPELINE_STAGES = [
    ("Layer 1", "Data Pipeline",      "data_pipeline",    "⚙"),
    ("Layer 2", "Federated Learning", "fl_trainer",       "🔗"),
    ("Layer 3", "Detection Engine",   "detection_engine", "🔍"),
    ("Layer 4", "Response Engine",    "response_engine",  "🛡"),
]

# ─────────────────────────────────────────────────────────────
# STAGE RUNNER
# ─────────────────────────────────────────────────────────────

def print_stage(layer: str, name: str, icon: str):
    print(f"\n{'═'*62}")
    print(f"  {icon}  {layer} — {name}")
    print(f"{'═'*62}")


def run_stage_1_data_pipeline():
    print_stage("Layer 1", "Data Pipeline", "⚙")
    import data_pipeline
    data_pipeline.run()


def run_stage_2_fl_training():
    print_stage("Layer 2", "Federated Learning Training", "🔗")
    import fl_trainer
    return fl_trainer.run()


def run_stage_3_4_detect_and_respond(mode: str = "demo"):
    print_stage("Layer 3+4", "Detection + Response (live loop)", "🔍🛡")
    import detection_engine
    import response_engine

    # Initialise response engine
    responder = response_engine.run()

    # Wire alert callback: detection → response
    def on_alert(alert: dict):
        responder.handle_alert(alert)

    # Run detection (blocking)
    engine = detection_engine.run(mode=mode, alert_callback=on_alert)
    return engine, responder

# ─────────────────────────────────────────────────────────────
# SUMMARY PRINTER
# ─────────────────────────────────────────────────────────────

def print_summary(start_time: float,
                  detect_stats: dict = None,
                  response_stats: dict = None):
    elapsed = time.time() - start_time
    print(f"\n{'═'*62}")
    print(f"  PIPELINE SUMMARY")
    print(f"{'═'*62}")
    print(f"  Total runtime     : {elapsed:.1f}s")

    if detect_stats:
        print(f"  Samples processed : {detect_stats.get('processed', 0)}")
        print(f"  Windows analysed  : {detect_stats.get('windows', 0)}")
        print(f"  Alerts raised     : {detect_stats.get('alerts', 0)}")

    if response_stats:
        print(f"  Isolations made   : {response_stats.get('isolations', 0)}")
        print(f"  Readmissions      : {response_stats.get('readmissions', 0)}")

    log_path = "logs/response_audit.jsonl"
    if os.path.exists(log_path):
        with open(log_path) as f:
            events = [l for l in f if l.strip()]
        print(f"  Audit log events  : {len(events)}  →  {log_path}")

    print(f"{'═'*62}\n")

# ─────────────────────────────────────────────────────────────
# PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────

def check_dependencies():
    missing = []
    for pkg, import_name in [
        ("torch",        "torch"),
        ("flwr",         "flwr"),
        ("pandas",       "pandas"),
        ("numpy",        "numpy"),
        ("sklearn",      "sklearn"),
        ("requests",     "requests"),
    ]:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"\n  ✗ Missing packages: {', '.join(missing)}")
        print(f"    Run: pip install {' '.join(missing)}")
        return False
    return True


def check_data_files(skip_train: bool):
    issues = []
    if not os.path.exists("malicious_data.csv"):
        issues.append("malicious_data.csv not found — place in current directory")
    if skip_train and not os.path.exists("models/federated_model.pt"):
        issues.append("models/federated_model.pt not found — run without --skip-train first")
    if issues:
        print("\n  ✗ Pre-flight issues:")
        for i in issues:
            print(f"    • {i}")
        return False
    return True

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="5G Slice Security — Full Pipeline Orchestrator"
    )
    parser.add_argument("--skip-train", action="store_true",
                        help="Skip FL training and use existing model")
    parser.add_argument("--train-only", action="store_true",
                        help="Run data pipeline + FL training only, no detection")
    parser.add_argument("--mode", choices=["demo", "kafka"], default="demo",
                        help="Detection mode: demo (replay CSV) or kafka (live)")
    parser.add_argument("--skip-data", action="store_true",
                        help="Skip data pipeline (use existing slice CSVs)")
    args = parser.parse_args()

    start_time = time.time()

    # ── Pre-flight ─────────────────────────────────────────
    print("  Pre-flight checks...")
    if not check_dependencies():
        sys.exit(1)
    if not check_data_files(args.skip_train):
        sys.exit(1)
    print("  ✓ All checks passed\n")

    print(f"  Mode          : {args.mode}")
    print(f"  Skip training : {args.skip_train}")
    print(f"  Train only    : {args.train_only}")
    print(f"  Started at    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Stage 1: Data Pipeline ────────────────────────────
    if not args.skip_data:
        try:
            run_stage_1_data_pipeline()
        except Exception as e:
            print(f"\n  ✗ Data pipeline failed: {e}")
            sys.exit(1)
    else:
        print("\n  [Stage 1] Skipping data pipeline — using existing CSVs")

    # ── Stage 2: FL Training ──────────────────────────────
    if not args.skip_train:
        try:
            model_path = run_stage_2_fl_training()
            print(f"\n  ✓ Model saved to {model_path}")
        except Exception as e:
            print(f"\n  ✗ FL training failed: {e}")
            sys.exit(1)
    else:
        print("\n  [Stage 2] Skipping FL training — using existing model")

    if args.train_only:
        print_summary(start_time)
        print("  Training complete. Run without --train-only to start detection.")
        return

    # ── Stage 3 + 4: Detect + Respond ────────────────────
    try:
        detect_engine, responder = run_stage_3_4_detect_and_respond(args.mode)
        print_summary(
            start_time,
            detect_stats=detect_engine.stats() if detect_engine else None,
            response_stats=responder.stats() if responder else None,
        )
    except KeyboardInterrupt:
        print("\n\n  Pipeline stopped by user.")
        print_summary(start_time)
    except Exception as e:
        print(f"\n  ✗ Detection/Response failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
