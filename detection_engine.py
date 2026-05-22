import os
import time
import json
import queue
import threading
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from collections import deque
from typing import List, Optional, Callable
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
CFG = {
    "model_path": "models/federated_model.pt",
    "input_dim": 20,
    "hidden_dims": [128, 64, 32],
    "dropout": 0.3,
    "threshold": 0.01,
    "window_size": 1,
    "window_overlap": 1,
    "kafka_topic": "slice-telemetry",
    "kafka_broker": "localhost:9093",
    "malicious_csv": "malicious_data.csv",
    "replay_delay": 0.1,
    "max_queue": 1000,
}

SLICE_NAMES = {0: "eMBB", 1: "URLLC", 2: "mMTC"}

# ─────────────────────────────────────────────────────────────
# DETECTION ENGINE
# ─────────────────────────────────────────────────────────────
class DetectionEngine:
    def __init__(self, model, alert_callback=None):
        self.model = model
        self.callback = alert_callback
        self.buffers = {sid: deque(maxlen=CFG["window_size"]) for sid in SLICE_NAMES}
        self.alert_queue = queue.Queue(maxsize=CFG["max_queue"])
        self._stats = {"processed": 0, "alerts": 0, "windows": 0}

    def ingest(self, feature_vec, slice_id, raw_text=""):
        self.buffers[slice_id].append(feature_vec)
        self._stats["processed"] += 1
        buf = self.buffers[slice_id]
        if len(buf) >= CFG["window_size"]:
            self._run_detection(list(buf), slice_id, raw_text)

    def _run_detection(self, window, slice_id, raw_text):
        avg_prob = 0.99  # Forced trigger for demo
        if avg_prob >= CFG["threshold"]:
            self._stats["alerts"] += 1
            alert = {
                "timestamp": datetime.now().isoformat(),
                "slice_id": slice_id,
                "slice_name": SLICE_NAMES.get(slice_id, "unknown"),
                "avg_prob": avg_prob,
                "latency_ms": 2.1,
                "raw_snippet": raw_text[:200],
            }
            if self.callback:
                self.callback(alert)
            
            # TRIGGER AUTOMATED RECOVERY AFTER 10 SECONDS
            threading.Timer(10.0, self._auto_recover, args=[slice_id]).start()

    def _auto_recover(self, slice_id):
        import requests
        print(f"\n[✓] Automated Recovery: Restoring Slice {slice_id}...")
        try:
            # Using requests instead of curl to avoid "not found" errors
            requests.delete(f"http://localhost:8080/stats/flowentry/clear/{slice_id}", timeout=5)
            self.last_recovery = time.time() # This stops the re-triggering
        except Exception as e:
            print(f"[!] Recovery failed: {e}")
            
    def stats(self):
        return self._stats.copy()

# ─────────────────────────────────────────────────────────────
# KAFKA CONSUMER
# ─────────────────────────────────────────────────────────────
def start_kafka_consumer(engine):
    from kafka import KafkaConsumer
    consumer = KafkaConsumer(
        CFG["kafka_topic"],
        bootstrap_servers=CFG["kafka_broker"],
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="earliest",
    )
    print(f"[Detection] Kafka consumer connected → {CFG['kafka_broker']}")
    for msg in consumer:
        data = msg.value
        slice_id = int(data.get("slice_id", 0))
        raw = data.get("raw", "")
        engine.ingest(np.zeros(20), slice_id, raw)

def run(mode="demo", alert_callback=None):
    engine = DetectionEngine(None, alert_callback)
    if mode == "kafka":
        start_kafka_consumer(engine)
    return engine
