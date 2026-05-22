"""
response_engine.py
==================
Layer 4 of the full pipeline.
Receives alerts from DetectionEngine and triggers:
  1. Immediate SDN flow rule via SSH to VM (Mininet/OVS)
  2. Recovery monitoring
  3. Full audit log
"""

import os
import time
import json
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
CFG = {
    "ryu_enabled":         True,    # Enabled for real VM control
    "max_isolations_min":  3,        # circuit breaker — max isolations per minute
    "clean_windows_req":   3,        # windows below threshold before re-admission
    "clean_threshold":     0.30,     # probability below this = clean window
    "log_dir":             "logs",
    "audit_log":           "logs/response_audit.jsonl",
}

SLICE_NAMES = {0: "eMBB", 1: "URLLC", 2: "mMTC"}

# ── Per-slice SDN config (Mapping port to Slice) ─────────────
# Slice 0 = Port 1, Slice 1 = Port 2, Slice 2 = Port 3
SLICE_SDN_CONFIG = {
    0: {"port": 1, "priority": 200},
    1: {"port": 2, "priority": 210},
    2: {"port": 3, "priority": 220},
}

# ── Response playbook ────────────────────────────────────────
RESPONSE_PLAYBOOK = {
    "nosql_injection": {
        "immediate":    ["Block source IP at NRF ingress", "Rate-limit /nnrf-disc/ to 10 req/s", "Enable MongoDB query validation"],
        "containment":  ["Quarantine slice VLAN", "Freeze NRF VNF instance"],
        "recovery":     ["Re-validate all NF registrations", "Restore MongoDB ACLs"],
    },
    "ddos": {
        "immediate":    ["Rate-limit ingress to 1,000 pps", "Blackhole top-N source IPs"],
        "containment":  ["Isolate slice VLAN", "Redirect via DDoS proxy"],
        "recovery":     ["Monitor for 3 clean windows"],
    },
    "lateral_movement": {
        "immediate":    ["CRITICAL: Block all inter-slice egress", "Alert neighboring slices"],
        "containment":  ["Hard-isolate compromised slice"],
        "recovery":     ["Full forensic analysis required"],
    },
    "default": {
        "immediate":    ["Block suspicious source", "Rate-limit affected endpoint"],
        "containment":  ["Isolate slice"],
        "recovery":     ["Monitor for clean windows"],
    },
}

# ─────────────────────────────────────────────────────────────
# CIRCUIT BREAKER & AUDIT LOGGER
# ─────────────────────────────────────────────────────────────

class CircuitBreaker:
    def __init__(self, max_per_min: int):
        self.max   = max_per_min
        self.count = 0
        self.reset_at = time.time() + 60

    def allow(self) -> bool:
        if time.time() > self.reset_at:
            self.count    = 0
            self.reset_at = time.time() + 60
        if self.count >= self.max:
            return False
        self.count += 1
        return True

def setup_audit_log():
    os.makedirs(CFG["log_dir"], exist_ok=True)

def write_audit(event: dict):
    with open(CFG["audit_log"], "a") as f:
        f.write(json.dumps(event) + "\n")

# ─────────────────────────────────────────────────────────────
# DISTRIBUTED SDN CONTROLLER (Host to VM via SSH)
# ─────────────────────────────────────────────────────────────

class DistributedSDNController:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def isolate_slice(self, slice_id: int) -> dict:
        cfg = SLICE_SDN_CONFIG.get(slice_id, {})
        port = cfg.get("port", 1)
        t0 = time.perf_counter()

        # SSH command to VM to block traffic on the switch port
        # -p 2222 maps to the VM's SSH, aakash is the VM username
        cmd = f"ssh -p 2222 aakash@127.0.0.1 'sudo ovs-ofctl add-flow s1 priority=200,in_port={port},actions=drop'"
        
        try:
            subprocess.run(cmd, shell=True, check=True)
            latency_ms = (time.perf_counter() - t0) * 1000
            print(f"    [SDN] Slice {slice_id} isolated via SSH ({latency_ms:.1f} ms)")
            return {"status": "isolated", "latency_ms": round(latency_ms, 2)}
        except Exception as e:
            print(f"    [SDN] SSH Isolation failed: {e}")
            return {"status": "failed", "latency_ms": 0.0}

    def restore_slice(self, slice_id: int) -> dict:
        cfg = SLICE_SDN_CONFIG.get(slice_id, {})
        port = cfg.get("port", 1)
        
        # SSH command to delete the drop rule
        cmd = f"ssh -p 2222 aakash@127.0.0.1 'sudo ovs-ofctl del-flows s1 in_port={port}'"
        subprocess.run(cmd, shell=True)
        return {"status": "restored", "latency_ms": 0.0}

# ─────────────────────────────────────────────────────────────
# RECOVERY MONITOR
# ─────────────────────────────────────────────────────────────

class RecoveryMonitor:
    def __init__(self, sdn: DistributedSDNController, audit_fn):
        self.sdn = sdn
        self.audit_fn = audit_fn
        self.isolated = {}
        self.clean_counts = defaultdict(int)

    def record_window(self, slice_id: int, avg_prob: float):
        if slice_id not in self.isolated: return
        if avg_prob < CFG["clean_threshold"]:
            self.clean_counts[slice_id] += 1
            if self.clean_counts[slice_id] >= CFG["clean_windows_req"]:
                self._readmit(slice_id)
        else:
            self.clean_counts[slice_id] = 0

    def _readmit(self, slice_id: int):
        sdn_result = self.sdn.restore_slice(slice_id)
        del self.isolated[slice_id]
        self.clean_counts[slice_id] = 0
        event = {"event": "slice_readmitted", "timestamp": datetime.now().isoformat(), 
                 "slice_id": slice_id, "sdn": sdn_result}
        self.audit_fn(event)

    def mark_isolated(self, slice_id: int):
        self.isolated[slice_id] = time.time()
        self.clean_counts[slice_id] = 0

# ─────────────────────────────────────────────────────────────
# RESPONSE ENGINE
# ─────────────────────────────────────────────────────────────

class ResponseEngine:
    def __init__(self):
        setup_audit_log()
        self.sdn      = DistributedSDNController(CFG["ryu_enabled"])
        self.breaker  = CircuitBreaker(CFG["max_isolations_min"])
        self.recovery = RecoveryMonitor(self.sdn, write_audit)
        self._stats   = {"alerts_received": 0, "isolations": 0}

    def handle_alert(self, alert: dict):
        self._stats["alerts_received"] += 1
        slice_id = alert["slice_id"]
        self.recovery.record_window(slice_id, alert["avg_prob"])

        if self.breaker.allow():
            t_isolate = time.perf_counter()
            sdn_result = self.sdn.isolate_slice(slice_id)
            isolate_ms = (time.perf_counter() - t_isolate) * 1000
            self.recovery.mark_isolated(slice_id)
            self._stats["isolations"] += 1
            
            write_audit({
                "event": "slice_isolated",
                "timestamp": alert["timestamp"],
                "slice_id": slice_id,
                "attack_type": self._classify_attack(alert.get("iocs", [])),
                "total_ms": round(alert["latency_ms"] + isolate_ms, 2),
                "sdn": sdn_result,
            })

    def _classify_attack(self, iocs: List[str]) -> str:
        ioc_text = " ".join(iocs).lower()
        if "nosql" in ioc_text: return "nosql_injection"
        if "ddos" in ioc_text: return "ddos"
        if "lateral" in ioc_text: return "lateral_movement"
        return "default"

    def stats(self) -> dict:
        return self._stats.copy()

def run() -> ResponseEngine:
    return ResponseEngine()
