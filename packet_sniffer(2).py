

"""
packet_sniffer.py
=================
Live packet capture daemon — replaces CSV replay for production.
Taps the UPF (User Plane Function) network interface,
extracts features from live 5G SBI traffic in real time,
and publishes feature vectors to Kafka.

Requires:
    pip install scapy kafka-python numpy
    sudo setcap cap_net_raw+eip $(which python3)   # or run as root

Usage:
    # Tap eth0, publish to local Kafka
    python packet_sniffer.py

    # Specific interface + remote Kafka
    python packet_sniffer.py --interface upf0 --broker 192.168.1.10:9092

    # Dry run (print features, don't publish)
    python packet_sniffer.py --dry-run

Architecture:
    [5G UPF interface]
          ↓  scapy AsyncSniffer
    [Feature extractor]
          ↓  JSON feature vector
    [Kafka producer] → topic: "slice-telemetry"
          ↓
    [detection_engine.py consumer]
"""

import os
import re
import sys
import json
import time
import queue
import hashlib
import argparse
import threading
import ipaddress
from datetime import datetime
from typing import Optional, Dict

import numpy as np

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
CFG = {
    "interface":      os.getenv("INTERFACE", "eth0"),
    "kafka_broker":   os.getenv("KAFKA_BROKER", "localhost:9092"),
    "kafka_topic":    os.getenv("KAFKA_TOPIC", "slice-telemetry"),
    "batch_size":     10,           # publish N packets at once
    "batch_timeout":  0.5,          # max seconds to wait before flushing
    "queue_maxsize":  5000,
    "feature_dim":    20,
    # 5G SBI port (NRF/UDM/SMF all listen on 7777 by default in Open5GS)
    "sbi_port":       7777,
    # Slice IP ranges — map source IP to slice
    "slice_ranges": {
        0: "10.10.0.0/24",   # eMBB
        1: "10.20.0.0/24",   # URLLC
        2: "10.30.0.0/24",   # mMTC
    },
    "dry_run":        False,
}

# 5G SBI endpoint → attack relevance score
SBI_ENDPOINTS = {
    "/nnrf-disc/":  {"nrf_disc": 1},
    "/nnrf-nfm/":   {"nrf_mgmt": 1},
    "/nudm-sdm/":   {"udm_access": 1},
    "/nsmf-pdusession/": {},
    "/namf-comm/":  {},
}

# ─────────────────────────────────────────────────────────────
# SLICE RESOLVER
# ─────────────────────────────────────────────────────────────

_slice_nets = {
    sid: ipaddress.IPv4Network(cidr)
    for sid, cidr in CFG["slice_ranges"].items()
}

def resolve_slice(src_ip: str) -> int:
    try:
        addr = ipaddress.IPv4Address(src_ip)
        for sid, net in _slice_nets.items():
            if addr in net:
                return sid
    except Exception:
        pass
    return 0   # default to eMBB

# ─────────────────────────────────────────────────────────────
# FEATURE EXTRACTOR
# ─────────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extracts the same 20 features as data_pipeline.py
    but from live scapy packets instead of CSV rows.
    Maintains per-flow state for stateful features.
    """
    def __init__(self):
        self._flow_stats: Dict[str, dict] = {}

    def _flow_key(self, pkt) -> str:
        try:
            src = pkt["IP"].src
            dst = pkt["IP"].dst
            sport = pkt["TCP"].sport if pkt.haslayer("TCP") else 0
            dport = pkt["TCP"].dport if pkt.haslayer("TCP") else 0
            return f"{src}:{sport}-{dst}:{dport}"
        except Exception:
            return "unknown"

    def extract(self, pkt) -> Optional[dict]:
        """Return feature dict or None if packet is not 5G SBI traffic."""
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.layers.http import HTTPRequest, HTTPResponse

            if not pkt.haslayer(IP):
                return None

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            slice_id = resolve_slice(src_ip)

            # Only process TCP traffic on SBI port
            if not pkt.haslayer(TCP):
                return None

            dport = pkt["TCP"].dport
            sport = pkt["TCP"].sport
            if dport != CFG["sbi_port"] and sport != CFG["sbi_port"]:
                return None

            # Extract raw payload
            payload = bytes(pkt["TCP"].payload).decode("utf-8", errors="replace")
            payload_len = len(payload)

            # HTTP method
            method_map = {"GET": 1, "POST": 2, "PUT": 3, "PATCH": 4,
                          "DELETE": 5, "HEAD": 6, "OPTIONS": 7}
            method = next(
                (v for k, v in method_map.items() if payload.startswith(k)), 0
            )

            # HTTP status
            status = 0
            m = re.search(r"HTTP/[12](?:\.\d)? (\d{3})", payload)
            if m:
                status = int(m.group(1))

            # Content length
            clen = 0
            m = re.search(r"[Cc]ontent-[Ll]ength:\s*(\d+)", payload)
            if m:
                clen = int(m.group(1))

            # Endpoint detection
            nrf_disc   = 1 if "/nnrf-disc/" in payload else 0
            nrf_mgmt   = 1 if "/nnrf-nfm/"  in payload else 0
            udm_access = 1 if "/nudm-sdm/"  in payload else 0

            # NoSQL injection indicators
            nosql_kw  = 1 if any(k in payload for k in [
                "$and", "$or", "$nor", "$gt", "$lt", "$ne",
                '{"find"', "NfProfile"
            ]) else 0
            inj_depth = min(payload.count("$"), 20) / 20.0

            # MongoDB indicators
            mongo_q   = 1 if '{"find"' in payload and "NfProfile" in payload else 0
            mongo_err = 1 if "errmsg" in payload else 0
            mongo_op  = 1 if '{"find"' in payload else 0

            # IMSI
            imsi = 1 if "imsi-" in payload.lower() else 0

            # TCP flags
            flags = pkt["TCP"].flags
            syn_flag = 1 if flags & 0x02 else 0   # SYN

            # Flow state
            fkey  = self._flow_key(pkt)
            fstat = self._flow_stats.setdefault(fkey, {
                "pkt_count": 0, "last_ts": time.time(), "byte_count": 0
            })
            fstat["pkt_count"] += 1
            fstat["byte_count"] += payload_len
            flow_dur = time.time() - fstat["last_ts"]
            fstat["last_ts"] = time.time()

            # Cleanup old flows (> 60s)
            now = time.time()
            self._flow_stats = {
                k: v for k, v in self._flow_stats.items()
                if now - v["last_ts"] < 60
            }

            return {
                "features": [
                    method,
                    nrf_disc,
                    nrf_mgmt,
                    udm_access,
                    nosql_kw,
                    min(status, 599) / 600.0,
                    min(clen, 10000) / 10000.0,
                    min(payload_len, 5000) / 5000.0,
                    mongo_q,
                    mongo_err,
                    mongo_op,
                    1 if 500 <= status < 600 else 0,
                    1 if 400 <= status < 500 else 0,
                    inj_depth,
                    imsi,
                    1 if method > 0 else 0,
                    1 if status > 0 else 0,
                    min(payload_len, 1000) / 1000.0,
                    slice_id / 3.0,
                    datetime.now().hour / 24.0,
                ],
                "slice_id":   slice_id,
                "src_ip":     src_ip,
                "dst_ip":     dst_ip,
                "timestamp":  datetime.now().isoformat(),
                "payload_snippet": payload[:200],
            }

        except Exception as e:
            return None

# ─────────────────────────────────────────────────────────────
# KAFKA PUBLISHER
# ─────────────────────────────────────────────────────────────

class KafkaPublisher:
    def __init__(self, broker: str, topic: str, dry_run: bool = False):
        self.topic   = topic
        self.dry_run = dry_run
        self.producer = None
        self._stats = {"published": 0, "errors": 0}

        if not dry_run:
            try:
                from kafka import KafkaProducer
                self.producer = KafkaProducer(
                    bootstrap_servers=broker,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    acks="all",
                    retries=3,
                    linger_ms=50,   # small batching delay for throughput
                )
                print(f"[Sniffer] Kafka producer connected → {broker}")
            except ImportError:
                print("[Sniffer] kafka-python not installed — dry run mode")
                self.dry_run = True
            except Exception as e:
                print(f"[Sniffer] Kafka connection failed: {e} — dry run mode")
                self.dry_run = True

    def publish(self, feature_dict: dict):
        if self.dry_run:
            sid = feature_dict.get("slice_id", 0)
            feat = feature_dict.get("features", [])
            nosql = feat[4] if len(feat) > 4 else 0
            print(f"  [DryRun] Slice {sid}  nosql={nosql:.0f}  "
                  f"features=[{', '.join(f'{v:.2f}' for v in feat[:5])}...]")
            self._stats["published"] += 1
            return

        try:
            self.producer.send(self.topic, value=feature_dict)
            self._stats["published"] += 1
        except Exception as e:
            self._stats["errors"] += 1
            print(f"  [Kafka] Publish error: {e}")

    def flush(self):
        if self.producer:
            self.producer.flush()

    def stats(self):
        return self._stats.copy()

# ─────────────────────────────────────────────────────────────
# SNIFFER
# ─────────────────────────────────────────────────────────────

class PacketSniffer:
    def __init__(self, interface: str, publisher: KafkaPublisher):
        self.interface = interface
        self.publisher = publisher
        self.extractor = FeatureExtractor()
        self._queue    = queue.Queue(maxsize=CFG["queue_maxsize"])
        self._stats    = {"captured": 0, "processed": 0, "dropped": 0}
        self._running  = False

    def _packet_callback(self, pkt):
        self._stats["captured"] += 1
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._stats["dropped"] += 1

    def _processor_thread(self):
        """Batch-process packets from the queue and publish to Kafka."""
        batch = []
        last_flush = time.time()

        while self._running:
            try:
                pkt = self._queue.get(timeout=0.1)
                features = self.extractor.extract(pkt)
                if features:
                    batch.append(features)
                    self._stats["processed"] += 1

                now = time.time()
                if len(batch) >= CFG["batch_size"] or \
                   (batch and now - last_flush >= CFG["batch_timeout"]):
                    for feat in batch:
                        self.publisher.publish(feat)
                    self.publisher.flush()
                    batch = []
                    last_flush = now

            except queue.Empty:
                # Flush remaining on timeout
                if batch:
                    for feat in batch:
                        self.publisher.publish(feat)
                    self.publisher.flush()
                    batch = []
                    last_flush = time.time()

    def _stats_thread(self):
        """Print stats every 10 seconds."""
        while self._running:
            time.sleep(10)
            pub = self.publisher.stats()
            print(f"  [Stats] captured={self._stats['captured']}  "
                  f"processed={self._stats['processed']}  "
                  f"dropped={self._stats['dropped']}  "
                  f"published={pub['published']}  "
                  f"errors={pub['errors']}")

    def start(self):
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            print("[Sniffer] scapy not installed: pip install scapy")
            sys.exit(1)

        self._running = True

        # Start processor + stats threads
        proc_thread  = threading.Thread(target=self._processor_thread, daemon=True)
        stats_thread = threading.Thread(target=self._stats_thread, daemon=True)
        proc_thread.start()
        stats_thread.start()

        print(f"\n{'='*60}")
        print(f"  PACKET SNIFFER")
        print(f"  Interface : {self.interface}")
        print(f"  SBI port  : {CFG['sbi_port']}")
        print(f"  Kafka     : {CFG['kafka_topic']}")
        print(f"  Dry run   : {CFG['dry_run']}")
        print(f"{'='*60}\n")
        print(f"  Sniffing... (Ctrl+C to stop)\n")

        # BPF filter — only SBI port traffic
        bpf = f"tcp port {CFG['sbi_port']}"

        sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
        )
        sniffer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  Stopping sniffer...")
            sniffer.stop()
            self._running = False
            time.sleep(1)
            pub = self.publisher.stats()
            print(f"\n  Final stats:")
            print(f"    Captured   : {self._stats['captured']}")
            print(f"    Processed  : {self._stats['processed']}")
            print(f"    Dropped    : {self._stats['dropped']}")
            print(f"    Published  : {pub['published']}")


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="5G SBI Packet Sniffer → Kafka Feature Publisher"
    )
    parser.add_argument("--interface", default=CFG["interface"],
                        help=f"Network interface to sniff (default: {CFG['interface']})")
    parser.add_argument("--broker", default=CFG["kafka_broker"],
                        help=f"Kafka broker address (default: {CFG['kafka_broker']})")
    parser.add_argument("--topic", default=CFG["kafka_topic"],
                        help=f"Kafka topic (default: {CFG['kafka_topic']})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print features to console instead of publishing to Kafka")
    args = parser.parse_args()

    CFG["interface"]   = args.interface
    CFG["kafka_broker"] = args.broker
    CFG["kafka_topic"] = args.topic
    CFG["dry_run"]     = args.dry_run

    publisher = KafkaPublisher(args.broker, args.topic, args.dry_run)
    sniffer   = PacketSniffer(args.interface, publisher)
    sniffer.start()
