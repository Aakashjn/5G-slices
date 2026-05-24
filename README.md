# SliceShield — AI-Driven 5G Network Slice Security

> **End-to-end security orchestration for 5G network slicing, combining Federated Learning, SDN automation, and AI-powered forensic analysis.**

**Team:** ISP81 &nbsp;|&nbsp; **Department:** Information Science & Engineering

[![5G Network Slicing](https://img.shields.io/badge/5G-Network_Slicing-0066CC?style=for-the-badge)](https://en.wikipedia.org/wiki/Network_slicing)
[![Federated Learning](https://img.shields.io/badge/AI-Federated_Learning-27AE60?style=for-the-badge)](https://flower.ai/)
[![SDN](https://img.shields.io/badge/SDN-Ryu_Controller-E67E22?style=for-the-badge)](https://ryu-sdn.org/)
[![Apache Kafka](https://img.shields.io/badge/Streaming-Apache_Kafka-1A1A2E?style=for-the-badge&logo=apachekafka)](https://kafka.apache.org/)
[![PyTorch](https://img.shields.io/badge/ML-PyTorch-EE4C2C?style=for-the-badge&logo=pytorch)](https://pytorch.org/)

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Component Breakdown](#component-breakdown)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Network Configuration](#network-configuration)
- [Running the System](#running-the-system)
- [Simulating Attacks](#simulating-attacks)
- [System Response Flow](#system-response-flow)

---

## Overview

**SliceShield** is an end-to-end security orchestration platform purpose-built for 5G network slicing environments. It addresses the critical challenge of securing isolated network slices — eMBB, URLLC, and mMTC — against real-time threats such as NoSQL injection, DDoS, and SBI (Service-Based Interface) abuse.

The platform integrates three core capabilities:

- **Distributed Anomaly Detection** — Federated Learning (Flower + PyTorch) enables privacy-preserving, on-device model training across edge nodes with no raw data sharing.
- **Real-Time Threat Mitigation** — An SDN controller (Ryu) enforces automated slice isolation in under **50ms** upon anomaly detection.
- **AI-Powered Forensic Analysis** — A Groq/Llama-3-backed Root Cause Analysis (RCA) agent automatically generates structured forensic reports from audit logs.

---

## Key Features

| Feature | Description |
|---|---|
| ⚡ **Sub-50ms Response** | Automated slice isolation triggered by the ML inference pipeline |
| 🔒 **Privacy-Preserving AI** | Federated Learning — model weights shared, never raw traffic data |
| 🔎 **Live Traffic Analysis** | Scapy-based packet sniffer streams 5G/SBI traffic via Apache Kafka |
| 🤖 **AI Forensic Reports** | Llama-3 generates structured Root Cause Analysis from audit logs |
| 🔄 **Automated Self-Healing** | Compromised slices auto-recover after a configurable cooldown period |
| 📊 **Real-Time Dashboard** | Flask API backend with live slice health state (RED/GREEN indicators) |
| 🧪 **Attack Simulation** | Supports both live Mininet attacks and synthetic API-triggered scenarios |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SLICESHIELD PLATFORM                         │
│                                                                     │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐ │
│   │ packet_      │───▶│  Apache      │───▶│  run_pipeline.py     │ │
│   │ sniffer.py   │    │  Kafka       │    │  (ML Orchestrator)   │ │
│   │ (Scapy/5G)   │    │  Stream      │    │  Federated Model     │ │
│   └──────────────┘    └──────────────┘    └──────────┬───────────┘ │
│                                                       │ Anomaly     │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────▼───────────┐ │
│   │ rca_agent.py │◀───│  Audit Logs  │◀───│  response_engine.py  │ │
│   │ (Llama-3     │    │  (JSONL)     │    │  (Ryu SDN Control)   │ │
│   │  Forensics)  │    └──────────────┘    └──────────────────────┘ │
│   └──────────────┘                                                  │
│          │                                                          │
│   ┌──────▼───────┐    ┌──────────────────────────────────────────┐ │
│   │ api_server.py│───▶│  Dashboard (Real-Time Slice Health)      │ │
│   │ (Flask REST) │    │  eMBB | URLLC | mMTC  [GREEN/RED]        │ │
│   └──────────────┘    └──────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

| File | Role | Description |
|---|---|---|
| `run_pipeline.py` | **Orchestrator** | Drives the end-to-end execution flow: Kafka ingestion → ML inference → SDN trigger |
| `packet_sniffer.py` | **Traffic Capture** | Captures live 5G/SBI packets from Mininet interfaces using Scapy; streams to Kafka |
| `response_engine.py` | **SDN Controller Interface** | Pushes flow rules to Ryu to isolate compromised slices; manages auto-recovery |
| `api_server.py` | **REST API Backend** | Flask server exposing dashboard state, audit log access, and attack simulation endpoints |
| `rca_agent.py` | **Forensic AI Agent** | Polls audit logs and invokes Groq (Llama-3) to produce structured forensic reports |
| `fl_trainer.py` | **Federated Trainer** | Orchestrates Flower-based Federated Learning rounds across simulated edge clients |
| `data_pipeline.py` | **Dataset Generator** | Generates balanced, labeled training data for eMBB, URLLC, and mMTC slice profiles |

---

## Prerequisites

### System Requirements

| Component | Requirement |
|---|---|
| **Operating System** | Ubuntu 22.04 LTS or later |
| **Python** | 3.10+ |
| **Network Simulation** | [Mininet](http://mininet.org/) + [Ryu SDN Controller](https://ryu-sdn.org/) |
| **Containers** | Docker & Docker Compose |
| **Hardware** | 8GB RAM minimum recommended |

### Python Dependencies

```
flwr          # Federated Learning framework (Flower)
torch         # PyTorch for ML model training and inference
pandas        # Data handling and feature engineering
numpy         # Numerical operations
requests      # HTTP client for Ryu REST API
flask         # REST API backend server
flask-cors    # Cross-origin resource sharing for dashboard
kafka-python  # Kafka producer/consumer integration
scapy         # Packet capture and dissection
```

---

## Installation

**1. Clone the repository and create a virtual environment:**

```bash
git clone <repository-url>
cd sliceshield
python3 -m venv venv
source venv/bin/activate
```

**2. Install all Python dependencies:**

```bash
pip install flwr torch pandas numpy requests flask flask-cors kafka-python scapy
```

**3. Start background infrastructure (Kafka + MLflow) via Docker:**

```bash
sudo docker compose up -d
```

---

## Network Configuration

> ⚠️ **Critical:** IP addresses in the source files must be updated to match your deployment topology before running.

### Option A — Single Machine (Recommended for Testing)

All components (Mininet, Ryu, Kafka, Python scripts) run on the same Ubuntu machine.

| File | Setting | Value |
|---|---|---|
| `response_engine.py` | `vm_ip` | `"127.0.0.1"` |
| `detection_engine.py` | `kafka_broker` | `"127.0.0.1"` |
| `detection_engine.py` | `ryu_controller_ip` | `"127.0.0.1"` |
| `packet_sniffer.py` | `--broker` flag | `127.0.0.1:9093` |

### Option B — Bridged VM Setup

Mininet runs inside a VM; the AI pipeline runs on the host laptop.

| File | Setting | Value |
|---|---|---|
| `response_engine.py` | `vm_ip` | VM's bridged IP (e.g., `10.184.x.x`) |
| `detection_engine.py` | `kafka_broker` | Host laptop's LAN IP |
| `detection_engine.py` | `ryu_controller_ip` | VM's bridged IP |
| `packet_sniffer.py` (inside VM) | `--broker` flag | `<LAPTOP_IP>:9093` |

---

## Running the System

Start all services in the order below. Each command should run in a **dedicated terminal window**.

### Phase 1 — Infrastructure

**Terminal 1: Kafka & MLflow**
```bash
sudo docker compose up -d
```

### Phase 2 — Network Layer

**Terminal 2: Ryu SDN Controller**
```bash
ryu-manager ryu.app.ofctl_rest ryu.app.simple_switch_13
```

**Terminal 3: Mininet (keep this open for attack simulation)**
```bash
sudo mn --topo single,3 --mac --switch ovsk --controller remote
```

### Phase 3 — Security & Dashboard

**Terminal 4: API & Dashboard Backend**
```bash
rm -f logs/response_audit.jsonl logs/dashboard_state.json
python api_server.py
```

**Terminal 5: Forensic AI Agent**
```bash
export GROQ_API_KEY="your_api_key_here"
python rca_agent.py
```

### Phase 4 — AI Pipeline

**Terminal 6: Master Orchestrator (ML Inference)**
```bash
python run_pipeline.py --skip-train --mode kafka
```

**Terminal 7: Live Packet Sniffer**
> Wait for Mininet (Terminal 3) to be fully running before executing this.

```bash
sudo python3 packet_sniffer.py --interface s1-eth1 --broker 127.0.0.1:9093
```

> 💡 Run `ip link show` to verify your Mininet interface name — it may be `s1-eth1` or `s1-eth3`.

---

## Simulating Attacks

### Method 1 — Live Network Attack (via Mininet CLI)

In **Terminal 3** (the Mininet CLI), run:

```bash
# Start a dummy listener on Host 2
mininet> h2 nc -l -p 80 > /dev/null &

# Launch a NoSQL Injection from Host 1 targeting Host 2
mininet> h1 curl -X POST http://10.0.0.2:80/nudm-sdm/ \
  -d '{"find": "NfProfile", "$or": [{"imsi-123": 1}]}'
```

### Method 2 — Synthetic API-Triggered Attack

Trigger a simulated attack directly against the Kafka stream:

```bash
curl -X POST http://127.0.0.1:5002/api/attack \
  -H "Content-Type: application/json" \
  -d '{"slice": 1, "attack": "nosql"}'
```

---

<img width="1600" height="836" alt="WhatsApp Image 2026-05-23 at 5 50 04 AM" src="https://github.com/user-attachments/assets/ba96a5a4-d508-4472-8a18-6dfcb46b92a6" />










## System Response Flow

Once an attack is triggered, SliceShield autonomously executes the following sequence:

```
Attack Detected
      │
      ▼
① DETECTION  ──── Sniffer captures payload → routed via Kafka
                   ML model flags anomaly in < 50ms
      │
      ▼
② RESPONSE   ──── Ryu SDN isolates the compromised slice
                   Dashboard indicator turns 🔴 RED
      │
      ▼
③ ANALYSIS   ──── RCA Agent reads audit logs
                   Llama-3 generates a forensic Markdown report
      │
      ▼
④ SELF-HEAL  ──── 5-second cooldown expires
                   Ryu lifts the isolation ban
                   Dashboard indicator turns 🟢 GREEN
```

---

*SliceShield — Securing the Sliced Future of 5G Networks*
