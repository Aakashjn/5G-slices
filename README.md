
# SliceShield: AI-Driven 5G Network Slice Security

## Overview

SliceShield is an end-to-end security platform for 5G network slicing. It leverages **Federated Learning** for distributed anomaly detection at the edge and an **SDN (Software Defined Networking)** controller for real-time threat mitigation. The system features automated isolation, forensic RCA (Root Cause Analysis), and self-healing (automated recovery).

## Project Architecture

## Component Breakdown

| File | Role |
| --- | --- |
| `run_pipeline.py` | Orchestrates the entire execution flow (Data, Training, Detection). |
| `data_pipeline.py` | Generates training datasets (malicious/benign) for specific slices. |
| `fl_trainer.py` | Executes the Federated Learning training process to generate the model. |
| `detection_engine.py` | Real-time inference engine consuming Kafka streams; triggers SDN isolation. |
| `response_engine.py` | Manages SDN flows and automated recovery/restoration logic. |
| `rca_agent.py` | AI-powered forensics agent using Groq/LLMs to generate incident reports. |
| `api_server.py` | Flask backend serving log data and RCA reports to the dashboard. |
| `packet_sniffer.py` | Captures SBI/5G traffic from the VM and publishes it to Kafka. |

## Quick Start Guide

### 1. Prerequisites

* Mininet (with Ryu SDN Controller)
* Docker & Docker Compose
* Python 3.x with dependencies: `pip install flwr torch pandas numpy requests flask flask-cors kafka-python`

### 2. Setup Infrastructure

```bash
# Start Kafka broker and supporting infrastructure
sudo docker compose up -d

```

### 3. Execution Order

**Terminal 1 (Detection/Response):**

```bash
python run_pipeline.py --skip-train --mode kafka

```

**Terminal 2 (Forensics Agent):**

```bash
export GROQ_API_KEY="your_api_key_here"
python rca_agent.py

```

**Terminal 3 (Dashboard API):**

```bash
python api_server.py

```

**VM Terminal (Sensor Layer):**

```bash
# Replace interface and broker IP with your environment settings
sudo python3 packet_sniffer.py --interface s1-eth3 --broker <LAPTOP_IP>:9093

```

## How it works (Demo Flow)

1. **Attack Injection:** Use the dashboard buttons to trigger synthetic attack traffic from Mininet.
2. **Detection:** The `detection_engine` identifies the anomaly in <50ms.
3. **Response:** SDN controller isolates the slice. Dashboard turns **RED**.
4. **Analysis:** `rca_agent` automatically analyzes the attack using LLMs.
5. **Recovery:** The system automatically restores the slice and clears flows after the cooldown period. Dashboard turns **GREEN**.


( i hv used VM and laptop ubuntu . and bridged them for communication has my ryu and mininet were in VM and the detection and run_piprlne .py were in laptop ubuntu)


(for running everything in ubuntu  itself )

# SliceShield: AI-Driven 5G Network Slice Security

### ISP81 | Dept. of ISE

## Overview

SliceShield is an end-to-end security platform for 5G network slicing. It leverages **Federated Learning** for distributed anomaly detection and an **SDN (Ryu)** controller for real-time threat mitigation.

## Project Architecture

## Running in Your Environment

Since the project runs on Ubuntu (with Mininet/Ryu and the Detection Engine on the same machine), use the following configuration:

### 1. Requirements

* **OS:** Ubuntu 22.04+
* **Network:** Mininet, Ryu Controller, Docker
* **Python:** 3.10+
* **Environment:** Create a virtual environment (`venv`) to avoid system package conflicts.

### 2. Execution Flow

Run these in separate terminal tabs in your `5gdemo` folder:

| Terminal | Task | Command |
| --- | --- | --- |
| **Terminal 1** | **SDN Controller** | `ryu-manager ryu.app.ofctl_rest ryu.app.simple_switch_13` |
| **Terminal 2** | **Mininet** | `sudo mn --topo single,3 --mac --switch ovsk --controller remote` |
| **Terminal 3** | **Kafka/Docker** | `sudo docker compose up -d` |
| **Terminal 4** | **Pipeline** | `python run_pipeline.py --skip-train --mode kafka` |
| **Terminal 5** | **Forensics** | `export GROQ_API_KEY="your_key" && python rca_agent.py` |
| **Terminal 6** | **API Server** | `python api_server.py` |
| **Terminal 7** | **Packet Sniffer** | `sudo python3 packet_sniffer.py --interface s1-eth1 --broker localhost:9093` |

*Note: In `packet_sniffer.py`, ensure the `--interface` matches the bridge interface created by Mininet (usually `s1-eth1` or `s1-eth3`).*

## Key Differences for your Team

* **No Remote IP Needed:** Because Ryu, Mininet, and the Pipeline are on the same machine, you can use `localhost` for all connections (Kafka, API, and SDN Controller).
* **Interface Visibility:** When you run `sudo mn`, Mininet creates virtual interfaces. Use `ifconfig` in a separate terminal to ensure you are sniffing the correct switch port.
* **RCA Integration:** The `rca_agent.py` reads logs from `logs/response_audit.jsonl`. Since this is a local file, ensure your team has read/write permissions for the `logs/` directory.

## File Context

* **`run_pipeline.py`**: The "Master Switch." Use this to start the detection loop.
* **`packet_sniffer.py`**: The "Eyes." It watches the Mininet switch and pipes data to Kafka.
* **`api_server.py`**: The "Bridge." Connects the dashboard to your logs.
* **`detection_engine.py`**: The "Brain." Includes the `_auto_recover` function which talks to your Ryu controller via `requests.delete` to clear SDN flows.


