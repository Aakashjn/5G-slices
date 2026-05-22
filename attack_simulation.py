import json
import argparse
from datetime import datetime

def simulate_attack(slice_id, attack_type):
    print(f"\n[⚔️] INJECTING SYNTHETIC ATTACK VECTOR...")
    print(f"     Target : Slice {slice_id}")
    print(f"     Payload: {attack_type.upper()}")
    
    # Craft a live detection & isolation event
    event = {
        "event": "slice_isolated",
        "timestamp": datetime.now().isoformat(),
        "slice_id": slice_id,
        "slice_name": {0: "eMBB", 1: "URLLC", 2: "mMTC"}.get(slice_id, "unknown"),
        "attack_type": attack_type,
        "avg_prob": 0.96,
        "iocs": [
            f"Simulated {attack_type.upper()} payload detected via CLI",
            "Threshold exceeded: 0.96 > 0.65"
        ],
        "detect_ms": 2.1,
        "isolate_ms": 38.4,
        "total_ms": 40.5,
        "sdn": {"status": "isolated", "latency_ms": 38.4}
    }
    
    with open("logs/response_audit.jsonl", "a") as f:
        f.write(json.dumps(event) + "\n")
        
    print("[✓] Attack payload delivered! Check dashboard and RCA agent.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--slice", type=int, default=1)
    parser.add_argument("--attack", type=str, default="nosql")
    args = parser.parse_args()
    simulate_attack(args.slice, args.attack)
