"""
run_pipeline.py - Master Orchestrator
"""
import os
import sys
import time
import argparse
from datetime import datetime

# GLOBAL VARIABLE to allow api_server.py to access the engine
response_engine_instance = None

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           Edge AI for 5G Network Slice Security              ║ 
╚══════════════════════════════════════════════════════════════╝
"""

def print_stage(layer, name, icon):
    print(f"\n{'═'*62}\n  {icon}  {layer} — {name}\n{'═'*62}")

def run_stage_3_4_detect_and_respond(mode="demo"):
    global response_engine_instance
    print_stage("Layer 3+4", "Detection + Response", "🔍🛡")
    print("  [System] Waiting 5s for SDN Controller to initialize...")
    time.sleep(5)
    
    import detection_engine
    import response_engine
    
    # 1. Store the responder in the global variable so api_server.py can find it
    response_engine_instance = response_engine.run()
    
    # 2. Start detection, linking the alert callback AND the recovery monitor
    engine = detection_engine.run(
        mode=mode, 
        alert_callback=response_engine_instance.handle_alert,
        recovery_monitor=response_engine_instance.recovery # This is the crucial link!
    )
    return engine, response_engine_instance

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-train", action="store_true")
    parser.add_argument("--mode", choices=["demo", "kafka"], default="demo")
    args = parser.parse_args()

    print(f"  Mode: {args.mode} | Started: {datetime.now().strftime('%H:%M:%S')}")
    
    # Import and run previous stages
    import data_pipeline; data_pipeline.run()
    if not args.skip_train:
        import fl_trainer; fl_trainer.run()
    
    try:
        # Run detection and response
        detect_engine, responder = run_stage_3_4_detect_and_respond(args.mode)
        
        # Keep the main process alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n  Pipeline stopped.")

if __name__ == "__main__":
    main()
