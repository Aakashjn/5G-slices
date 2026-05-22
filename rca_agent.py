import os
import time
import json
import requests
from datetime import datetime

LOG_FILE = "logs/response_audit.jsonl"

def generate_rca(event_data):
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[ERROR] Invalid GROQ_API_KEY. Set it first.")
        return

    print(f"\n[RCA Agent] Analyzing attack on Slice {event_data.get('slice_id')} via Groq (Llama 3)...")
    
    prompt = f"""
    You are an expert 5G Core Cybersecurity Analyst. 
    Review the following automated slice isolation log and generate a concise Root Cause Analysis (RCA) report in Markdown.
    Focus on the attack type, probability, and the IoCs (Indicators of Compromise).
    
    LOG DATA:
    {json.dumps(event_data, indent=2)}
    """

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.1-8b-instant", 
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        report = response.json()["choices"][0]["message"]["content"]
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        out_file = f"RCA_Report_Slice{event_data.get('slice_id')}_{timestamp}.md"
        
        with open(out_file, "w") as f:
            f.write(report)
            
        print(f"[SUCCESS] RCA Report saved to: {out_file}\n")
        print(report)
        
    except Exception as e:
        print(f"\n[ERROR] Failed to contact Groq API: {e}\n")

def watch_logs():
    print(f"[*] RCA Agent Active. Watching {LOG_FILE} for new isolations...")
    if not os.path.exists("logs"): os.makedirs("logs")
    if not os.path.exists(LOG_FILE): open(LOG_FILE, 'a').close()

    with open(LOG_FILE, "r") as f:
        # Move the pointer to the end of the file so we only catch NEW attacks
        f.seek(0, 2) 
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            
            try:
                event = json.loads(line)
                # Only trigger on actual isolations, ignore readmissions
                if event.get("event") == "slice_isolated":
                    print("\n" + "="*60)
                    print("[!] New Slice Isolation Detected! Triggering Analysis...")
                    generate_rca(event)
                    print("="*60)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    watch_logs()
