from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import json
import subprocess

app = Flask(__name__)
CORS(app)

@app.route('/api/logs')
def get_logs():
    logs = []
    log_path = 'logs/response_audit.jsonl'
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return jsonify(logs)

@app.route('/api/rca/<int:slice_id>')
def get_rca(slice_id):
    # Searches for the most recent RCA report for the given slice
    reports = [f for f in os.listdir('.') if f.startswith(f'RCA_Report_Slice{slice_id}')]
    if not reports:
        return jsonify({"report": "No RCA report available yet."})
    latest_report = sorted(reports)[-1]
    with open(latest_report, 'r') as f:
        return jsonify({"report": f.read()})

@app.route('/api/attack', methods=['POST'])
def trigger_attack():
    data = request.json
    slice_id = data.get('slice', 1)
    attack_type = data.get('attack', 'nosql')
    subprocess.Popen(['python', 'attack_simulation.py', '--slice', str(slice_id), '--attack', attack_type])
    return jsonify({"status": "success", "message": "Attack injected"})

if __name__ == '__main__':
    app.run(port=5002)
