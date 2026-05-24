from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import json

app = Flask(__name__)
CORS(app)

# CRITICAL: Prevent browser caching so the UI instantly updates to GREEN
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

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
    
    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers='10.184.141.151:9093',
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        producer.send('slice-telemetry', {
            "slice_id": slice_id,
            "features": [0.95] * 20, 
            "attack_type": attack_type
        })
        producer.flush()
        producer.close()
        return jsonify({"status": "success", "message": "Attack injected into Kafka stream"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/status')
def get_status():
    # Read the state directly from the JSON file!
    state_file = 'logs/dashboard_state.json'
    try:
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                return jsonify(json.load(f))
    except Exception:
        pass
    return jsonify({"0": "NORMAL", "1": "NORMAL", "2": "NORMAL"})

if __name__ == '__main__':
    app.run(port=5002)
