from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import time
import uuid
import json
import threading
import requests
import ai_model
from security import (
    apply_security_headers, rate_limiter, sanitize_input,
    validate_endpoint_id, perf_tracker, encryptor, ConnectionPool
)

app = Flask(__name__)
CORS(app)

# Apply security headers to every response
@app.after_request
def add_security_headers(response):
    return apply_security_headers(response)

# Rate limiting middleware
@app.before_request
def check_rate_limit():
    client_ip = request.remote_addr
    if not rate_limiter.is_allowed(client_ip):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

DB_PATH = 'analytics.db'
AGENT_AUTH_KEY = "nx-agent-secure-token-v1"

# Connection pool for high-throughput SQLite access
db_pool = ConnectionPool(DB_PATH, pool_size=5)

# To track when to update the AI baseline
payload_counters = {}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Enable WAL mode for concurrent reads
    c.execute("PRAGMA journal_mode=WAL")
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    endpoint_id TEXT,
                    timestamp REAL,
                    risk_level TEXT,
                    description TEXT,
                    details TEXT
                 )''')
    c.execute("DROP TABLE IF EXISTS metrics")
    c.execute('''CREATE TABLE metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint_id TEXT,
                    user_id TEXT,
                    timestamp REAL,
                    cpu_usage REAL,
                    memory_usage REAL,
                    network_tx REAL,
                    network_rx REAL,
                    active_processes TEXT,
                    recent_urls TEXT
                 )''')
    # Create indexes for faster queries
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_endpoint ON alerts(endpoint_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk_level)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_metrics_endpoint ON metrics(endpoint_id)")
    conn.commit()
    conn.close()

init_db()

def background_ai_training(endpoint_id, user_id):
    print(f"[*] Triggering AI Baseline Training for {endpoint_id} ({user_id})...")
    success = ai_model.update_baseline(endpoint_id, user_id)
    if success:
        print(f"[+] AI Baseline successfully updated and stored for {endpoint_id}")
    else:
        print(f"[-] AI Baseline training deferred (insufficient historical data)")

@app.route('/submit_metrics', methods=['POST'])
def submit_metrics():
    start_time = time.time()
    
    auth_header = request.headers.get("Authorization")
    if auth_header != f"Bearer {AGENT_AUTH_KEY}":
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400
    
    # Phase 12: Input Validation
    endpoint_id = data.get('endpoint_id', '')
    if not validate_endpoint_id(endpoint_id):
        return jsonify({"error": "Invalid endpoint_id"}), 400
        
    endpoint_id = data.get('endpoint_id')
    user_id = data.get('user_id')
    timestamp = data.get('timestamp')
    
    # Track payloads to periodically retrain AI
    key = f"{endpoint_id}_{user_id}"
    payload_counters[key] = payload_counters.get(key, 0) + 1
    
    # Store metrics in DB for historical ML
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO metrics 
                 (endpoint_id, user_id, timestamp, cpu_usage, memory_usage, 
                  network_tx, network_rx, active_processes, recent_urls) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (endpoint_id, user_id, timestamp, 
               data.get('cpu_usage'), data.get('memory_usage'),
               data.get('network_tx'), data.get('network_rx'),
               json.dumps(data.get('active_processes', [])),
               json.dumps(data.get('recent_urls', []))))
    
    # Analyze using the AI model
    alerts = ai_model.analyze_behavior(data)
    
    response_actions = []

    # Store generated alerts
    for alert in alerts:
        # Determine Automated Response Actions
        if alert['risk_level'] in ['Critical', 'High']:
            proc = alert.get('process_name', 'N/A')
            if proc not in ["N/A", "Unknown", "Unknown (AI Inferred)"]:
                response_actions.append({"action": "kill_process", "target": proc})
                
            if "isolate" in alert.get('remediation', '').lower() or alert['risk_level'] == 'Critical':
                if not any(a['action'] == 'isolate_network' for a in response_actions):
                    response_actions.append({"action": "isolate_network", "target": "all"})

        # Calculate Frequency
        c.execute("SELECT COUNT(*) FROM alerts WHERE endpoint_id=? AND description=?", (endpoint_id, alert["description"]))
        freq = c.fetchone()[0] + 1
        alert["frequency"] = freq
        alert["source_ip"] = request.remote_addr
        
        alert_id = str(uuid.uuid4())
        details_json = json.dumps(alert)
        
        c.execute("INSERT INTO alerts (id, endpoint_id, timestamp, risk_level, description, details) VALUES (?, ?, ?, ?, ?, ?)",
                  (alert_id, endpoint_id, timestamp, alert['risk_level'], alert['description'], details_json))
        
        # Log Alert to Blockchain Ledger
        try:
            requests.post("http://localhost:5002/log", json={
                "type": "ALERT",
                "alert_id": alert_id,
                "endpoint_id": endpoint_id,
                "timestamp": timestamp,
                "risk_level": alert['risk_level'],
                "details": alert
            }, timeout=2)
        except Exception as e:
            pass
            
    # Log Automated Actions to Blockchain
    for action in response_actions:
        try:
            requests.post("http://localhost:5002/log", json={
                "type": "AUTOMATED_RESPONSE",
                "endpoint_id": endpoint_id,
                "timestamp": timestamp,
                "action_taken": action['action'],
                "target": action['target']
            }, timeout=2)
        except Exception as e:
            pass
        
    conn.commit()
    conn.close()
    
    # Retrain AI baseline every 20 payloads to keep it continuously dynamic
    if payload_counters[key] % 20 == 0:
        threading.Thread(target=background_ai_training, args=(endpoint_id, user_id)).start()
        
    is_learning = payload_counters[key] < 20
    status = "learning (AI)" if is_learning else "monitoring (AI Active)"
    
    # Check for manual admin actions
    global pending_manual_actions
    if endpoint_id in pending_manual_actions and pending_manual_actions[endpoint_id]:
        response_actions.extend(pending_manual_actions[endpoint_id])
        pending_manual_actions[endpoint_id] = []
        
    return jsonify({
        "status": status, 
        "alerts_generated": len(alerts),
        "payloads_received": payload_counters[key],
        "response_actions": response_actions
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, endpoint_id, timestamp, risk_level, description, details FROM alerts ORDER BY timestamp DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    
    alerts = []
    for r in rows:
        alerts.append({
            "id": r[0],
            "endpoint_id": r[1],
            "timestamp": r[2],
            "risk_level": r[3],
            "description": r[4],
            "details": r[5]
        })
        
    return jsonify(alerts)

@app.route('/api/endpoints', methods=['GET'])
def get_endpoints():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT endpoint_id, MAX(timestamp), cpu_usage, memory_usage, user_id 
                 FROM metrics GROUP BY endpoint_id''')
    rows = c.fetchall()
    conn.close()
    
    endpoints = []
    for r in rows:
        ep_id = r[0]
        uid = r[4]
        key = f"{ep_id}_{uid}"
        count = payload_counters.get(key, 0)
        status_text = "Online (AI Learning...)" if count < 20 else "Online (AI Protected)"
        if (time.time() - r[1]) >= 30:
            status_text = "Offline"
            
        endpoints.append({
            "endpoint_id": ep_id,
            "last_seen": r[1],
            "cpu_usage": round(r[2], 1) if r[2] else 0,
            "memory_usage": round(r[3], 1) if r[3] else 0,
            "status": status_text
        })
        
    return jsonify(endpoints)

pending_manual_actions = {}

@app.route('/api/alerts/resolve/<alert_id>', methods=['POST'])
def resolve_alert(alert_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM alerts WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    
    try:
        requests.post("http://localhost:5002/log", json={
            "type": "ADMIN_ACTION", "action": "RESOLVE_ALERT", "alert_id": alert_id, "timestamp": time.time()
        }, timeout=2)
    except: pass
    return jsonify({"status": "success"})

@app.route('/api/endpoints/isolate/<endpoint_id>', methods=['POST'])
def isolate_endpoint(endpoint_id):
    global pending_manual_actions
    pending_manual_actions[endpoint_id] = pending_manual_actions.get(endpoint_id, [])
    pending_manual_actions[endpoint_id].append({"action": "isolate_network", "target": "all"})
    
    try:
        requests.post("http://localhost:5002/log", json={
            "type": "ADMIN_ACTION", "action": "MANUAL_ISOLATION", "endpoint_id": endpoint_id, "timestamp": time.time()
        }, timeout=2)
    except: pass
    return jsonify({"status": "isolation_pending"})

@app.route('/api/chat', methods=['POST'])
def chat():
    import chatbot
    data = request.json
    if not data or 'message' not in data:
        return jsonify({"error": "No message provided"}), 400
    
    # Phase 12: Sanitize user input
    user_message = sanitize_input(data['message'], max_length=500)
    response = chatbot.process_query(user_message)
    return jsonify({"response": response})

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for high-availability monitoring."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("SELECT 1")
        conn.close()
        db_status = "healthy"
    except:
        db_status = "unhealthy"
    
    return jsonify({
        "status": "online",
        "service": "analytics_engine",
        "database": db_status,
        "uptime": time.time(),
        "active_endpoints": len(payload_counters),
        "performance": perf_tracker.get_stats()
    })

@app.route('/api/performance', methods=['GET'])
def get_performance():
    """Returns real-time performance metrics."""
    return jsonify(perf_tracker.get_stats())

if __name__ == '__main__':
    print("[*] Starting Analytics Engine with AI Behavior Learning on port 5001...")
    app.run(port=5001, threaded=True)
