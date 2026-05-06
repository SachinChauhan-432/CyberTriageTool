from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import time
import uuid
import json
import threading
import requests
import os
from pathlib import Path
from dotenv import load_dotenv
import ai_model
from security import (
    apply_security_headers, rate_limiter, sanitize_input,
    validate_endpoint_id, perf_tracker, encryptor, ConnectionPool
)

# Load environment variables from project root
dotenv_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(dotenv_path=dotenv_path)

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
AGENT_AUTH_KEY = os.getenv("AGENT_AUTH_TOKEN", "nx-agent-secure-token-v1")
ANALYTICS_PORT = os.getenv("ANALYTICS_PORT", "5001")

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
    
    # Feature 8: Backend Extension for False Positives
    c.execute('''CREATE TABLE IF NOT EXISTS false_positives (
                    id TEXT PRIMARY KEY,
                    process_name TEXT,
                    destination_ip TEXT,
                    description TEXT
                 )''')
                 
    # Feature 5: Admin Access Registered Endpoints
    c.execute('''CREATE TABLE IF NOT EXISTS registered_endpoints (
                    mac_address TEXT PRIMARY KEY,
                    device_name TEXT
                 )''')
                 
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

def background_blockchain_log(log_data):
    """Logs data to the blockchain service in the background to prevent blocking the main thread."""
    try:
        # Use the port from env for the blockchain service too
        BLOCKCHAIN_PORT = os.getenv("BLOCKCHAIN_PORT", "5002")
        requests.post(f"http://localhost:{BLOCKCHAIN_PORT}/log", json=log_data, timeout=3)
    except Exception:
        pass

@app.route('/submit_baseline', methods=['POST'])
def submit_baseline():
    auth_header = request.headers.get("Authorization")
    if auth_header != f"Bearer {AGENT_AUTH_KEY}":
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    endpoint_id = data.get('endpoint_id')
    user_id = data.get('user_id')
    historical_activity = data.get('historical_activity', [])
    
    if historical_activity:
        ai_model.update_baseline_from_historical(endpoint_id, user_id, historical_activity)
        
    return jsonify({"status": "success"})

@app.route('/submit_metrics', methods=['POST'])
def submit_metrics():
    start_time = time.time()
    
    auth_header = request.headers.get("Authorization")
    if auth_header != f"Bearer {AGENT_AUTH_KEY}":
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400
    
    endpoint_id = data.get('endpoint_id', '')
    if not validate_endpoint_id(endpoint_id):
        return jsonify({"error": "Invalid endpoint_id"}), 400
        
    user_id = data.get('user_id')
    timestamp = data.get('timestamp')
    
    # Track payloads to periodically retrain AI
    key = f"{endpoint_id}_{user_id}"
    payload_counters[key] = payload_counters.get(key, 0) + 1
    
    is_learning = payload_counters[key] < 20
    
    conn = db_pool.get_connection()
    try:
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
        
        # Analyze using the AI model, passing the learning phase flag
        alerts = ai_model.analyze_behavior(data, is_learning)
        
        response_actions = []

        for alert in alerts:
            if alert['risk_level'] in ['Critical', 'High']:
                proc = alert.get('process_name', 'N/A')
                if proc not in ["N/A", "Unknown", "Unknown (AI Inferred)"]:
                    response_actions.append({"action": "kill_process", "target": proc})
                    
                if "isolate" in alert.get('remediation', '').lower() or alert['risk_level'] == 'Critical':
                    if not any(a['action'] == 'isolate_network' for a in response_actions):
                        response_actions.append({"action": "isolate_network", "target": "all"})

            c.execute("SELECT COUNT(*) FROM alerts WHERE endpoint_id=? AND description=?", (endpoint_id, alert["description"]))
            freq = c.fetchone()[0] + 1
            alert["frequency"] = freq
            alert["source_ip"] = request.remote_addr
            
            alert_id = str(uuid.uuid4())
            details_json = json.dumps(alert)
            
            c.execute("INSERT INTO alerts (id, endpoint_id, timestamp, risk_level, description, details) VALUES (?, ?, ?, ?, ?, ?)",
                      (alert_id, endpoint_id, timestamp, alert['risk_level'], alert['description'], details_json))
            
            # Log Alert to Blockchain Ledger (ASYNC)
            threading.Thread(target=background_blockchain_log, args=({
                "type": "ALERT",
                "alert_id": alert_id,
                "endpoint_id": endpoint_id,
                "timestamp": timestamp,
                "risk_level": alert['risk_level'],
                "details": alert
            },)).start()
                
        # Log Automated Actions to Blockchain (ASYNC)
        for action in response_actions:
            threading.Thread(target=background_blockchain_log, args=({
                "type": "AUTOMATED_RESPONSE",
                "endpoint_id": endpoint_id,
                "timestamp": timestamp,
                "action_taken": action['action'],
                "target": action['target']
            },)).start()
            
        conn.commit()
        
        # Retrain AI baseline every 20 payloads
        if payload_counters[key] % 20 == 0:
            threading.Thread(target=background_ai_training, args=(endpoint_id, user_id)).start()
            
        is_learning = payload_counters[key] < 20
        status = "learning (AI)" if is_learning else "monitoring (AI Active)"
        
        global pending_manual_actions
        if endpoint_id in pending_manual_actions and pending_manual_actions[endpoint_id]:
            response_actions.extend(pending_manual_actions[endpoint_id])
            pending_manual_actions[endpoint_id] = []
            
        perf_tracker.record("submit_metrics", (time.time() - start_time) * 1000)
        
        return jsonify({
            "status": status, 
            "alerts_generated": len(alerts),
            "payloads_received": payload_counters[key],
            "response_actions": response_actions
        })
    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        print(f"CRITICAL ERROR in submit_metrics:\n{error_msg}")
        return jsonify({"error": "Internal Processing Error", "details": str(e)}), 500
    finally:
        db_pool.return_connection(conn)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        
        # Load False Positives patterns
        c.execute("SELECT process_name, destination_ip, description FROM false_positives")
        fp_patterns = c.fetchall()
        
        c.execute("SELECT id, endpoint_id, timestamp, risk_level, description, details FROM alerts ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall()
        
        alerts = []
        for r in rows:
            alert_id, endpoint_id, timestamp, risk_level, description, details_json = r
            details = {}
            try:
                details = json.loads(details_json)
            except:
                pass
                
            process_name = details.get('process_name', 'N/A')
            dest_ip = details.get('destination_ip', 'N/A')
            
            # Check if alert matches any False Positive pattern
            is_fp = False
            for fp in fp_patterns:
                if fp[0] == process_name and fp[1] == dest_ip and fp[2] == description:
                    is_fp = True
                    break
                    
            if is_fp:
                risk_level = 'Low'
                details['is_resolved'] = True
                details['resolved_reason'] = "Auto-downgraded (False Positive Pattern)"
                
            alerts.append({
                "id": alert_id, "endpoint_id": endpoint_id, "timestamp": timestamp,
                "risk_level": risk_level, "description": description, "details": json.dumps(details)
            })
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_pool.return_connection(conn)

@app.route('/api/alerts/resolve/<alert_id>', methods=['POST'])
def resolve_alert(alert_id):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT details FROM alerts WHERE id=?", (alert_id,))
        row = c.fetchone()
        if not row:
            return jsonify({"error": "Alert not found"}), 404
            
        details = json.loads(row[0])
        details['is_resolved'] = True
        details['resolved_reason'] = "Manually Resolved"
        
        c.execute("UPDATE alerts SET risk_level='Low', details=? WHERE id=?", (json.dumps(details), alert_id))
        conn.commit()
        
        threading.Thread(target=background_blockchain_log, args=({
            "type": "ADMIN_ACTION", "action": "RESOLVE_ALERT", "alert_id": alert_id, "timestamp": time.time()
        },)).start()
        return jsonify({"status": "success"})
    finally:
        db_pool.return_connection(conn)

@app.route('/api/alerts/false_positive/<alert_id>', methods=['POST'])
def mark_false_positive(alert_id):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT description, details FROM alerts WHERE id=?", (alert_id,))
        row = c.fetchone()
        if not row:
            return jsonify({"error": "Alert not found"}), 404
            
        description = row[0]
        details = json.loads(row[1])
        process_name = details.get('process_name', 'N/A')
        dest_ip = details.get('destination_ip', 'N/A')
        
        # Insert pattern into false_positives table
        fp_id = str(uuid.uuid4())
        c.execute("INSERT OR IGNORE INTO false_positives (id, process_name, destination_ip, description) VALUES (?, ?, ?, ?)",
                  (fp_id, process_name, dest_ip, description))
                  
        # Update the alert itself
        details['is_resolved'] = True
        details['resolved_reason'] = "Marked as False Positive"
        c.execute("UPDATE alerts SET risk_level='Low', details=? WHERE id=?", (json.dumps(details), alert_id))
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        db_pool.return_connection(conn)

@app.route('/api/endpoints', methods=['GET'])
def get_endpoints():
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute('''SELECT endpoint_id, MAX(timestamp), cpu_usage, memory_usage, user_id 
                     FROM metrics GROUP BY endpoint_id''')
        rows = c.fetchall()
        
        endpoints = []
        now = time.time()
        for r in rows:
            ep_id, last_seen, cpu, mem, uid = r
            key = f"{ep_id}_{uid}"
            count = payload_counters.get(key, 0)
            
            if (now - last_seen) >= 30:
                status_text = "OFFLINE"
            else:
                status_text = "LEARNING" if count < 20 else "PROTECTED"
                
            endpoints.append({
                "endpoint_id": ep_id,
                "last_seen": last_seen,
                "cpu_usage": round(cpu, 1) if cpu else 0,
                "memory_usage": round(mem, 1) if mem else 0,
                "status": status_text,
                "learning_progress": min(100, int((count / 20.0) * 100))
            })
        return jsonify(endpoints)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_pool.return_connection(conn)

@app.route('/api/endpoints/register', methods=['POST'])
def register_endpoint():
    conn = db_pool.get_connection()
    try:
        data = request.json
        mac = data.get('mac_address')
        name = data.get('device_name')
        if not mac or not name:
            return jsonify({"error": "Missing mac_address or device_name"}), 400
            
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO registered_endpoints (mac_address, device_name) VALUES (?, ?)", (mac, name))
        conn.commit()
        return jsonify({"status": "success", "message": f"Endpoint {name} registered."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_pool.return_connection(conn)

@app.route('/api/endpoints/<mac>', methods=['DELETE'])
def remove_endpoint(mac):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM registered_endpoints WHERE mac_address=?", (mac,))
        conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_pool.return_connection(conn)

@app.route('/api/endpoints/registered', methods=['GET'])
def get_registered_endpoints():
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT mac_address, device_name FROM registered_endpoints")
        rows = c.fetchall()
        return jsonify([{"mac_address": r[0], "device_name": r[1]} for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_pool.return_connection(conn)

pending_manual_actions = {}

@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM alerts")
        conn.commit()
        
        threading.Thread(target=background_blockchain_log, args=({
            "type": "ADMIN_ACTION", "action": "CLEAR_ALL_ALERTS", "timestamp": time.time()
        },)).start()
        return jsonify({"status": "success"})
    finally:
        db_pool.return_connection(conn)

@app.route('/api/endpoints/isolate/<endpoint_id>', methods=['POST'])
def isolate_endpoint(endpoint_id):
    global pending_manual_actions
    pending_manual_actions[endpoint_id] = pending_manual_actions.get(endpoint_id, [])
    pending_manual_actions[endpoint_id].append({"action": "isolate_network", "target": "all"})
    
    threading.Thread(target=background_blockchain_log, args=({
        "type": "ADMIN_ACTION", "action": "MANUAL_ISOLATION", "endpoint_id": endpoint_id, "timestamp": time.time()
    },)).start()
    return jsonify({"status": "isolation_pending"})

@app.route('/api/chat', methods=['POST'])
def chat():
    import chatbot
    data = request.json
    if not data or 'message' not in data:
        return jsonify({"error": "No message provided"}), 400
    
    user_message = sanitize_input(data['message'], max_length=500)
    response = chatbot.process_query(user_message)
    return jsonify({"response": response})

@app.route('/health', methods=['GET'])
def health_check():
    try:
        conn = db_pool.get_connection()
        conn.execute("SELECT 1")
        db_pool.return_connection(conn)
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

if __name__ == '__main__':
    print(f"[*] Starting Analytics Engine on port {ANALYTICS_PORT}...")
    app.run(port=int(ANALYTICS_PORT), threaded=True)
