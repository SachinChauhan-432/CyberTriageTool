from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import requests
import os
import time

app = Flask(__name__, static_folder='../../dashboard')
CORS(app)

ANALYTICS_URL = "http://localhost:5001"
BLOCKCHAIN_URL = "http://localhost:5002"

# ============================================================
# Phase 12: Security Headers
# ============================================================
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ============================================================
# Static File Serving
# ============================================================
@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# ============================================================
# API Proxies
# ============================================================
@app.route('/api/alerts', methods=['GET'])
def proxy_alerts():
    try:
        resp = requests.get(f"{ANALYTICS_URL}/api/alerts", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": "Analytics Engine is offline"}), 503

@app.route('/api/endpoints', methods=['GET'])
def proxy_endpoints():
    try:
        resp = requests.get(f"{ANALYTICS_URL}/api/endpoints", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": "Analytics Engine is offline"}), 503

@app.route('/api/blockchain', methods=['GET'])
def proxy_blockchain():
    try:
        resp = requests.get(f"{BLOCKCHAIN_URL}/ledger", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": "Blockchain Logger is offline"}), 503

@app.route('/api/alerts/resolve/<alert_id>', methods=['POST'])
def proxy_resolve_alert(alert_id):
    try:
        resp = requests.post(f"{ANALYTICS_URL}/api/alerts/resolve/{alert_id}", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": "Analytics Engine is offline"}), 503

@app.route('/api/alerts/false_positive/<alert_id>', methods=['POST'])
def proxy_mark_false_positive(alert_id):
    try:
        resp = requests.post(f"{ANALYTICS_URL}/api/alerts/false_positive/{alert_id}", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": "Analytics Engine is offline"}), 503

@app.route('/api/endpoints/isolate/<endpoint_id>', methods=['POST'])
def proxy_isolate_endpoint(endpoint_id):
    try:
        resp = requests.post(f"{ANALYTICS_URL}/api/endpoints/isolate/{endpoint_id}", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": "Analytics Engine is offline"}), 503

@app.route('/api/chat', methods=['POST'])
def proxy_chat():
    try:
        resp = requests.post(f"{ANALYTICS_URL}/api/chat", json=request.json, timeout=10)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": "Analytics Engine is offline"}), 503

# ============================================================
# Phase 12: Health Check (Aggregated)
# ============================================================
@app.route('/api/health', methods=['GET'])
def health():
    """Aggregated health check across all microservices."""
    services = {}
    
    try:
        r = requests.get(f"{ANALYTICS_URL}/health", timeout=3)
        services["analytics_engine"] = r.json() if r.status_code == 200 else {"status": "degraded"}
    except:
        services["analytics_engine"] = {"status": "offline"}
    
    try:
        r = requests.get(f"{BLOCKCHAIN_URL}/verify", timeout=3)
        bc = r.json()
        services["blockchain_logger"] = {"status": "online", "chain_valid": bc.get("is_valid", False)}
    except:
        services["blockchain_logger"] = {"status": "offline"}
    
    all_online = all(s.get("status") in ["online", "healthy"] for s in services.values())
    
    return jsonify({
        "platform": "NexusGuard",
        "status": "healthy" if all_online else "degraded",
        "timestamp": time.time(),
        "services": services
    })

if __name__ == '__main__':
    print("[*] Starting API Gateway on port 5000...")
    app.run(port=5000, threaded=True)
