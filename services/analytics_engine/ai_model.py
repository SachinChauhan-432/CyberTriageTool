import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os
import json
from threat_intel import ti_engine

BASELINES_DIR = 'baselines'
os.makedirs(BASELINES_DIR, exist_ok=True)

DB_PATH = 'analytics.db'

def get_model_path(endpoint_id, user_id):
    safe_end = "".join([c for c in endpoint_id if c.isalnum()])
    safe_usr = "".join([c for c in user_id if c.isalnum()])
    return os.path.join(BASELINES_DIR, f"{safe_end}_{safe_usr}_model.joblib")

def get_profile_path(endpoint_id, user_id):
    safe_end = "".join([c for c in endpoint_id if c.isalnum()])
    safe_usr = "".join([c for c in user_id if c.isalnum()])
    return os.path.join(BASELINES_DIR, f"{safe_end}_{safe_usr}_profile.json")

def load_categorical_profile(endpoint_id, user_id):
    path = get_profile_path(endpoint_id, user_id)
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[-] Error loading profile: {e}")
            return {"processes": [], "ips": []}
    return {"processes": [], "ips": []}

def save_categorical_profile(endpoint_id, user_id, profile):
    path = get_profile_path(endpoint_id, user_id)
    with open(path, 'w') as f:
        json.dump(profile, f)

def update_baseline(endpoint_id, user_id):
    """
    Train/Retrain the Isolation Forest model using historical data for the specific endpoint and user.
    Called periodically to ensure dynamic adaptation.
    """
    conn = sqlite3.connect(DB_PATH)
    query = '''SELECT cpu_usage, memory_usage, network_tx, network_rx 
               FROM metrics 
               WHERE endpoint_id=? AND user_id=?
               ORDER BY timestamp DESC LIMIT 500'''
               
    df = pd.read_sql_query(query, conn, params=(endpoint_id, user_id))
    conn.close()
    
    if len(df) < 20: # Need minimum data points to train
        return False
        
    # Isolation Forest for continuous anomaly detection
    # contamination=0.05 means we assume 5% of the historical data might be anomalies
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df)
    
    # Save the model securely
    model_path = get_model_path(endpoint_id, user_id)
    joblib.dump(model, model_path)
    
    # Process historical categorical data to build known profile
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT active_processes, recent_urls 
                 FROM metrics 
                 WHERE endpoint_id=? AND user_id=?
                 ORDER BY timestamp DESC LIMIT 500''', (endpoint_id, user_id))
    rows = c.fetchall()
    conn.close()
    
    known_procs = set()
    known_ips = set()
    
    for r in rows:
        if r[0]:
            try:
                known_procs.update(json.loads(r[0]))
            except: pass
        if r[1]:
            try:
                known_ips.update(json.loads(r[1]))
            except: pass
            
    profile = {
        "processes": list(known_procs),
        "ips": list(known_ips)
    }
    save_categorical_profile(endpoint_id, user_id, profile)
    return True

def update_baseline_from_historical(endpoint_id, user_id, historical_data):
    """
    Phase 5: Baseline Learning Engine (Historical Data Ingestion)
    Parses Windows Activity data to build a baseline of normal app usage.
    """
    profile = load_categorical_profile(endpoint_id, user_id)
    known_procs = set(profile.get("processes", []))
    
    for entry in historical_data:
        app = entry.get("app_name")
        if app and app.lower() not in [p.lower() for p in known_procs]:
            known_procs.add(app)
            
    profile["processes"] = list(known_procs)
    save_categorical_profile(endpoint_id, user_id, profile)
    print(f"[+] AI Model learned {len(known_procs)} safe applications from Historical Activity.")

SUSPICIOUS_PROCS = ["miner", "hack", "mimikatz", "ncat", "nc.exe", "crypto", "ransom", "payload", "cmd.exe", "powershell.exe"]

def analyze_behavior(data, is_learning=False):
    """
    Uses the trained ML model and learned categorical profile to detect anomalies.
    Classifies anomalies by severity (Low, Medium, High, Critical) and returns structured intelligent alerts.
    """
    endpoint_id = data.get('endpoint_id')
    user_id = data.get('user_id')
    alerts = []
    
    model_path = get_model_path(endpoint_id, user_id)
    profile = load_categorical_profile(endpoint_id, user_id)
    
    cpu = data.get('cpu_usage', 0)
    mem = data.get('memory_usage', 0)
    net_tx = data.get('network_tx', 0)
    net_rx = data.get('network_rx', 0)
    
    metrics_str = f"CPU: {cpu}% | Mem: {mem}% | Net Tx: {net_tx}MB/s"
    
    def create_alert(risk, desc, dest_ip, proc, cause, remediate):
        return {
            "risk_level": risk,
            "description": desc,
            "destination_ip": dest_ip,
            "process_name": proc,
            "metrics": metrics_str,
            "root_cause": cause,
            "remediation": remediate
        }
        
    # 0. Phase 7: Threat Intelligence & Signature-Based Detection
    current_procs = data.get('active_processes', [])
    current_ips = data.get('recent_urls', [])
    
    # Check Processes against Threat Intel
    for p in current_procs:
        ti_match = ti_engine.check_process(p)
        if ti_match["is_malicious"]:
            alerts.append(create_alert(
                "Critical", 
                f"Known Malware Signature: {p}", 
                "N/A", 
                p, 
                f"Process matches known threat: {ti_match['threat_name']}", 
                "1. IMMEDIATELY isolate endpoint. 2. Terminate process. 3. Initiate full incident response."
            ))
            
    # Check IPs against Threat Intel
    for ip in current_ips:
        ti_match = ti_engine.check_ip(ip)
        if ti_match["is_malicious"]:
            alerts.append(create_alert(
                "Critical", 
                f"Malicious Infrastructure Connection", 
                ip, 
                "Unknown", 
                f"IP matches known threat database: {ti_match['threat_name']}", 
                "1. Isolate endpoint. 2. Block IP on firewall. 3. Scan for active beacons."
            ))
    
    # 1. Continuous Metrics AI Analysis (Unusual CPU spikes, etc)
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            X_new = pd.DataFrame([{'cpu_usage': cpu, 'memory_usage': mem, 'network_tx': net_tx, 'network_rx': net_rx}])
            
            # Predict: 1 is normal, -1 is anomaly
            prediction = model.predict(X_new)[0]
            if prediction == -1:
                if cpu > 95:
                    alerts.append(create_alert("Critical", "Critical CPU Spike", "N/A", "Unknown (AI Inferred)", "Cryptojacking, runaway destructive malware, or severe system fault.", "1. Identify and kill high-CPU process. 2. Isolate endpoint if unauthorized software found. 3. Reboot if unresponsive."))
                elif cpu > 80:
                    alerts.append(create_alert("High", "Unusual CPU Spike", "N/A", "Unknown (AI Inferred)", "A non-standard background process is consuming high resources.", "1. Monitor endpoint for continued spikes. 2. Verify with user if they started a heavy workload."))
                
                if net_tx > 50:
                    alerts.append(create_alert("Critical", "Massive Data Exfiltration Risk", "Multiple/Unknown", "Unknown", "A process is rapidly uploading data out of the network.", "1. IMMEDIATELY isolate endpoint. 2. Block outbound ports on firewall. 3. Audit recent file access logs."))
                elif net_tx > 15:
                    alerts.append(create_alert("High", "High Outbound Traffic", "Multiple/Unknown", "Unknown", "Higher than baseline data transfer detected.", "1. Review destination IPs for this endpoint. 2. Check if a cloud backup or large file transfer was initiated."))
                    
                if mem > 95:
                    alerts.append(create_alert("High", "Critical Memory Usage", "N/A", "Unknown", "Severe memory leak or memory exhaustion attack.", "1. Terminate high-RAM applications. 2. Increase swap space or reboot."))
                    
                if not is_learning and not any(a['description'] in ["Critical CPU Spike", "Unusual CPU Spike", "Massive Data Exfiltration Risk", "High Outbound Traffic", "Critical Memory Usage"] for a in alerts):
                    alerts.append(create_alert("Low", "Minor Behavioral Deviation", "N/A", "N/A", "General resource consumption pattern shifted slightly from the ML baseline.", "1. No immediate action required. 2. Log for future behavioral auditing."))
                    
        except Exception as e:
            print(f"Error in ML prediction: {e}")
            
    # 2. Categorical Profile Analysis (Unknown Processes & IP Connections)
    if profile["processes"]:
        current_procs = data.get('active_processes', [])
        new_procs = [p for p in current_procs if p not in profile["processes"]]
        
        for p in new_procs:
            is_suspicious = any(kw in p.lower() for kw in SUSPICIOUS_PROCS)
            if is_suspicious:
                alerts.append(create_alert("Critical", f"Suspicious Process Executed: {p}", "N/A", p, "User or attacker launched a known malicious binary or hacking tool.", f"1. Kill process '{p}'. 2. Isolate endpoint. 3. Initiate full EDR scan."))
            elif not is_learning:
                alerts.append(create_alert("Medium", f"Unknown Process Executed: {p}", "N/A", p, "A benign-looking application was started that has never been used by this user.", f"1. Verify if '{p}' is company-approved. 2. Monitor for further anomalous actions."))
            
        current_ips = data.get('recent_urls', [])
        new_ips = [ip for ip in current_ips if ip not in profile["ips"]]
        
        for ip in new_ips:
            if net_tx > 15:
                alerts.append(create_alert("Critical", f"Abnormal IP Connection with Data Transfer", ip, "Unknown", "Endpoint is funneling large amounts of data to an unverified IP address.", f"1. Isolate endpoint. 2. Block IP {ip} at gateway firewall. 3. Analyze what data was exfiltrated."))
            elif not is_learning:
                alerts.append(create_alert("Low", f"Irregular Website/IP Usage", ip, "Unknown", "Endpoint navigated to an IP that is not in its historical baseline.", f"1. Log IP {ip} for threat intel correlation. 2. No immediate action required."))
            
    return alerts
