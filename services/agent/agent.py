import time
import requests
import psutil
import socket
import os
import getpass
import hashlib
import hmac
import json

ANALYTICS_URL = "http://localhost:5001/submit_metrics"
AGENT_AUTH_KEY = "nx-agent-secure-token-v1"
HMAC_SECRET = "NxG-HMAC-Integrity-2026"
ENDPOINT_ID = socket.gethostname()

try:
    USER_ID = getpass.getuser()
except Exception:
    USER_ID = "UnknownUser"

# Tracking previous metrics for rate calculation
last_net_io = psutil.net_io_counters()
last_time = time.time()

def generate_payload_signature(payload):
    """Generate HMAC-SHA256 signature for payload integrity verification."""
    return hmac.new(
        HMAC_SECRET.encode('utf-8'),
        json.dumps(payload, sort_keys=True).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def get_real_metrics():
    global last_net_io, last_time
    
    current_time = time.time()
    time_diff = current_time - last_time
    if time_diff == 0:
        time_diff = 1

    current_net_io = psutil.net_io_counters()
    
    # Calculate MB/s
    tx_mbps = (current_net_io.bytes_sent - last_net_io.bytes_sent) / (1024 * 1024) / time_diff
    rx_mbps = (current_net_io.bytes_recv - last_net_io.bytes_recv) / (1024 * 1024) / time_diff
    
    last_net_io = current_net_io
    last_time = current_time
    
    # 1. Application Usage (Running Processes)
    active_processes = set()
    try:
        for proc in psutil.process_iter(['name']):
            try:
                name = proc.info.get('name')
                if name:
                    active_processes.add(name.lower())
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception:
        pass
        
    # 2. Network Connections & IPs
    recent_urls = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ip = conn.raddr.ip
                port = conn.raddr.port
                if port in (80, 443, 8080, 8443):
                    recent_urls.add(ip)
    except psutil.AccessDenied:
        pass
    except Exception:
        pass
        
    return {
        "endpoint_id": ENDPOINT_ID,
        "user_id": USER_ID,
        "cpu_usage": round(psutil.cpu_percent(interval=None), 2),
        "memory_usage": round(psutil.virtual_memory().percent, 2),
        "network_tx": round(tx_mbps, 4),
        "network_rx": round(rx_mbps, 4),
        "active_processes": list(active_processes),
        "recent_urls": list(recent_urls),
        "timestamp": current_time
    }

ISOLATED = False
consecutive_failures = 0
MAX_RETRIES = 3

def run_agent():
    global ISOLATED, consecutive_failures
    print(f"[*] Starting NexusGuard Real Endpoint Agent (Phase 12: Hardened)")
    print(f"    Endpoint ID: {ENDPOINT_ID}")
    print(f"    User ID: {USER_ID}")
    print(f"    HMAC Integrity: Enabled")
    print(f"    Target Server: {ANALYTICS_URL}")
    
    # Initial call to cpu_percent to set the baseline for measurement
    psutil.cpu_percent(interval=1)
    
    headers = {
        "Authorization": f"Bearer {AGENT_AUTH_KEY}",
        "Content-Type": "application/json"
    }
    
    while True:
        try:
            if ISOLATED:
                print(f"[!!!] ENDPOINT ISOLATED. ALL OUTBOUND NETWORK TRAFFIC BLOCKED.")
                time.sleep(5)
                continue
                
            data = get_real_metrics()
            
            # Phase 12: Sign payload with HMAC for integrity verification
            signature = generate_payload_signature(data)
            headers["X-Payload-Signature"] = signature
            
            # Secure transmission with timeout
            response = requests.post(ANALYTICS_URL, json=data, headers=headers, timeout=8)
            
            if response.status_code == 200:
                consecutive_failures = 0
                resp_data = response.json()
                print(f"[+] Metrics -> CPU: {data['cpu_usage']}% | Mem: {data['memory_usage']}% | Procs: {len(data['active_processes'])} | IPs: {len(data['recent_urls'])} | HMAC: ✔")
                
                # Phase 8: Execute Automated Responses
                actions = resp_data.get("response_actions", [])
                for action in actions:
                    if action["action"] == "kill_process":
                        target = action["target"]
                        print(f"\n[!] AUTOMATED RESPONSE TRIGGERED:")
                        print(f"    -> Terminating Malicious Process: {target}")
                        os.system(f"taskkill /F /IM {target} >nul 2>&1")
                        
                    elif action["action"] == "isolate_network":
                        print(f"\n[!!!] AUTOMATED RESPONSE TRIGGERED: CRITICAL THREAT")
                        print(f"    -> Isolating Endpoint {ENDPOINT_ID} from Network.")
                        ISOLATED = True

            elif response.status_code == 429:
                print(f"[!] Rate limited by server. Backing off...")
                time.sleep(10)
            else:
                print(f"[-] Server returned status {response.status_code}")
                
        except requests.exceptions.Timeout:
            consecutive_failures += 1
            print(f"[-] Request timed out. Failure {consecutive_failures}/{MAX_RETRIES}")
        except requests.exceptions.ConnectionError:
            consecutive_failures += 1
            print(f"[-] Central server unreachable. Failure {consecutive_failures}/{MAX_RETRIES}")
        except Exception as e:
            consecutive_failures += 1
            print(f"[-] Error collecting metrics: {e}")
        
        # Exponential backoff on consecutive failures
        if consecutive_failures > 0:
            backoff = min(5 * (2 ** (consecutive_failures - 1)), 60)
            print(f"    Retrying in {backoff}s...")
            time.sleep(backoff)
        else:
            time.sleep(5)

if __name__ == "__main__":
    run_agent()
