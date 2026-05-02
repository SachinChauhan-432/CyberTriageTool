"""
NexusGuard Phase 12: Load Testing Suite
Simulates multiple concurrent endpoints sending telemetry data
to stress-test the Analytics Engine under enterprise-scale load.

Usage: python load_test.py
"""
import requests
import threading
import time
import random
import json
import sys

API_URL = "http://localhost:5001/submit_metrics"
AUTH_KEY = "nx-agent-secure-token-v1"

# Test Configuration
NUM_ENDPOINTS = 10          # Simulated concurrent endpoints
REQUESTS_PER_ENDPOINT = 50  # Number of payloads per endpoint
RESULTS = {"success": 0, "fail": 0, "latencies": []}
lock = threading.Lock()

def generate_fake_payload(endpoint_id):
    """Generate a realistic telemetry payload."""
    return {
        "endpoint_id": f"LOADTEST-EP-{endpoint_id:03d}",
        "user_id": f"user_{endpoint_id}",
        "cpu_usage": round(random.uniform(5, 95), 2),
        "memory_usage": round(random.uniform(30, 90), 2),
        "network_tx": round(random.uniform(0.01, 5.0), 4),
        "network_rx": round(random.uniform(0.01, 10.0), 4),
        "active_processes": [f"proc_{i}.exe" for i in range(random.randint(5, 20))],
        "recent_urls": [f"192.168.1.{random.randint(1,254)}" for _ in range(random.randint(0, 5))],
        "timestamp": time.time()
    }

def endpoint_worker(endpoint_id):
    """Simulate a single endpoint sending multiple payloads."""
    headers = {
        "Authorization": f"Bearer {AUTH_KEY}",
        "Content-Type": "application/json"
    }
    
    for i in range(REQUESTS_PER_ENDPOINT):
        payload = generate_fake_payload(endpoint_id)
        start = time.time()
        try:
            resp = requests.post(API_URL, json=payload, headers=headers, timeout=10)
            latency = (time.time() - start) * 1000
            
            with lock:
                RESULTS["latencies"].append(latency)
                if resp.status_code == 200:
                    RESULTS["success"] += 1
                else:
                    RESULTS["fail"] += 1
        except Exception as e:
            with lock:
                RESULTS["fail"] += 1
        
        time.sleep(0.1)  # 100ms between requests per endpoint

def run_load_test():
    print("=" * 60)
    print("  NexusGuard Load Testing Suite")
    print("=" * 60)
    print(f"  Endpoints:      {NUM_ENDPOINTS}")
    print(f"  Requests/EP:    {REQUESTS_PER_ENDPOINT}")
    print(f"  Total Requests: {NUM_ENDPOINTS * REQUESTS_PER_ENDPOINT}")
    print(f"  Target:         {API_URL}")
    print("=" * 60)
    print()
    
    # Check server is up
    try:
        requests.get("http://localhost:5001/health", timeout=3)
    except:
        print("[!] Analytics Engine is not running. Start it first.")
        return
    
    print("[*] Starting load test...\n")
    start_time = time.time()
    
    threads = []
    for i in range(NUM_ENDPOINTS):
        t = threading.Thread(target=endpoint_worker, args=(i,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    duration = time.time() - start_time
    
    # Results
    total = RESULTS["success"] + RESULTS["fail"]
    latencies = RESULTS["latencies"]
    
    print()
    print("=" * 60)
    print("  LOAD TEST RESULTS")
    print("=" * 60)
    print(f"  Duration:         {duration:.2f}s")
    print(f"  Total Requests:   {total}")
    print(f"  Successful:       {RESULTS['success']} ({RESULTS['success']/total*100:.1f}%)")
    print(f"  Failed:           {RESULTS['fail']} ({RESULTS['fail']/total*100:.1f}%)")
    print(f"  Throughput:       {total/duration:.1f} req/s")
    
    if latencies:
        latencies.sort()
        print(f"\n  Latency:")
        print(f"    Avg:    {sum(latencies)/len(latencies):.1f}ms")
        print(f"    Min:    {min(latencies):.1f}ms")
        print(f"    Max:    {max(latencies):.1f}ms")
        print(f"    P50:    {latencies[len(latencies)//2]:.1f}ms")
        print(f"    P95:    {latencies[int(len(latencies)*0.95)]:.1f}ms")
        print(f"    P99:    {latencies[int(len(latencies)*0.99)]:.1f}ms")
    
    print("=" * 60)
    
    # Pass/Fail
    if RESULTS['success'] / total > 0.95 and sum(latencies)/len(latencies) < 500:
        print("  ✔ LOAD TEST PASSED")
    else:
        print("  ✖ LOAD TEST FAILED — Performance below threshold")
    print("=" * 60)

if __name__ == "__main__":
    run_load_test()
