"""
NexusGuard Phase 12: Security Testing Suite
Validates security controls across all microservices.

Usage: python security_test.py
"""
import requests
import json
import time

API_GATEWAY = "http://localhost:5000"
ANALYTICS = "http://localhost:5001"
BLOCKCHAIN = "http://localhost:5002"

passed = 0
failed = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✔ PASS: {name}")
    else:
        failed += 1
        print(f"  ✖ FAIL: {name} — {detail}")

def run_security_tests():
    global passed, failed
    
    print("=" * 60)
    print("  NexusGuard Security Testing Suite")
    print("=" * 60)
    print()
    
    # ---- 1. Authentication Tests ----
    print("[1] Authentication & Authorization")
    print("-" * 40)
    
    # No auth header
    try:
        r = requests.post(f"{ANALYTICS}/submit_metrics", json={"test": True}, timeout=5)
        test("Reject unauthenticated request", r.status_code == 401)
    except:
        test("Reject unauthenticated request", False, "Server unreachable")
    
    # Wrong auth header
    try:
        r = requests.post(f"{ANALYTICS}/submit_metrics", json={"test": True},
                         headers={"Authorization": "Bearer WRONG-TOKEN"}, timeout=5)
        test("Reject invalid auth token", r.status_code == 401)
    except:
        test("Reject invalid auth token", False, "Server unreachable")
    
    # Correct auth but bad data
    try:
        r = requests.post(f"{ANALYTICS}/submit_metrics", json={},
                         headers={"Authorization": "Bearer nx-agent-secure-token-v1"}, timeout=5)
        test("Reject empty payload with valid auth", r.status_code == 400)
    except:
        test("Reject empty payload with valid auth", False, "Server unreachable")
    
    print()
    
    # ---- 2. Input Validation Tests ----
    print("[2] Input Validation & Sanitization")
    print("-" * 40)
    
    # SQL injection in endpoint_id
    try:
        payload = {
            "endpoint_id": "'; DROP TABLE alerts; --",
            "user_id": "test", "cpu_usage": 50, "memory_usage": 50,
            "network_tx": 0, "network_rx": 0, "active_processes": [],
            "recent_urls": [], "timestamp": time.time()
        }
        r = requests.post(f"{ANALYTICS}/submit_metrics", json=payload,
                         headers={"Authorization": "Bearer nx-agent-secure-token-v1"}, timeout=5)
        test("Block SQL injection in endpoint_id", r.status_code == 400)
    except:
        test("Block SQL injection in endpoint_id", False, "Server unreachable")
    
    # XSS in chat input
    try:
        r = requests.post(f"{ANALYTICS}/api/chat",
                         json={"message": "<script>alert('xss')</script>"}, timeout=5)
        data = r.json()
        test("Sanitize XSS in chat input",
             "<script>" not in data.get("response", ""),
             "XSS payload reflected in response")
    except:
        test("Sanitize XSS in chat input", False, "Server unreachable")
    
    # Oversized payload
    try:
        r = requests.post(f"{ANALYTICS}/api/chat",
                         json={"message": "A" * 10000}, timeout=5)
        test("Handle oversized input gracefully", r.status_code == 200)
    except:
        test("Handle oversized input gracefully", False, "Server unreachable")
    
    print()
    
    # ---- 3. Security Headers Tests ----
    print("[3] Security Headers")
    print("-" * 40)
    
    try:
        r = requests.get(f"{API_GATEWAY}/api/alerts", timeout=5)
        h = r.headers
        test("X-Content-Type-Options: nosniff", h.get('X-Content-Type-Options') == 'nosniff')
        test("X-Frame-Options: DENY", h.get('X-Frame-Options') == 'DENY')
        test("X-XSS-Protection present", 'X-XSS-Protection' in h)
        test("Strict-Transport-Security present", 'Strict-Transport-Security' in h)
        test("Cache-Control: no-store", 'no-store' in h.get('Cache-Control', ''))
        test("Referrer-Policy present", 'Referrer-Policy' in h)
    except:
        test("Security headers check", False, "API Gateway unreachable")
    
    print()
    
    # ---- 4. Rate Limiting Tests ----
    print("[4] Rate Limiting")
    print("-" * 40)
    
    try:
        rate_limited = False
        for i in range(150):
            r = requests.get(f"{ANALYTICS}/health", timeout=2)
            if r.status_code == 429:
                rate_limited = True
                break
        test("Rate limiter activates under flood", rate_limited,
             "No 429 response after 150 rapid requests")
    except:
        test("Rate limiter activates under flood", False, "Server unreachable")
    
    print()
    
    # ---- 5. Blockchain Integrity Tests ----
    print("[5] Blockchain Integrity")
    print("-" * 40)
    
    try:
        r = requests.get(f"{BLOCKCHAIN}/verify", timeout=5)
        data = r.json()
        test("Blockchain chain is valid", data.get("is_valid") == True)
    except:
        test("Blockchain chain is valid", False, "Blockchain Logger unreachable")
    
    try:
        r = requests.get(f"{BLOCKCHAIN}/ledger", timeout=5)
        data = r.json()
        chain = data.get("chain", [])
        if len(chain) >= 2:
            test("Genesis block has index 0", chain[0]["index"] == 0)
            test("Chain hashes are linked", chain[1]["previous_hash"] == chain[0]["hash"])
        else:
            test("Chain has enough blocks for validation", False, "Only genesis block exists")
    except:
        test("Blockchain structure check", False, "Blockchain Logger unreachable")
    
    print()
    
    # ---- 6. Health Check Tests ----
    print("[6] Health & Availability")
    print("-" * 40)
    
    try:
        r = requests.get(f"{API_GATEWAY}/api/health", timeout=5)
        data = r.json()
        test("Aggregated health endpoint responds", r.status_code == 200)
        test("Platform status reported", "status" in data)
        test("All services enumerated", "services" in data)
    except:
        test("Health check endpoint", False, "API Gateway unreachable")
    
    try:
        r = requests.get(f"{ANALYTICS}/health", timeout=5)
        data = r.json()
        test("Analytics Engine health responds", data.get("status") == "online")
        test("Database health reported", "database" in data)
    except:
        test("Analytics health check", False, "Analytics Engine unreachable")
    
    print()
    
    # ---- Summary ----
    total = passed + failed
    print("=" * 60)
    print(f"  SECURITY TEST RESULTS")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    print("=" * 60)
    if failed == 0:
        print("  ✔ ALL SECURITY TESTS PASSED")
    else:
        print(f"  ✖ {failed} TEST(S) FAILED — Review and fix")
    print("=" * 60)

if __name__ == "__main__":
    run_security_tests()
