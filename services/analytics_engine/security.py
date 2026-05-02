"""
NexusGuard Phase 12: Security & Performance Module
Provides encryption utilities, rate limiting, input validation, and security headers.
"""
import hashlib
import hmac
import base64
import os
import time
import json
from functools import wraps
from collections import defaultdict

# ============================================================
# AES-like XOR Encryption (Lightweight, no external deps)
# For full AES, use: from cryptography.fernet import Fernet
# ============================================================
class DataEncryptor:
    """
    Encrypts/decrypts data at rest using a repeating-key XOR cipher.
    In production, replace with AES-256-GCM via the `cryptography` package.
    """
    def __init__(self, key=None):
        self.key = key or os.environ.get('NEXUSGUARD_ENC_KEY', 'NxG-Enterprise-Key-2026!@#$%')
    
    def encrypt(self, plaintext):
        """Encrypt a string and return a base64-encoded ciphertext."""
        if not plaintext:
            return plaintext
        key_bytes = self.key.encode('utf-8')
        plain_bytes = plaintext.encode('utf-8')
        encrypted = bytes([p ^ key_bytes[i % len(key_bytes)] for i, p in enumerate(plain_bytes)])
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext):
        """Decrypt a base64-encoded ciphertext back to plaintext."""
        if not ciphertext:
            return ciphertext
        key_bytes = self.key.encode('utf-8')
        encrypted = base64.b64decode(ciphertext.encode('utf-8'))
        decrypted = bytes([c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(encrypted)])
        return decrypted.decode('utf-8')

# ============================================================
# HMAC Payload Integrity Verification
# ============================================================
HMAC_SECRET = os.environ.get('NEXUSGUARD_HMAC_SECRET', 'NxG-HMAC-Integrity-2026')

def generate_hmac(payload_json):
    """Generate HMAC-SHA256 signature for a JSON payload."""
    return hmac.new(
        HMAC_SECRET.encode('utf-8'),
        json.dumps(payload_json, sort_keys=True).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def verify_hmac(payload_json, signature):
    """Verify HMAC-SHA256 signature matches the payload."""
    expected = generate_hmac(payload_json)
    return hmac.compare_digest(expected, signature)

# ============================================================
# Rate Limiter (Per-IP)
# ============================================================
class RateLimiter:
    """
    Token-bucket rate limiter. Limits requests per IP address.
    """
    def __init__(self, max_requests=60, window_seconds=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = defaultdict(list)
    
    def is_allowed(self, client_ip):
        """Check if the client IP is within rate limits."""
        now = time.time()
        # Clean old entries
        self.requests[client_ip] = [
            t for t in self.requests[client_ip] if now - t < self.window
        ]
        if len(self.requests[client_ip]) >= self.max_requests:
            return False
        self.requests[client_ip].append(now)
        return True

# ============================================================
# Input Sanitizer
# ============================================================
def sanitize_input(text, max_length=500):
    """Sanitize user input to prevent injection attacks."""
    if not isinstance(text, str):
        return ""
    # Strip dangerous characters
    sanitized = text.replace('<', '&lt;').replace('>', '&gt;')
    sanitized = sanitized.replace('"', '&quot;').replace("'", '&#39;')
    # Truncate to max length
    return sanitized[:max_length]

def validate_endpoint_id(endpoint_id):
    """Validate endpoint ID format."""
    if not endpoint_id or not isinstance(endpoint_id, str):
        return False
    if len(endpoint_id) > 100:
        return False
    # Allow alphanumeric, hyphens, underscores, dots
    allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.')
    return all(c in allowed for c in endpoint_id)

# ============================================================
# Security Headers Middleware
# ============================================================
def apply_security_headers(response):
    """Apply enterprise security headers to every HTTP response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self' http://localhost:* https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com"
    return response

# ============================================================
# Connection Pool for SQLite
# ============================================================
import sqlite3
import threading

class ConnectionPool:
    """Thread-safe SQLite connection pool for high-throughput operation."""
    def __init__(self, db_path, pool_size=5):
        self.db_path = db_path
        self.pool_size = pool_size
        self._pool = []
        self._lock = threading.Lock()
    
    def get_connection(self):
        with self._lock:
            if self._pool:
                return self._pool.pop()
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for concurrency
        conn.execute("PRAGMA synchronous=NORMAL")  # Faster writes with safety
        conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
        conn.execute("PRAGMA temp_store=MEMORY")
        return conn
    
    def return_connection(self, conn):
        with self._lock:
            if len(self._pool) < self.pool_size:
                self._pool.append(conn)
            else:
                conn.close()

# ============================================================
# Performance Metrics Tracker
# ============================================================
class PerformanceTracker:
    """Track processing times for performance monitoring."""
    def __init__(self):
        self._times = defaultdict(list)
        self._lock = threading.Lock()
    
    def record(self, operation, duration_ms):
        with self._lock:
            self._times[operation].append(duration_ms)
            # Keep only last 100 measurements
            if len(self._times[operation]) > 100:
                self._times[operation] = self._times[operation][-100:]
    
    def get_stats(self):
        with self._lock:
            stats = {}
            for op, times in self._times.items():
                if times:
                    stats[op] = {
                        "avg_ms": round(sum(times) / len(times), 2),
                        "max_ms": round(max(times), 2),
                        "min_ms": round(min(times), 2),
                        "samples": len(times)
                    }
            return stats

# Shared instances
encryptor = DataEncryptor()
rate_limiter = RateLimiter(max_requests=120, window_seconds=60)
perf_tracker = PerformanceTracker()
