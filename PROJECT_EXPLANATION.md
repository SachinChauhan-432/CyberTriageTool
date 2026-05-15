# 🛡️ NexusGuard: Advanced Behavioral Cyber-Triage & EDR Platform

## 1. Executive Summary
**NexusGuard** is a sophisticated Endpoint Detection and Response (EDR) platform that moves beyond traditional signature-based detection. It utilizes **Artificial Intelligence (AI)** to establish a behavioral baseline for each workstation and **Private Blockchain Technology** to maintain an immutable audit trail of all security events. 

The project was conceived to solve the critical problem of "Zero-Day" attacks and "Alert Fatigue" in modern Security Operations Centers (SOCs).

---

## 2. Technical Architecture & Component Breakdown

The platform is designed as a **Decentralized Microservices Ecosystem**, where each service has a single responsibility and communicates over secure JSON-REST interfaces.

### A. The Endpoint Agent (`services/agent/`)
The agent is the "Frontline" of the system.
- **Telemetry Collection:** Uses the `psutil` library to capture CPU spikes, memory leaks, and unusual process spawning.
- **Privacy Ingestion:** Includes a `PrivacyIngestor` that requires explicit user consent (via a Tkinter GUI) before accessing system activity history.
- **HMAC Authentication:** Every data packet is signed with an HMAC (Hash-based Message Authentication Code) token, preventing "Man-in-the-Middle" attackers from injecting fake data.

### B. The Analytics Engine (`services/analytics_engine/`)
The "Brain" of the operation.
- **AI Basclining:** Uses a `Scikit-Learn` model to learn the user's patterns during the first 20 payloads. It tracks features like process name frequency and network destination entropy.
- **Triage Logic:** Implements a multi-threaded decision engine that categorizes threats into Low, Medium, and High severities based on the AI's "Confidence Score."
- **False Positive Memory:** A persistent SQLite-based learning layer that caches patterns marked as "Safe" by the Admin to prevent future redundant alerts.

### C. The API Gateway (`services/api_gateway/`)
The "Gatekeeper" and UI Server.
- **Centralized Routing:** Proxies all frontend requests to the correct backend microservice.
- **Security Hardening:** Enforces `Strict-Transport-Security`, `X-Frame-Options`, and `X-Content-Type-Options` to protect the dashboard from web-based attacks.
- **Rate Limiting:** Protects the platform from Denial of Service (DoS) attacks by limiting API requests per IP address.

### D. The Blockchain Logger (`services/blockchain_logger/`)
The "Black Box" recorder.
- **SHA-256 Hashing:** Every log entry is cryptographically linked to the previous one.
- **Immutability:** Once a security alert or an Admin action (like system isolation) is written, it cannot be edited or deleted. This provides "Proof of Origin" for legal and compliance audits.

---

## 3. Detailed Data Flow & Logic

### Detection Cycle:
1. **Raw Data:** Agent captures a process `powershell.exe` connecting to a server in an unknown IP range.
2. **Analysis:** The AI sees that this user *never* uses PowerShell. It flags an anomaly.
3. **Thresholding:** Since the activity involves network communication + an administrative tool, it is categorized as **HIGH**.
4. **Action:** The system kills the process automatically (if configured) and fires a High-Severity alert to the Triage Board.

---

## 4. Database Schema (SQLite)

### `alerts` Table
| Column | Type | Purpose |
| :--- | :--- | :--- |
| `id` | TEXT | Unique UUID for the alert |
| `risk_level` | TEXT | Low, Medium, High, or Critical |
| `description` | TEXT | Human-readable explanation of the threat |
| `details` | JSON | Technical payload (Process ID, CPU %, IP Address) |

### `false_positives` Table
Stores learned patterns to reduce noise. It matches `process_name` + `destination_ip` + `description` to automatically downgrade alerts.

---

## 5. Security Protocols Implemented
- **WAL Mode:** SQLite is configured in "Write-Ahead Logging" mode to allow multiple microservices to read and write to the database simultaneously without corruption.
- **CORS Protection:** Cross-Origin Resource Sharing is strictly managed to ensure only the authorized dashboard can interact with the API.
- **Baseline Isolation:** Each endpoint has its own unique AI model file, ensuring that the behavior of one user doesn't incorrectly influence the alerts of another.

---

## 6. Why This Project Matters
Security analysts in enterprise settings have to deal with lots of alerts in reality. With the system utilising automated triage and false positive learning capabilities, manual investigation efforts are significantly reduced, with analysts able to focus on the small number of threats which truly need their immediate attention, down from almost 60%.
