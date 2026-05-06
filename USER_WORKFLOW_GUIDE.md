# 🔄 Detailed Workflow: How NexusGuard Secures Your Network

This guide provides a deep-dive into the operational lifecycle of the NexusGuard platform. It is designed to help both technical and non-technical stakeholders understand the "Life of a Threat."

---

## Phase 1: The Initialization (Baseline Learning)
Before the system can protect you, it must know what "Normal" looks like.

1.  **The Handshake:** When the **Agent** first starts, it registers with the **Analytics Engine**.
2.  **The Observation Period:** For the first 20 minutes of activity (or 20 data snapshots), the system is in **Learning Mode**.
3.  **Profiling:** The AI builds a profile of your computer: 
    *   *Which apps do you use?* 
    *   *How much memory do they usually take?* 
    *   *Where do they connect on the internet?*
    *   *Does this user usually run administrative commands?*

---

## Phase 2: Detection in Action (The Scenario)
Let’s look at a "Real-World" example of how the system stops a Ransomware attack.

### 1. The Trigger
A user accidentally opens a malicious email attachment. A hidden process starts running in the background.

### 2. The Anomaly
The **Agent** notices that this new process is suddenly using **90% CPU** (it’s encrypting files) and is reaching out to an **Unknown IP Address** in another country.

### 3. The Analysis
The **Analytics Engine** compares this to your Baseline. It realizes:
- "This user has never run a process with this name before."
- "This process is using an extreme amount of CPU compared to the user's average."
- **Decision:** This is a **HIGH-RISK** event.

---

## Phase 3: The Triage & Management
Once a threat is detected, it enters the **Triage Board** on the Dashboard.

### The Three Columns:
1.  **🟢 LOW (Auto-Pilot):** These are "Noise" alerts. For example, Chrome updated itself and changed its behavior slightly. The system badges these as "✔ Resolved" automatically. You can ignore these.
2.  **🟡 MEDIUM (The Warning):** Something is "weird" but not necessarily "dangerous." For example, a user logged in at 3 AM for the first time.
3.  **🔴 HIGH / CRITICAL (The Fire):** This is where Ransomware or Hackers appear. The system may have already killed the process, but it needs an Admin's eyes.

---

## Phase 4: Administrative Response
An Admin (You) logs into the dashboard and sees the High Alert.

1.  **The Deep Dive:** You click the **[ CHECK ]** button. 
2.  **The Evidence:** You see the Process Name, the IP Address, and the AI's "Root Cause" explanation.
3.  **The Decision:**
    *   **Option A (Manually Resolve):** You realize it was just a specialized IT tool you ran. You click "Mark as Resolved." The alert moves to the Low column.
    *   **Option B (False Positive):** You click "Mark as False Positive." The system **learns** this tool is safe and will never bother you about it again.
    *   **Option C (Isolate):** You realize the computer is indeed infected. You click **[ ISOLATE SYSTEM ]**.

---

## Phase 5: The "Digital Lockdown"
When **Isolate System** is clicked:
1.  A "Kill" command is sent to the Agent.
2.  The Agent uses local firewall rules (simulated in our demo) to block all internet traffic except for communication with the NexusGuard Dashboard.
3.  The user sees a warning on their screen: *"This system is isolated due to high-risk activity."*
4.  The virus is now trapped and cannot spread to the server or other coworkers.

---

## Phase 6: The Immutable Audit (Blockchain)
While all this was happening, every click was being recorded.
- **Why?** If a hacker managed to delete the database, the **Blockchain Ledger** still has the record.
- **Audit Ready:** When a teacher or an auditor asks: *"How did you handle the attack on May 6th?"*, you can pull the Blockchain log and show the exact second the alert fired and the exact second the Admin isolated the system.

---

## 🏆 Summary: A Day in the Life of an Admin
As an Admin, your day becomes much quieter. Instead of looking at 1,000 "Low" alerts, you ignore the Green column entirely. You spend 5 minutes reviewing the Yellow and Red columns, taking action only when the AI is 90% sure something is wrong. **You go from a "Filter" to a "Decision Maker."**
