import sqlite3
import json
import time
import random

DB_PATH = 'analytics.db'

DAILY_TIPS = [
    "🔑 Use unique, strong passwords for every account. Consider a password manager like Bitwarden or 1Password.",
    "🛡️ Enable Multi-Factor Authentication (MFA) on all critical accounts — email, banking, and cloud services.",
    "📧 Never click links in unsolicited emails. Phishing is the #1 attack vector for credential theft.",
    "💾 Follow the 3-2-1 backup rule: 3 copies, 2 different media, 1 offsite. Test your backups regularly.",
    "🔄 Keep all software updated. Over 60% of breaches exploit known vulnerabilities with available patches.",
    "🌐 Use a VPN on public Wi-Fi networks. Attackers can intercept unencrypted traffic in seconds.",
    "🔒 Enable full-disk encryption (BitLocker on Windows, FileVault on macOS) to protect data at rest.",
    "👁️ Review your browser extensions monthly. Malicious extensions can steal passwords and session cookies.",
    "📱 Be cautious with USB drives from unknown sources. USB drop attacks are still highly effective.",
    "🚫 Never share credentials over email or chat. Use a secure password sharing tool instead.",
    "⚠️ Watch for typosquatting — attackers register domains like 'go0gle.com' to steal credentials.",
    "🔍 Check haveibeenpwned.com regularly to see if your credentials have been leaked in a breach.",
    "🖥️ Lock your workstation (Win+L) every time you step away, even for a minute.",
    "📊 Monitor your bank and credit card statements weekly for unauthorized transactions.",
    "🧹 Regularly audit user accounts and remove inactive ones — dormant accounts are easy targets."
]

AWARENESS_TOPICS = {
    "phishing": "Phishing is a social engineering attack where attackers send fraudulent emails that appear legitimate. They trick users into clicking malicious links or downloading malware. Always verify the sender's email address, hover over links before clicking, and never enter credentials on unfamiliar sites.",
    "ransomware": "Ransomware encrypts your files and demands payment (usually cryptocurrency) for the decryption key. Prevention: maintain offline backups, keep systems patched, use endpoint detection, and never pay the ransom — it funds criminal operations and doesn't guarantee recovery.",
    "zero-day": "A zero-day vulnerability is a software flaw unknown to the vendor with no available patch. NexusGuard's behavioral AI can detect zero-day exploitation through anomalous behavior patterns, even when signature-based tools fail.",
    "lateral movement": "Lateral movement is when an attacker moves through your network after initial compromise, escalating privileges and accessing more systems. Signs include unusual login patterns, unexpected admin tool usage (PsExec, WMI), and cross-system authentication spikes.",
    "insider threat": "Insider threats come from employees, contractors, or partners who misuse their access. NexusGuard monitors behavioral baselines per user — if someone suddenly accesses files or systems outside their normal pattern, the AI flags it.",
    "ddos": "A DDoS (Distributed Denial of Service) attack floods your systems with traffic to make them unavailable. Watch for sudden bandwidth spikes on the dashboard. Mitigation includes rate limiting, CDN usage, and upstream filtering.",
    "social engineering": "Social engineering manipulates people into breaking security procedures. Attacks include pretexting, baiting, tailgating, and quid pro quo. Training and awareness are the best defenses — technology alone can't stop human error."
}

def get_system_summary():
    """Pull live data from the database to build a context-aware system summary."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Count alerts by severity
        c.execute("SELECT risk_level, COUNT(*) FROM alerts GROUP BY risk_level")
        severity_counts = dict(c.fetchall())
        
        # Total alerts
        c.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = c.fetchone()[0]
        
        # Recent critical alerts
        c.execute("SELECT description, details FROM alerts WHERE risk_level='Critical' ORDER BY timestamp DESC LIMIT 3")
        critical_alerts = c.fetchall()
        
        # Endpoint info
        c.execute("SELECT endpoint_id, cpu_usage, memory_usage, timestamp FROM metrics ORDER BY timestamp DESC LIMIT 10")
        recent_metrics = c.fetchall()
        
        conn.close()
        
        return {
            "total_alerts": total_alerts,
            "severity": severity_counts,
            "critical_alerts": critical_alerts,
            "recent_metrics": recent_metrics
        }
    except Exception as e:
        return {"total_alerts": 0, "severity": {}, "critical_alerts": [], "recent_metrics": []}

def process_query(user_message):
    """
    Process a natural language query from the admin and return an intelligent,
    context-aware response using live system data.
    """
    q = user_message.lower().strip()
    summary = get_system_summary()
    
    # ---- Daily Tip Request ----
    if any(kw in q for kw in ['tip', 'tips', 'advice', 'daily', 'suggestion']):
        tip = random.choice(DAILY_TIPS)
        return f"💡 Daily Cybersecurity Tip:\n\n{tip}"
    
    # ---- Awareness / Education Topics ----
    for topic, explanation in AWARENESS_TOPICS.items():
        if topic in q:
            return f"📚 Cybersecurity Awareness — {topic.title()}:\n\n{explanation}"
    
    if any(kw in q for kw in ['awareness', 'educate', 'learn', 'training', 'teach']):
        topics_list = ", ".join(AWARENESS_TOPICS.keys())
        return f"📚 I can explain these cybersecurity topics in simple language:\n\n{topics_list}\n\nJust ask me about any of them! For example: 'What is ransomware?'"
    
    # ---- System Status / Health ----
    if any(kw in q for kw in ['status', 'health', 'overview', 'how is', 'system', 'summary']):
        total = summary['total_alerts']
        sev = summary['severity']
        critical = sev.get('Critical', 0)
        high = sev.get('High', 0)
        medium = sev.get('Medium', 0)
        low = sev.get('Low', 0)
        
        if critical > 0:
            health = "⚠️ ELEVATED THREAT LEVEL"
            advice = "I recommend reviewing the Critical alerts immediately and considering endpoint isolation."
        elif high > 0:
            health = "🟡 Moderate threat activity detected"
            advice = "Monitor the High-severity alerts and verify if the flagged processes are authorized."
        elif total > 0:
            health = "🟢 System is mostly healthy"
            advice = "Minor anomalies detected but no immediate action required."
        else:
            health = "✅ All systems are clean and protected"
            advice = "No threats detected. The AI behavioral engine is actively learning."
        
        return f"📊 System Health Report:\n\n{health}\n\n• Total Active Alerts: {total}\n• Critical: {critical}\n• High: {high}\n• Medium: {medium}\n• Low: {low}\n\n{advice}"
    
    # ---- Alert Explanation ----
    if any(kw in q for kw in ['alert', 'threat', 'what happened', 'explain', 'why', 'cause', 'problem']):
        critical_alerts = summary['critical_alerts']
        if critical_alerts:
            response = "🔍 Here's a plain-language explanation of your most recent critical alerts:\n\n"
            for i, (desc, details_str) in enumerate(critical_alerts, 1):
                try:
                    d = json.loads(details_str)
                    cause = d.get('root_cause', 'Unknown')
                    fix = d.get('remediation', 'No steps available')
                    response += f"Alert {i}: {desc}\n"
                    response += f"  • What happened: {cause}\n"
                    response += f"  • What to do: {fix}\n\n"
                except:
                    response += f"Alert {i}: {desc}\n\n"
            return response.strip()
        else:
            total = summary['total_alerts']
            if total > 0:
                return f"No Critical alerts right now, but there are {total} total active alerts. Most are Low/Medium severity — the system is monitoring them. Would you like a full system summary?"
            return "✅ No active alerts at this time. The behavioral AI is learning patterns and will flag any anomalies automatically."
    
    # ---- Mitigation / What to do ----
    if any(kw in q for kw in ['mitigat', 'fix', 'remediat', 'solve', 'respond', 'what should i do', 'help', 'action']):
        critical_alerts = summary['critical_alerts']
        if critical_alerts:
            desc, details_str = critical_alerts[0]
            try:
                d = json.loads(details_str)
                fix = d.get('remediation', 'Isolate the affected endpoint and run a full scan.')
                return f"🛠️ Recommended Action for \"{desc}\":\n\n{fix}\n\nYou can also click the '🔒 Isolate' button on the Endpoints tab to quarantine the affected device immediately."
            except:
                pass
        return "🛠️ General Mitigation Steps:\n\n1. Check the Threat Alerts tab for active threats\n2. Isolate any compromised endpoints from the Endpoints tab\n3. Review the Blockchain Logs for the full audit trail\n4. Update all endpoint software and patches\n5. Run a full endpoint detection scan"
    
    # ---- Isolate ----
    if 'isolate' in q:
        return "🔒 To isolate an endpoint:\n\n1. Go to the 'Endpoints' tab\n2. Find the affected device\n3. Click the '🔒 Isolate' button (requires Admin role)\n\nThis will quarantine the device, blocking all outbound network traffic. The action is logged immutably on the blockchain."
    
    # ---- Blockchain ----
    if 'blockchain' in q or 'ledger' in q or 'audit' in q or 'tamper' in q:
        return "⛓️ Blockchain Audit System:\n\nEvery alert, automated response, and admin action is cryptographically hashed using SHA-256 and stored in an immutable ledger. Each block references the previous block's hash — if anyone tampers with a record, the chain validation will immediately flag it.\n\nCheck the 'Blockchain Logs' tab to view the full audit trail and verify integrity."
    
    # ---- Risk Score ----
    if 'risk' in q or 'score' in q:
        sev = summary['severity']
        critical = sev.get('Critical', 0)
        high = sev.get('High', 0)
        medium = sev.get('Medium', 0)
        low = sev.get('Low', 0)
        score = min(100, critical * 25 + high * 10 + medium * 3 + low * 1)
        
        if score <= 20: level = "LOW RISK 🟢"
        elif score <= 50: level = "MODERATE RISK 🟡"
        elif score <= 75: level = "HIGH RISK 🟠"
        else: level = "CRITICAL RISK 🔴"
        
        return f"🎯 Current Risk Score: {score}/100 — {level}\n\nThe score is calculated as:\n• Critical alerts × 25 points\n• High alerts × 10 points\n• Medium alerts × 3 points\n• Low alerts × 1 point\n\nA score above 75 requires immediate executive attention."
    
    # ---- Role / Access ----
    if 'role' in q or 'access' in q or 'permission' in q or 'rbac' in q:
        return "👤 Role-Based Access Control (RBAC):\n\n• Admin — Full access: view, resolve alerts, isolate endpoints\n• Analyst — Can view and resolve alerts, but cannot isolate devices\n• Viewer — Read-only access to all dashboards and logs\n\nYou can check your current role in the top-right corner of the dashboard."
    
    # ---- Greeting ----
    if any(kw in q for kw in ['hello', 'hi', 'hey', 'good morning', 'good afternoon']):
        tip = random.choice(DAILY_TIPS)
        return f"Hello! I'm your NexusGuard AI Security Assistant. I'm continuously monitoring behavioral baselines across all endpoints.\n\nHere's your tip of the day:\n{tip}\n\nAsk me about system health, alerts, risk scores, or cybersecurity topics!"
    
    # ---- Fallback: Context-Aware Default ----
    total = summary['total_alerts']
    sev = summary['severity']
    critical = sev.get('Critical', 0)
    
    if critical > 0:
        return f"I'm not sure I understood that, but I want to flag that there are {critical} Critical alerts requiring your attention right now. Ask me 'explain alerts' for details or 'what should I do' for remediation steps."
    elif total > 0:
        return f"I'm here to help! There are currently {total} active alerts in the system. You can ask me:\n\n• 'System status' — for a health overview\n• 'Explain alerts' — to understand threats in plain language\n• 'Give me a tip' — for a daily cybersecurity tip\n• 'What is phishing?' — for awareness education"
    else:
        return "I'm here to help! The system is currently clean with no active threats. You can ask me:\n\n• 'System status' — for a health overview\n• 'Risk score' — to see the threat posture\n• 'Give me a tip' — for a daily cybersecurity tip\n• 'What is ransomware?' — for awareness education"
