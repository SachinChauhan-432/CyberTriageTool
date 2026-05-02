import os
import time

class ThreatIntelligence:
    def __init__(self):
        # Simulated global threat database downloaded from Open-Source Feeds (e.g. AlienVault OTX, AbuseIPDB)
        self.malicious_ips = {
            "185.15.11.2": "Known Emotet C2 Server",
            "45.22.1.99": "Ransomware Payment Gateway",
            "91.200.12.14": "Cobalt Strike Beacon Drop",
            "192.168.1.100": "Local Network Scanner (Suspicious)" # For local testing
        }
        
        self.malicious_processes = {
            "wannacry.exe": "WannaCry Ransomware",
            "ryuk.exe": "Ryuk Ransomware",
            "mimikatz.exe": "Credential Dumper",
            "ncat.exe": "Reverse Shell Utility",
            "psexec.exe": "Lateral Movement Tool (Unverified)"
        }
        
        self.last_updated = time.time()
        
    def update_feeds(self):
        """Simulates reaching out to global threat intelligence databases to pull the latest IOCs (Indicators of Compromise)."""
        # In a production environment, this would HTTP GET from VirusTotal/AlienVault
        self.last_updated = time.time()
        print("[*] Threat Intelligence Feeds Updated Successfully.")
        
    def check_ip(self, ip_address):
        """Cross-checks an IP against the known malicious database."""
        if ip_address in self.malicious_ips:
            return {
                "is_malicious": True,
                "threat_name": self.malicious_ips[ip_address]
            }
        return {"is_malicious": False}
        
    def check_process(self, process_name):
        """Cross-checks a process name (or signature) against known malware families."""
        p_lower = process_name.lower()
        if p_lower in self.malicious_processes:
            return {
                "is_malicious": True,
                "threat_name": self.malicious_processes[p_lower]
            }
            
        # Basic heuristic for common generic malicious names not caught by exact match
        generic_keywords = ["miner", "crypt", "hack", "payload", "ransom"]
        for kw in generic_keywords:
            if kw in p_lower:
                return {
                    "is_malicious": True,
                    "threat_name": f"Generic Suspicious Signature ({kw})"
                }
                
        return {"is_malicious": False}

# Singleton instance
ti_engine = ThreatIntelligence()
