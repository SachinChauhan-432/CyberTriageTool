import os
import sqlite3
import shutil
import tempfile
import time
import getpass
import tkinter as tk
from tkinter import messagebox

class ActivityIngestor:
    def __init__(self):
        self.consent_given = False
        self.user_data = []
        self.username = getpass.getuser()
        
    def request_consent(self):
        """Phase 1: Ask for explicit user consent before accessing activity databases."""
        try:
            root = tk.Tk()
            root.withdraw() # Hide the main window
            
            msg = (
                "NexusGuard Activity Ingestion Module\n\n"
                "To provide advanced behavioral learning, this agent needs to access your Windows Activity History.\n\n"
                "Data to be accessed:\n"
                "- Application usage history\n"
                "- Timestamps\n\n"
                "This data will be kept securely within the NexusGuard platform.\n\n"
                "Do you grant permission to read this data (Read-Only)?"
            )
            
            result = messagebox.askyesno("Privacy Consent Required", msg)
            self.consent_given = result
            root.destroy()
        except Exception as e:
            print(f"[!] UI Consent failed, falling back to console: {e}")
            ans = input("NexusGuard wants to access your Activity History for behavioral learning. Grant permission? (y/n): ")
            self.consent_given = ans.lower().startswith('y')

        return self.consent_given

    def find_activities_cache(self):
        """Phase 2: Dynamically detect the Windows ActivitiesCache.db"""
        localappdata = os.getenv('LOCALAPPDATA')
        if not localappdata:
            return None
            
        cdp_path = os.path.join(localappdata, "ConnectedDevicesPlatform")
        if not os.path.exists(cdp_path):
            return None
            
        # The ActivitiesCache.db is usually inside a user-specific subfolder (e.g., 'L.username')
        for folder in os.listdir(cdp_path):
            folder_path = os.path.join(cdp_path, folder)
            if os.path.isdir(folder_path):
                db_path = os.path.join(folder_path, "ActivitiesCache.db")
                if os.path.exists(db_path):
                    return db_path
                    
        return None

    def ingest_windows_activity(self):
        """Extracts data from the Windows Activity Cache"""
        if not self.consent_given:
            print("[-] Consent denied. Skipping activity ingestion.")
            return self.get_simulated_fallback_data()

        db_path = self.find_activities_cache()
        if not db_path:
            print("[-] ActivitiesCache.db not found. Falling back to simulated historical data.")
            return self.get_simulated_fallback_data()

        print(f"[+] Found Activity DB: {db_path}")
        
        # Phase 10: Failsafe - Copy file to temp location to bypass file locks
        temp_dir = tempfile.gettempdir()
        temp_db_path = os.path.join(temp_dir, "NexusGuard_ActivitiesCache_Temp.db")
        
        try:
            shutil.copy2(db_path, temp_db_path)
        except PermissionError:
            print("[-] Permission Error copying DB. Windows is locking it tightly. Using fallback.")
            return self.get_simulated_fallback_data()
        except Exception as e:
            print(f"[-] Error copying DB: {e}")
            return self.get_simulated_fallback_data()

        try:
            # Connect to the copied DB
            conn = sqlite3.connect(temp_db_path)
            c = conn.cursor()
            
            # The 'Activity' table contains the AppId and Timestamps
            # AppId format is usually JSON or a string like 'WWA:...'
            c.execute('''
                SELECT AppId, StartTime, EndTime, LastModifiedTime
                FROM Activity
                ORDER BY LastModifiedTime DESC
                LIMIT 50
            ''')
            
            rows = c.fetchall()
            conn.close()
            
            parsed_data = []
            for row in rows:
                app_id = str(row[0])
                # Clean up the AppId string a bit for readability
                app_name = app_id.split('/')[-1].split('\\')[-1].split('!')[0]
                if len(app_name) > 30:
                    app_name = app_name[:30] + "..."
                    
                parsed_data.append({
                    "user": self.username,
                    "app_name": app_name,
                    "timestamp": row[3], # LastModifiedTime
                    "activity_type": "app_usage",
                    "source": "windows_timeline"
                })
                
            # Clean up temp file
            os.remove(temp_db_path)
            
            if not parsed_data:
                return self.get_simulated_fallback_data()
                
            return parsed_data
            
        except sqlite3.OperationalError:
            print("[-] SQLite Operational Error (DB might be locked or encrypted). Using fallback.")
            return self.get_simulated_fallback_data()
        except Exception as e:
            print(f"[-] Error parsing Activity DB: {e}")
            return self.get_simulated_fallback_data()

    def get_simulated_fallback_data(self):
        """Phase 10: Failsafe Simulated Data if real ingestion fails"""
        print("[*] Generating Safe Historical Baseline (Fallback)")
        now = time.time()
        return [
            {"user": self.username, "app_name": "chrome.exe", "timestamp": now - 3600, "activity_type": "web_browsing", "source": "simulated"},
            {"user": self.username, "app_name": "code.exe", "timestamp": now - 7200, "activity_type": "development", "source": "simulated"},
            {"user": self.username, "app_name": "explorer.exe", "timestamp": now - 86400, "activity_type": "system", "source": "simulated"},
            {"user": self.username, "app_name": "teams.exe", "timestamp": now - 172800, "activity_type": "communication", "source": "simulated"}
        ]

if __name__ == "__main__":
    ingestor = ActivityIngestor()
    if ingestor.request_consent():
        data = ingestor.ingest_windows_activity()
        print(f"[+] Ingested {len(data)} activity records.")
        for d in data[:5]:
            print(f"    - {d['app_name']} at {d['timestamp']}")
    else:
        print("[-] Operation aborted by user.")
