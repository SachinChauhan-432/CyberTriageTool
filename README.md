# 🛡️ NexusGuard Cybersecurity Platform

NexusGuard is an enterprise-grade cyber-triage platform that uses AI to detect zero-day threats and blockchain to ensure audit integrity.

---

## 🛠️ Prerequisites
Before running the tool, ensure you have the following installed:
1.  **Python 3.8+** (Download from [python.org](https://www.python.org/))
2.  **Web Browser** (Chrome, Firefox, or Edge)

---

## ⚙️ Installation & Setup

### 1. Clone or Extract the Project
Ensure all project files are in a folder on your computer.

### 2. Install Dependencies
Open your terminal (Command Prompt or PowerShell) in the project folder and run:
```bash
pip install -r requirements.txt
```

---

## 🚀 How to Run the Tool

### Step 1: Start the Backend Services
The easiest way to start the entire platform is to use the provided automated startup script. In your terminal, run:
```powershell
.\start.bat
```
*This will automatically launch 4 separate windows: API Gateway, Analytics Engine, Blockchain Logger, and the Endpoint Agent.*

### Step 2: Grant Privacy Consent
A small popup window will appear on your screen asking for permission to monitor system activity. 
- Click **"Yes"** to begin the security monitoring.

### Step 3: Access the Dashboard
Once the services are running, open your web browser and navigate to:
- **`http://localhost:5000`** 
*(Or simply open `dashboard/index.html` directly in your browser).*

---

## 🧠 Using the Platform

### 1. AI Baseline Learning
When you first start, you will see a **"Learning"** status on the dashboard. The AI is observing your normal computer usage to create a "safe profile." After 20 payloads, it will switch to **"Monitoring"** mode.

### 2. Triage Board
Go to the **"Threat Alerts"** tab to see alerts separated into **Low**, **Medium**, and **High** columns. 
- **Low** alerts are handled automatically.
- **Medium/High** alerts require you to click **CHECK** to review and resolve them.

### 3. Admin Tools
As an Admin, you can go to the **"Endpoints"** tab to register new devices or **Isolate** a compromised system from the network with one click.

---

## 📄 Documentation
For more details, please refer to:
- `PROJECT_EXPLANATION.md`: For technical architecture and the "Why" behind the project.
- `USER_WORKFLOW_GUIDE.md`: For a simple, step-by-step guide on how data flows through the system.
