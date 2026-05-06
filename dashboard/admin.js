// admin.js - Advanced Alert Management & Admin Controls

let currentAlertsData = [];
let currentEndpointsData = [];

window.addEventListener('alertsDataUpdated', (e) => {
    currentAlertsData = e.detail;
    renderTriageBoard();
});

window.addEventListener('endpointsDataUpdated', (e) => {
    currentEndpointsData = e.detail;
});

function parseDetails(alert) {
    try {
        return JSON.parse(alert.details);
    } catch(err) {
        return { root_cause: alert.details, remediation: 'N/A', metrics: 'N/A', process_name: 'N/A', destination_ip: 'N/A', source_ip: 'N/A', frequency: 1, is_resolved: false };
    }
}

function renderTriageBoard() {
    const colLow = document.getElementById('alerts-col-low');
    const colMed = document.getElementById('alerts-col-medium');
    const colHigh = document.getElementById('alerts-col-high');
    
    if (!colLow || !colMed || !colHigh) return;
    
    colLow.innerHTML = '';
    colMed.innerHTML = '';
    colHigh.innerHTML = '';
    
    currentAlertsData.forEach(alert => {
        const d = parseDetails(alert);
        const card = document.createElement('div');
        card.style.background = 'rgba(0,0,0,0.3)';
        card.style.padding = '12px';
        card.style.borderRadius = '8px';
        card.style.marginBottom = '10px';
        card.style.fontSize = '12px';
        card.style.borderLeft = `3px solid ${alert.risk_level === 'Low' ? 'var(--accent)' : alert.risk_level === 'Medium' ? 'var(--warning)' : 'var(--critical)'}`;
        
        let content = `
            <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                <strong style="font-size: 13px;">${alert.description}</strong>
                <span style="color: var(--text-muted); font-size: 11px;">${new Date(alert.timestamp * 1000).toLocaleTimeString()}</span>
            </div>
            <div style="color: var(--text-muted); margin-bottom: 8px;">EP: ${alert.endpoint_id}</div>
        `;
        
        if (alert.risk_level === 'Low' || d.is_resolved) {
            // LOW alerts or already resolved alerts
            content += `<div style="background: rgba(16,185,129,0.15); color: var(--accent); padding: 4px 8px; border-radius: 4px; display: inline-block; font-size: 11px;">✔ Resolved ${d.resolved_reason ? '(' + d.resolved_reason + ')' : ''}</div>`;
            card.innerHTML = content;
            colLow.appendChild(card);
        } else {
            // MEDIUM or HIGH/CRITICAL alerts
            content += `<button class="action-btn resolve-btn" style="width: 100%; margin-top: 5px;" onclick="handleCheck('${alert.id}')">CHECK</button>`;
            card.innerHTML = content;
            if (alert.risk_level === 'Medium') colMed.appendChild(card);
            else colHigh.appendChild(card);
        }
    });
}

let activeAlertId = null;

window.handleCheck = function(alertId) {
    const alert = currentAlertsData.find(a => a.id === alertId);
    if (!alert) return;
    openAlertModal(alert);
};

window.openAlertModal = function(alert) {
    if (!alert) return;
    const d = parseDetails(alert);
    activeAlertId = alert.id;
    
    document.getElementById('modal-alert-title').textContent = alert.description;
    document.getElementById('modal-alert-endpoint').textContent = alert.endpoint_id;
    document.getElementById('modal-alert-severity').textContent = alert.risk_level;
    document.getElementById('modal-alert-time').textContent = new Date(alert.timestamp * 1000).toLocaleString();
    document.getElementById('modal-alert-process').textContent = d.process_name || 'N/A';
    document.getElementById('modal-alert-ip').textContent = d.destination_ip || 'N/A';
    document.getElementById('modal-alert-usage').textContent = d.metrics || "N/A";
    document.getElementById('modal-alert-cause').textContent = d.root_cause || alert.details;
    document.getElementById('modal-alert-fix').textContent = d.remediation || "N/A";
    
    // Color code the severity
    const severityEl = document.getElementById('modal-alert-severity');
    severityEl.style.color = alert.risk_level === 'Critical' || alert.risk_level === 'High' ? 'var(--critical)' : 'var(--warning)';
    
    document.getElementById('alert-modal').style.display = 'flex';
};

document.getElementById('btn-mark-resolved').addEventListener('click', async () => {
    if (!activeAlertId) return;
    try {
        await fetch(`http://127.0.0.1:5000/api/alerts/resolve/${activeAlertId}`, { method: 'POST' });
        document.getElementById('alert-modal').style.display = 'none';
        // Force refresh
        if (window.updateDashboard) window.updateDashboard();
    } catch(e) { alert("Failed to resolve alert"); }
});

document.getElementById('btn-mark-fp').addEventListener('click', async () => {
    if (!activeAlertId) return;
    try {
        await fetch(`http://127.0.0.1:5000/api/alerts/false_positive/${activeAlertId}`, { method: 'POST' });
        document.getElementById('alert-modal').style.display = 'none';
        // Force refresh
        if (window.updateDashboard) window.updateDashboard();
    } catch(e) { alert("Failed to mark as false positive"); }
});

// Endpoint Detail View Logic
let currentEndpointViewId = null;

// Feature 8: Admin System Isolation Control
window.isolateEndpoint = async function(endpoint_id) {
    if (!confirm(`Are you sure you want to ISOLATE ${endpoint_id}?\nThis will block all network communication for this device.`)) return;
    try {
        await fetch(`http://127.0.0.1:5000/api/endpoints/isolate/${endpoint_id}`, { method: 'POST' });
        alert(`🔒 SYSTEM ISOLATED\n${endpoint_id} has been successfully isolated from the network.\nAction logged to blockchain ledger.`);
        if (window.updateDashboard) window.updateDashboard();
    } catch(e) { alert("Failed to isolate system."); }
};

window.openEndpointDetails = function(endpoint_id) {
    currentEndpointViewId = endpoint_id;
    document.getElementById('modal-ep-title').textContent = `Endpoint Details: ${endpoint_id}`;
    
    // Feature 8: Show ISOLATE SYSTEM button for admins
    const roleSpan = document.getElementById('current-user-role');
    const isolateBtn = document.getElementById('btn-admin-isolate');
    
    // Check for "Admin" or "ADMIN" (case insensitive)
    const isAdmin = roleSpan && roleSpan.textContent.trim().toUpperCase() === 'ADMIN';
    
    if (isAdmin) {
        isolateBtn.style.display = 'block';
    } else {
        isolateBtn.style.display = 'none';
    }
    
    const epAlerts = currentAlertsData.filter(a => a.endpoint_id === endpoint_id);
    let medCount = 0;
    let highCount = 0;
    
    const listHtml = document.getElementById('modal-ep-alerts-list');
    listHtml.innerHTML = '';
    
    epAlerts.forEach(alert => {
        const d = parseDetails(alert);
        if (alert.risk_level === 'Low' || d.is_resolved) return;
        
        if (alert.risk_level === 'Medium') medCount++;
        else highCount++;
        
        const card = document.createElement('div');
        card.style.background = 'rgba(0,0,0,0.3)';
        card.style.padding = '12px';
        card.style.borderRadius = '8px';
        card.style.borderLeft = `3px solid ${alert.risk_level === 'Medium' ? 'var(--warning)' : 'var(--critical)'}`;
        
        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                <strong style="color: var(--text-main); font-size: 14px;">${alert.description}</strong>
                <span style="color: var(--text-muted); font-size: 12px;">${new Date(alert.timestamp * 1000).toLocaleString()}</span>
            </div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 5px;">${d.root_cause || alert.details}</p>
            <p style="font-size: 12px; color: var(--accent); margin-bottom: 10px;">Fix: ${d.remediation || 'N/A'}</p>
            <div style="display: flex; gap: 10px;">
                <button class="action-btn resolve-btn" onclick="handleCheck('${alert.id}')">Resolve Threat</button>
            </div>
        `;
        listHtml.appendChild(card);
    });
    
    if (listHtml.innerHTML === '') {
        listHtml.innerHTML = '<div style="color: var(--text-muted); padding: 20px; text-align: center;">No active Medium/High threats for this endpoint.</div>';
    }
    
    document.getElementById('modal-ep-med-count').textContent = medCount;
    document.getElementById('modal-ep-high-count').textContent = highCount;
    
    document.getElementById('endpoint-modal').style.display = 'flex';
};

// Feature 8: Admin System Isolation Control
document.getElementById('btn-admin-isolate').addEventListener('click', () => {
    if (!currentEndpointViewId) return;
    window.isolateEndpoint(currentEndpointViewId);
    document.getElementById('endpoint-modal').style.display = 'none';
});

// Feature 7: Real-Time Alerts Section (JSON Summary Modal)
window.openRealtimeAlertJson = function(alert) {
    const d = parseDetails(alert);
    const summary = {
        alert_id: alert.id,
        endpoint_mac: alert.endpoint_id,
        ip_address: d.destination_ip || "N/A",
        process: d.process_name || "N/A",
        severity: alert.risk_level,
        cpu_usage: d.metrics ? d.metrics.split(',')[0] : "N/A",
        timestamp: new Date(alert.timestamp * 1000).toISOString(),
        description: alert.description,
        mitigation: d.remediation || "N/A"
    };
    
    document.getElementById('json-modal-content').textContent = JSON.stringify(summary, null, 2);
    document.getElementById('json-modal').style.display = 'flex';
};

// Admin Access - Registered Endpoints
document.addEventListener('DOMContentLoaded', () => {
    const roleSpan = document.getElementById('current-user-role');
    const registerBtn = document.getElementById('btn-open-register');
    
    if (roleSpan && roleSpan.textContent.trim().toUpperCase() === 'ADMIN') {
        if (registerBtn) registerBtn.style.display = 'block';
    }
    
    if (registerBtn) {
        registerBtn.addEventListener('click', () => {
            document.getElementById('admin-modal').style.display = 'flex';
            loadRegisteredEndpoints();
        });
    }
});

async function loadRegisteredEndpoints() {
    try {
        const res = await fetch('http://127.0.0.1:5000/api/endpoints/registered');
        const data = await res.json();
        const list = document.getElementById('admin-ep-list');
        list.innerHTML = '';
        data.forEach(ep => {
            const div = document.createElement('div');
            div.style.display = 'flex';
            div.style.justifyContent = 'space-between';
            div.style.padding = '8px';
            div.style.background = 'rgba(0,0,0,0.3)';
            div.style.marginBottom = '5px';
            div.style.borderRadius = '4px';
            
            div.innerHTML = `
                <div>
                    <strong style="color: var(--accent);">${ep.device_name}</strong>
                    <div style="color: var(--text-muted);">${ep.mac_address}</div>
                </div>
                <button class="action-btn isolate-btn" onclick="removeRegisteredEndpoint('${ep.mac_address}')" style="padding: 4px 8px;">Remove</button>
            `;
            list.appendChild(div);
        });
    } catch(e) { console.error("Failed to load registered endpoints", e); }
}

window.removeRegisteredEndpoint = async function(mac) {
    try {
        await fetch(`http://127.0.0.1:5000/api/endpoints/${mac}`, { method: 'DELETE' });
        loadRegisteredEndpoints();
    } catch(e) { alert("Failed to remove endpoint"); }
};

document.getElementById('btn-register-ep').addEventListener('click', async () => {
    const mac = document.getElementById('admin-mac-input').value.trim();
    const name = document.getElementById('admin-device-input').value.trim();
    if (!mac || !name) return alert("Please enter MAC Address and Device Name");
    
    try {
        await fetch('http://127.0.0.1:5000/api/endpoints/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac_address: mac, device_name: name })
        });
        document.getElementById('admin-mac-input').value = '';
        document.getElementById('admin-device-input').value = '';
        loadRegisteredEndpoints();
    } catch(e) { alert("Failed to register endpoint"); }
});
