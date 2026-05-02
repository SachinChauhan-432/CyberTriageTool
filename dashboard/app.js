document.addEventListener('DOMContentLoaded', () => {
    // ==========================================
    // PHASE 9: RBAC
    // ==========================================
    let currentRole = 'viewer';

    const loginOverlay = document.getElementById('login-overlay');
    const loginBtn = document.getElementById('login-btn');
    const roleSelect = document.getElementById('role-select');
    const roleLabel = document.getElementById('current-user-role');

    loginBtn.addEventListener('click', () => {
        currentRole = roleSelect.value;
        loginOverlay.style.display = 'none';
        roleLabel.textContent = currentRole.charAt(0).toUpperCase() + currentRole.slice(1);
        updateDashboard();
    });

    function canResolveAlerts() { return currentRole === 'admin' || currentRole === 'analyst'; }
    function canControlDevices() { return currentRole === 'admin'; }

    // ==========================================
    // Navigation
    // ==========================================
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.view');
    const viewTitle = document.getElementById('view-title');

    const viewTitles = {
        'dashboard': 'Overview Dashboard',
        'alerts': 'Threat Alerts',
        'endpoints': 'Endpoint Management',
        'blockchain': 'Blockchain Audit Ledger',
        'ai-assistant': 'AI Cybersecurity Assistant'
    };

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            views.forEach(v => v.classList.remove('active'));
            item.classList.add('active');
            const targetId = item.getAttribute('data-target');
            const targetView = document.getElementById(targetId);
            if (targetView) targetView.classList.add('active');
            if (viewTitle) viewTitle.textContent = viewTitles[targetId] || 'Dashboard';
        });
    });

    // ==========================================
    // API
    // ==========================================
    const API_BASE = 'http://localhost:5000/api';

    async function fetchData(endpoint) {
        try {
            const response = await fetch(`${API_BASE}/${endpoint}`);
            if (!response.ok) throw new Error('Fetch error');
            return await response.json();
        } catch (e) {
            console.error(`Error fetching ${endpoint}:`, e);
            return null;
        }
    }

    async function postAction(endpoint) {
        try {
            const response = await fetch(`${API_BASE}/${endpoint}`, { method: 'POST' });
            return await response.json();
        } catch (e) {
            console.error(`Error posting to ${endpoint}:`, e);
            return null;
        }
    }

    function formatTime(ts) { return new Date(ts * 1000).toLocaleTimeString(); }

    // ==========================================
    // Actions
    // ==========================================
    async function resolveAlert(id) {
        const r = await postAction(`alerts/resolve/${id}`);
        if (r && r.status === 'success') updateDashboard();
    }
    async function isolateEndpoint(id) {
        const r = await postAction(`endpoints/isolate/${id}`);
        if (r) updateDashboard();
    }
    window.resolveAlert = resolveAlert;
    window.isolateEndpoint = isolateEndpoint;

    // ==========================================
    // Risk Score Gauge
    // ==========================================
    function updateRiskGauge(alerts) {
        let critical = 0, high = 0, medium = 0, low = 0;
        alerts.forEach(a => {
            if (a.risk_level === 'Critical') critical++;
            else if (a.risk_level === 'High') high++;
            else if (a.risk_level === 'Medium') medium++;
            else low++;
        });

        document.getElementById('risk-critical').textContent = critical;
        document.getElementById('risk-high').textContent = high;
        document.getElementById('risk-medium').textContent = medium;
        document.getElementById('risk-low').textContent = low;

        // Score: 0 (safe) to 100 (dire)
        const score = Math.min(100, critical * 25 + high * 10 + medium * 3 + low * 1);

        // Gauge arc
        const maxDash = 251.2;
        const fillDash = maxDash - (score / 100) * maxDash;
        const gaugeFill = document.getElementById('gauge-fill');
        const gaugeText = document.getElementById('gauge-text');
        const gaugeLabel = document.getElementById('gauge-label');
        const statRisk = document.getElementById('stat-risk');

        gaugeFill.style.strokeDashoffset = fillDash;

        let color, label;
        if (score <= 20) {
            color = '#10b981'; label = 'Low Risk';
        } else if (score <= 50) {
            color = '#f59e0b'; label = 'Moderate Risk';
        } else if (score <= 75) {
            color = '#f97316'; label = 'High Risk';
        } else {
            color = '#ef4444'; label = 'Critical Risk';
        }

        gaugeFill.style.stroke = color;
        gaugeText.textContent = score;
        gaugeLabel.textContent = label;
        statRisk.textContent = `${score}/100`;
        statRisk.style.color = color;
    }

    // ==========================================
    // System Health Bars
    // ==========================================
    function updateHealthBars(endpoints, bcData) {
        if (!endpoints || endpoints.length === 0) return;

        const avgCpu = endpoints.reduce((a, e) => a + e.cpu_usage, 0) / endpoints.length;
        const avgMem = endpoints.reduce((a, e) => a + e.memory_usage, 0) / endpoints.length;

        const cpuBar = document.getElementById('health-cpu');
        const memBar = document.getElementById('health-mem');
        const netBar = document.getElementById('health-net');

        if (cpuBar) {
            cpuBar.style.width = `${avgCpu}%`;
            cpuBar.style.background = avgCpu > 80 ? 'var(--critical)' : avgCpu > 50 ? 'var(--warning)' : 'var(--primary)';
        }
        document.getElementById('health-cpu-val').textContent = `${avgCpu.toFixed(1)}%`;

        if (memBar) {
            memBar.style.width = `${avgMem}%`;
            memBar.style.background = avgMem > 80 ? 'var(--warning)' : 'var(--accent)';
        }
        document.getElementById('health-mem-val').textContent = `${avgMem.toFixed(1)}%`;

        if (netBar) {
            netBar.style.width = '60%';
            netBar.style.background = 'var(--info)';
        }
        document.getElementById('health-net-val').textContent = 'Stable';

        if (bcData && bcData.is_valid !== undefined) {
            const bcBar = document.getElementById('health-bc');
            if (bcBar) {
                bcBar.style.width = '100%';
                bcBar.style.background = bcData.is_valid ? 'var(--accent)' : 'var(--critical)';
            }
            document.getElementById('health-bc-val').textContent = bcData.is_valid ? 'Secured' : 'Tampered!';
        }
    }

    // ==========================================
    // Main Dashboard Update
    // ==========================================
    async function updateDashboard() {
        const endpointsData = await fetchData('endpoints');
        const alertsData = await fetchData('alerts');
        const blockchainData = await fetchData('blockchain');

        // ---- Stat Cards ----
        if (endpointsData) {
            document.getElementById('stat-endpoints').textContent = endpointsData.length;
            if (endpointsData.length > 0) {
                const avgCpu = (endpointsData.reduce((a, e) => a + e.cpu_usage, 0) / endpointsData.length).toFixed(1);
                document.getElementById('stat-cpu').textContent = `${avgCpu}%`;
            }

            // Dashboard: Endpoint Feed
            const epFeed = document.getElementById('dashboard-endpoints');
            epFeed.innerHTML = '';
            endpointsData.forEach(ep => {
                const isOnline = ep.status.includes('Online');
                const div = document.createElement('div');
                div.className = 'endpoint-item';
                div.innerHTML = `
                    <div class="ep-info">
                        <span class="ep-name">${ep.endpoint_id}</span>
                        <span class="ep-status" style="color:${isOnline ? 'var(--accent)' : 'var(--critical)'}">${ep.status}</span>
                    </div>
                    <div class="ep-metrics">
                        CPU: ${ep.cpu_usage}%<br>
                        Mem: ${ep.memory_usage}%
                    </div>
                `;
                epFeed.appendChild(div);
            });

            // Endpoints Tab
            const epTbody = document.getElementById('endpoints-table-body');
            if (epTbody) {
                epTbody.innerHTML = '';
                endpointsData.forEach(ep => {
                    const isOnline = ep.status.includes('Online');
                    const tr = document.createElement('tr');
                    let actionsHtml = canControlDevices()
                        ? `<button class="action-btn isolate-btn" onclick="isolateEndpoint('${ep.endpoint_id}')">🔒 Isolate</button>`
                        : `<span style="color:var(--text-muted); font-size:11px;">Requires Admin</span>`;

                    tr.innerHTML = `
                        <td><strong>${ep.endpoint_id}</strong><br><span style="font-size:11px; color:var(--text-muted)">Last: ${formatTime(ep.last_seen)}</span></td>
                        <td><span class="badge" style="background:${isOnline ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'}; color:${isOnline ? 'var(--accent)' : 'var(--critical)'};">${ep.status}</span></td>
                        <td>
                            <div class="metric-bar-container"><div class="metric-bar" style="width:${ep.cpu_usage}%; background:${ep.cpu_usage > 80 ? 'var(--critical)' : 'var(--primary)'}"></div></div>
                            <span style="font-size:12px;">${ep.cpu_usage}%</span>
                        </td>
                        <td>
                            <div class="metric-bar-container"><div class="metric-bar" style="width:${ep.memory_usage}%; background:${ep.memory_usage > 80 ? 'var(--warning)' : 'var(--accent)'}"></div></div>
                            <span style="font-size:12px;">${ep.memory_usage}%</span>
                        </td>
                        <td>${actionsHtml}</td>
                    `;
                    epTbody.appendChild(tr);
                });
            }
        }

        // ---- Alerts ----
        if (alertsData) {
            document.getElementById('stat-threats').textContent = alertsData.length;
            updateRiskGauge(alertsData);

            // Dashboard: Recent Alerts
            const alertsFeed = document.getElementById('dashboard-alerts');
            alertsFeed.innerHTML = '';
            if (alertsData.length === 0) {
                alertsFeed.innerHTML = '<div class="loading">No active threats detected. System is clean.</div>';
            }
            alertsData.slice(0, 6).forEach(alert => {
                let d;
                try { d = JSON.parse(alert.details); } catch(e) { d = { root_cause: alert.details }; }
                const div = document.createElement('div');
                div.className = `alert-item ${alert.risk_level}`;
                div.innerHTML = `
                    <div class="alert-header">
                        <span class="alert-title">${alert.description}</span>
                        <span class="alert-time">${formatTime(alert.timestamp)}</span>
                    </div>
                    <div class="alert-details">${d.root_cause || alert.details}</div>
                `;
                alertsFeed.appendChild(div);
            });

            // Alerts Tab
            const tbody = document.getElementById('alerts-table-body');
            tbody.innerHTML = '';
            alertsData.forEach(alert => {
                let d;
                try { d = JSON.parse(alert.details); }
                catch(e) {
                    d = { root_cause: alert.details, remediation: 'N/A', metrics: 'N/A', process_name: 'N/A', destination_ip: 'N/A', source_ip: 'N/A', frequency: 1 };
                }

                let actionsHtml = canResolveAlerts()
                    ? `<button class="action-btn resolve-btn" onclick="resolveAlert('${alert.id}')">✔ Resolve</button>`
                    : `<span style="color:var(--text-muted); font-size:11px;">Read Only</span>`;

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${formatTime(alert.timestamp)}<br><span style="font-size:11px; color:var(--text-muted)">×${d.frequency || 1}</span></td>
                    <td>${alert.endpoint_id}<br><span style="font-size:11px; color:var(--text-muted)">IP: ${d.source_ip || 'N/A'}</span></td>
                    <td><span class="badge ${alert.risk_level}">${alert.risk_level}</span></td>
                    <td>
                        <strong>${alert.description}</strong><br>
                        <span style="font-size:12px; color:var(--text-muted)">Proc: ${d.process_name} → ${d.destination_ip}</span><br>
                        <span style="font-size:11px; color:var(--text-muted)">${d.metrics}</span>
                    </td>
                    <td>
                        <div style="margin-bottom:4px; font-size:12px;"><strong style="color:var(--warning);">Cause:</strong> ${d.root_cause}</div>
                        <div style="font-size:12px;"><strong style="color:var(--accent);">Fix:</strong> ${d.remediation}</div>
                    </td>
                    <td>${actionsHtml}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        // ---- System Health ----
        updateHealthBars(endpointsData, blockchainData);

        // ---- Blockchain ----
        if (blockchainData && blockchainData.chain) {
            const bcStatus = document.getElementById('blockchain-status');
            if (blockchainData.is_valid) {
                bcStatus.textContent = '✔ Cryptographic Integrity Verified';
                bcStatus.style.color = 'var(--accent)';
            } else {
                bcStatus.textContent = '✖ Ledger Tampered!';
                bcStatus.style.color = 'var(--critical)';
            }

            const bcContainer = document.getElementById('blockchain-container');
            if (bcContainer) {
                bcContainer.innerHTML = '';
                [...blockchainData.chain].reverse().forEach(block => {
                    const div = document.createElement('div');
                    div.style = 'background:rgba(0,0,0,0.2); padding:16px; border-radius:10px; border-left:4px solid var(--secondary); font-family:monospace;';

                    let dataStr = typeof block.data === 'string' ? block.data : JSON.stringify(block.data, null, 2);
                    let typeColor = '#a78bfa';
                    if (typeof block.data === 'object') {
                        if (block.data.type === 'ALERT') typeColor = '#fca5a5';
                        else if (block.data.type === 'AUTOMATED_RESPONSE') typeColor = '#fcd34d';
                        else if (block.data.type === 'ADMIN_ACTION') typeColor = '#6ee7b7';
                    }

                    div.innerHTML = `
                        <div style="display:flex; justify-content:space-between; color:var(--text-muted); margin-bottom:8px;">
                            <span>Block #${block.index}</span>
                            <span>${formatTime(block.timestamp)}</span>
                        </div>
                        <div style="font-size:11px; word-break:break-all; margin-bottom:8px; color:${typeColor};">
                            <strong>Hash:</strong> ${block.hash}<br>
                            <strong>Prev:</strong> ${block.previous_hash}
                        </div>
                        <div style="background:rgba(0,0,0,0.3); padding:8px; border-radius:6px; font-size:11px; white-space:pre-wrap; overflow-x:auto; color:var(--text-main);">${dataStr}</div>
                    `;
                    bcContainer.appendChild(div);
                });
            }
        }
    }

    // ---- Polling ----
    updateDashboard();
    setInterval(updateDashboard, 3000);

    // ==========================================
    // AI Assistant (Backend-Powered)
    // ==========================================
    const chatInput = document.getElementById('chat-input');
    const sendBtn = document.getElementById('send-chat');
    const chatWindow = document.getElementById('chat-window');

    function appendMessage(text, sender) {
        const msg = document.createElement('div');
        msg.className = `message ${sender}`;
        // Support newlines in AI responses
        msg.innerHTML = text.replace(/\n/g, '<br>');
        chatWindow.appendChild(msg);
        chatWindow.scrollTop = chatWindow.scrollHeight;
    }

    function showTypingIndicator() {
        const typing = document.createElement('div');
        typing.className = 'message ai typing-indicator';
        typing.id = 'typing-indicator';
        typing.innerHTML = '<span class="dot"></span><span class="dot"></span><span class="dot"></span>';
        chatWindow.appendChild(typing);
        chatWindow.scrollTop = chatWindow.scrollHeight;
    }

    function removeTypingIndicator() {
        const el = document.getElementById('typing-indicator');
        if (el) el.remove();
    }

    async function handleChat() {
        const val = chatInput.value.trim();
        if (!val) return;
        appendMessage(val, 'user');
        chatInput.value = '';
        sendBtn.disabled = true;

        showTypingIndicator();

        try {
            const response = await fetch(`${API_BASE}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: val })
            });
            const data = await response.json();
            removeTypingIndicator();
            appendMessage(data.response || "I'm sorry, I couldn't process that request.", 'ai');
        } catch (e) {
            removeTypingIndicator();
            appendMessage("⚠️ Unable to reach the AI engine. Please ensure the Analytics Engine is running.", 'ai');
        }

        sendBtn.disabled = false;
        chatInput.focus();
    }

    // Suggested prompts
    const suggestedPrompts = document.getElementById('suggested-prompts');
    if (suggestedPrompts) {
        suggestedPrompts.addEventListener('click', (e) => {
            if (e.target.classList.contains('prompt-chip')) {
                chatInput.value = e.target.textContent;
                handleChat();
            }
        });
    }

    sendBtn.addEventListener('click', handleChat);
    chatInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') handleChat(); });
});
