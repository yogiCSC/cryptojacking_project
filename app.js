// Global Chart Variables
let telemetryChart;
const maxDataPoints = 20;
let chartLabels = [];
let cpuData = [];
let memoryData = [];

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    fetchDashboardData();
    
    // Polling intervals
    setInterval(fetchDashboardData, 2000);
    
    // Event listeners
    document.getElementById('btn-train').addEventListener('click', retrainModel);
    document.getElementById('btn-clear').addEventListener('click', clearAlerts);
    document.getElementById('proc-search').addEventListener('input', filterProcesses);
});

// Initialize Chart.js
function initChart() {
    const ctx = document.getElementById('telemetryChart').getContext('2d');
    
    // Initialize blank data
    for (let i = 0; i < maxDataPoints; i++) {
        chartLabels.push('');
        cpuData.push(0);
        memoryData.push(0);
    }
    
    telemetryChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [
                {
                    label: 'CPU %',
                    data: cpuData,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Memory %',
                    data: memoryData,
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false // We use custom legends in HTML
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(38, 56, 89, 0.2)'
                    },
                    ticks: {
                        display: false
                    }
                },
                y: {
                    min: 0,
                    max: 100,
                    grid: {
                        color: 'rgba(38, 56, 89, 0.2)'
                    },
                    ticks: {
                        color: '#9ca3af',
                        font: {
                            family: 'Outfit',
                            size: 10
                        }
                    }
                }
            }
        }
    });
}

// Update telemetry charts
function updateChart(cpu, memory) {
    cpuData.push(cpu);
    cpuData.shift();
    
    memoryData.push(memory);
    memoryData.shift();
    
    telemetryChart.update('none'); // silent update without reset animations
}

// Fetch all system logs & endpoints
async function fetchDashboardData() {
    try {
        const [statusRes, procRes, alertsRes] = await Promise.all([
            fetch('/api/status'),
            fetch('/api/processes'),
            fetch('/api/alerts')
        ]);
        
        if (statusRes.ok) {
            const status = await statusRes.json();
            updateStatusUI(status);
        }
        
        if (procRes.ok) {
            const processes = await procRes.json();
            updateProcessTable(processes);
        }
        
        if (alertsRes.ok) {
            const alerts = await alertsRes.json();
            updateAlertsList(alerts);
        }
    } catch (e) {
        console.error("Error updating dashboard stats: ", e);
    }
}

// Update status badges and alerts UI
function updateStatusUI(data) {
    const badge = document.getElementById('status-badge');
    const ring = document.getElementById('status-ring');
    const statusIcon = document.getElementById('status-icon');
    const cardTitle = document.getElementById('security-state-title');
    const cardDesc = document.getElementById('security-state-desc');
    const cpuText = document.getElementById('cpu-percentage-text');
    const card = document.getElementById('status-card');
    
    // Model fields
    document.getElementById('model-status').textContent = data.model_status;
    document.getElementById('collected-logs').textContent = data.log_count;
    
    // CPU load text
    cpuText.textContent = Math.round(data.cpu_percent) + "%";
    
    // Conic gradient ring matching CPU %
    if (data.is_secure) {
        ring.style.background = `conic-gradient(var(--accent-blue) ${data.cpu_percent}%, rgba(38, 56, 89, 0.3) 0%)`;
    } else {
        ring.style.background = `conic-gradient(var(--accent-red) ${data.cpu_percent}%, rgba(38, 56, 89, 0.3) 0%)`;
    }
    
    // Update active security states
    if (data.is_secure) {
        badge.className = 'system-status-indicator secure';
        badge.querySelector('.status-label').textContent = 'SECURE';
        
        statusIcon.className = 'fa-solid fa-circle-check main-status-icon';
        statusIcon.style.color = 'var(--accent-green)';
        
        cardTitle.textContent = 'System Status: Secure';
        cardTitle.style.color = 'var(--text-primary)';
        cardDesc.textContent = 'The AI models are monitoring background processes. System behavior is normal.';
        card.style.borderColor = 'var(--card-border)';
    } else {
        badge.className = 'system-status-indicator warning';
        badge.querySelector('.status-label').textContent = 'CRYPTOJACKING DETECTED';
        
        statusIcon.className = 'fa-solid fa-triangle-exclamation main-status-icon';
        statusIcon.style.color = 'var(--accent-red)';
        
        const alert = data.active_alert;
        cardTitle.textContent = 'WARNING: Cryptojacking Detected!';
        cardTitle.style.color = 'var(--accent-red)';
        cardDesc.textContent = `Process "${alert.process_name}" (PID: ${alert.pid}) is consuming abnormal CPU (${alert.cpu_usage}%). Check details and terminate process.`;
        card.style.borderColor = 'var(--accent-red)';
    }
    
    // Update live graph
    updateChart(data.cpu_percent, data.memory_percent);
}

// Update Active Processes list
let lastProcessList = [];
function updateProcessTable(processes) {
    lastProcessList = processes;
    renderProcesses();
}

function renderProcesses() {
    const tbody = document.getElementById('process-table-body');
    const searchVal = document.getElementById('proc-search').value.toLowerCase();
    
    const filtered = lastProcessList.filter(p => p.name.toLowerCase().includes(searchVal) || p.pid.toString().includes(searchVal));
    
    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-table">No processes match the query.</td></tr>`;
        return;
    }
    
    tbody.innerHTML = filtered.map(p => {
        let threatBadgeClass = 'low';
        let threatText = 'Low Risk';
        let rowClass = '';
        
        if (p.risk_score > 0.7) {
            threatBadgeClass = 'high';
            threatText = 'Cryptojacker';
            rowClass = 'style="background-color: rgba(239, 68, 68, 0.05);"';
        } else if (p.risk_score > 0.3) {
            threatBadgeClass = 'medium';
            threatText = 'Suspicious';
            rowClass = 'style="background-color: rgba(245, 158, 11, 0.03);"';
        }
        
        return `
            <tr ${rowClass}>
                <td><code>${p.pid}</code></td>
                <td style="font-weight: 500;">${p.name}</td>
                <td class="num-col">${p.cpu_percent}%</td>
                <td class="num-col">${p.memory_percent}%</td>
                <td><span class="badge ${threatBadgeClass}">${threatText}</span></td>
            </tr>
        `;
    }).join('');
}

function filterProcesses() {
    renderProcesses();
}

// Update Alert incident feed
function updateAlertsList(alerts) {
    const list = document.getElementById('alerts-list');
    const headerIcon = document.getElementById('alerts-header-icon');
    
    if (alerts.length === 0) {
        headerIcon.className = 'fa-solid fa-bell-slash header-icon';
        headerIcon.style.color = 'var(--text-secondary)';
        list.innerHTML = `
            <div class="empty-alerts">
                <i class="fa-solid fa-shield-halved empty-icon"></i>
                <p>No cryptojacking alerts triggered yet</p>
            </div>
        `;
        return;
    }
    
    // Check if there are active unresolved alerts to ring the bell icon
    const activeCount = alerts.filter(a => !a.resolved).length;
    if (activeCount > 0) {
        headerIcon.className = 'fa-solid fa-bell header-icon';
        headerIcon.style.color = 'var(--accent-red)';
        headerIcon.style.animation = 'text-pulse 1s infinite';
    } else {
        headerIcon.className = 'fa-solid fa-bell-slash header-icon';
        headerIcon.style.color = 'var(--accent-green)';
        headerIcon.style.animation = 'none';
    }
    
    list.innerHTML = alerts.map(alert => {
        const timeStr = new Date(alert.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const dateStr = new Date(alert.timestamp * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
        
        let statusText = "Active Threat";
        let statusClass = "";
        let iconClass = "fa-solid fa-triangle-exclamation";
        
        if (alert.resolved) {
            statusText = "Resolved / Stopped";
            statusClass = "resolved";
            iconClass = "fa-solid fa-circle-check";
        }
        
        return `
            <div class="alert-item ${statusClass}">
                <div class="alert-icon">
                    <i class="${iconClass}"></i>
                </div>
                <div class="alert-content">
                    <div class="alert-title">${alert.process_name} (PID: ${alert.pid})</div>
                    <div class="alert-desc">Sustained high CPU usage detected (${alert.cpu_usage}%). Status: ${statusText}</div>
                    <div class="alert-time"><i class="fa-regular fa-clock"></i> ${dateStr} at ${timeStr}</div>
                </div>
            </div>
        `;
    }).join('');
}

// Trigger AI Model Retraining
async function retrainModel() {
    const btn = document.getElementById('btn-train');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Dispatching...`;
    
    try {
        const res = await fetch('/api/train', { method: 'POST' });
        if (res.ok) {
            showToast("Model training job started in the background!");
        } else {
            showToast("Failed to dispatch model training.", true);
        }
    } catch (e) {
        showToast("Error retraining model.", true);
    }
    
    setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-microchip"></i> Retrain Model`;
    }, 3000);
}

// Clear Alerts
async function clearAlerts() {
    try {
        const res = await fetch('/api/clear_alerts', { method: 'POST' });
        if (res.ok) {
            showToast("Active alerts resolved successfully.");
            fetchDashboardData();
        } else {
            showToast("Failed to resolve alerts.", true);
        }
    } catch (e) {
        showToast("Error resolving alerts.", true);
    }
}

// Helper to show modern toast notification
function showToast(message, isError = false) {
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toast-message');
    const toastIcon = toast.querySelector('.toast-icon');
    
    toastMsg.textContent = message;
    
    if (isError) {
        toast.style.borderColor = 'var(--accent-red)';
        toastIcon.className = 'fa-solid fa-circle-exclamation toast-icon';
        toastIcon.style.color = 'var(--accent-red)';
    } else {
        toast.style.borderColor = 'var(--accent-blue)';
        toastIcon.className = 'fa-solid fa-circle-info toast-icon';
        toastIcon.style.color = 'var(--accent-blue)';
    }
    
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 4000);
}
