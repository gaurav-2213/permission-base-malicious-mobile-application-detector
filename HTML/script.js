document.addEventListener('DOMContentLoaded', async () => {
    wireExports();
    wireNotifications();
    await loadHistory();
    await loadTimeline();
    setGauge(null);
});

let toastTimer = null;

function showToast(title, message) {
    const toast = document.getElementById('toast');
    const toastTitle = document.getElementById('toastTitle');
    const toastBody = document.getElementById('toastBody');
    if (!toast || !toastTitle || !toastBody) return;
    toastTitle.textContent = title || 'Alert';
    toastBody.textContent = message || '';
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 4200);
}

function notifyUser(title, body) {
    try {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, { body });
        }
    } catch (e) {
        // ignore
    }
    showToast(title, body);
}

function wireNotifications() {
    const btn = document.getElementById('notifyBtn');
    if (!btn) return;
    btn.addEventListener('click', async () => {
        if (!('Notification' in window)) {
            showToast('Alerts unavailable', 'Your browser does not support notifications. Using in-app alerts only.');
            return;
        }
        if (Notification.permission === 'granted') {
            showToast('Alerts enabled', 'Browser notifications are already enabled.');
            return;
        }
        if (Notification.permission === 'denied') {
            showToast('Alerts blocked', 'Enable notifications in browser settings to receive alerts.');
            return;
        }
        const perm = await Notification.requestPermission();
        if (perm === 'granted') {
            showToast('Alerts enabled', 'You will now receive warning notifications.');
        } else {
            showToast('Alerts disabled', 'Using in-app alerts only.');
        }
    });
}

function wireExports() {
    const pdf = document.getElementById('exportPdfBtn');
    const csv = document.getElementById('exportCsvBtn');
    const json = document.getElementById('exportJsonBtn');

    if (pdf) pdf.addEventListener('click', () => window.open('/export/pdf', '_blank'));
    if (csv) csv.addEventListener('click', () => window.open('/export/csv', '_blank'));
    if (json) json.addEventListener('click', () => window.open('/export/json', '_blank'));
}

function setRadarScanning(isScanning) {
    const radar = document.getElementById('radar');
    if (!radar) return;
    radar.classList.toggle('scanning', !!isScanning);
}

function setGauge(payload) {
    const scoreEl = document.getElementById('scoreValue');
    const riskEl = document.getElementById('riskValue');
    const tierEl = document.getElementById('tierPill');
    const repEl = document.getElementById('reputationValue');
    const modelMeta = document.getElementById('modelMeta');
    const gauge = document.querySelector('.gauge-fg');

    if (!scoreEl || !riskEl || !tierEl || !repEl || !modelMeta || !gauge) return;

    if (!payload) {
        scoreEl.textContent = '--';
        riskEl.textContent = '--';
        repEl.textContent = 'Unknown';
        modelMeta.textContent = '--';
        tierEl.textContent = 'Unknown';
        tierEl.className = 'pill';
        gauge.style.strokeDasharray = `0 100`;
        gauge.style.stroke = 'rgba(34, 211, 238, 0.9)';
        return;
    }

    const score = typeof payload.score_0_100 === 'number'
        ? payload.score_0_100
        : (typeof payload.malware_score === 'number' ? Math.round((1 - payload.malware_score) * 100) : null);
    const risk = typeof payload.malware_risk_0_100 === 'number'
        ? payload.malware_risk_0_100
        : (typeof payload.malware_score === 'number' ? Math.round(payload.malware_score * 100) : null);
    const tier = payload.tier || (score === null ? 'Unknown' : (score >= 90 ? 'Excellent' : score >= 70 ? 'Moderate' : 'Vulnerable'));
    const rep = payload.reputation || 'Unknown';

    scoreEl.textContent = score === null ? '--' : String(score);
    riskEl.textContent = risk === null ? '--' : `${risk}%`;
    repEl.textContent = rep;

    tierEl.textContent = tier;
    tierEl.className = 'pill ' + (tier.toLowerCase());

    if (typeof payload.threshold === 'number') {
        const thresholdPercent = (payload.threshold * 100).toFixed(1);
        modelMeta.textContent = `Threshold ${thresholdPercent}%`;
    } else {
        modelMeta.textContent = 'Heuristic';
    }

    const pct = score === null ? 0 : Math.max(0, Math.min(100, score));
    gauge.style.strokeDasharray = `${pct} 100`;
    if (pct >= 90) gauge.style.stroke = 'rgba(74, 222, 128, 0.95)';
    else if (pct >= 70) gauge.style.stroke = 'rgba(34, 211, 238, 0.95)';
    else gauge.style.stroke = 'rgba(251, 113, 133, 0.95)';
}

function buildExplanation(features, payload) {
    const enabled = Object.entries(features || {}).filter(([, v]) => v === 1).map(([k]) => k);
    const score = payload && typeof payload.score_0_100 === 'number' ? payload.score_0_100 : null;
    const pred = payload && payload.prediction ? payload.prediction : 'Unknown';

    if (!enabled.length) return 'No permissions selected. This typically indicates low risk in this demo.';

    const lines = [];
    const hasSms = enabled.includes('sms');
    const hasContacts = enabled.includes('contacts');
    const hasAudio = enabled.includes('audio');
    const hasCamera = enabled.includes('camera');
    const hasInternet = enabled.includes('internet');

    if (hasSms && hasContacts) {
        lines.push('Combining SMS + Contacts can be used for OTP interception and social-engineering propagation.');
    }
    if (hasAudio && hasCamera) {
        lines.push('Audio + Camera access can enable covert surveillance if abused by malware.');
    }
    if (hasInternet && (hasSms || hasContacts || hasAudio || hasCamera)) {
        lines.push('Network access paired with sensitive permissions can facilitate data exfiltration.');
    }
    if (enabled.length >= 4) {
        lines.push('A broad permission set increases the potential blast radius if the app is compromised.');
    }

    if (!lines.length) {
        lines.push('This permission pattern is not strongly suspicious by itself, but always verify publisher and reviews.');
    }

    if (pred === 'Malicious') {
        lines.push('Model result indicates behavior consistent with malicious apps in the training data.');
    }
    if (score !== null && score < 70) {
        lines.push('Security score is below 70, indicating elevated risk. Consider uninstalling or restricting permissions.');
    } else if (score !== null && score >= 90) {
        lines.push('Security score is high (90+). This looks safer under the current model and rules.');
    }

    return lines.join(' ');
}

document.getElementById('permissionForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    // Get interactive elements
    const btn = document.getElementById('submitBtn');
    const resultBox = document.getElementById('resultBox');
    const predictionText = document.getElementById('predictionText');
    const resultMeta = document.getElementById('resultMeta');
    const aiExplain = document.getElementById('aiExplain');
    
    // Set active/loading state visually
    const originalBtnText = btn.textContent;
    btn.textContent = 'Analyzing...';
    btn.disabled = true;
    resultBox.classList.add('hidden');
    resultMeta.classList.add('hidden');
    resultMeta.textContent = '';
    setRadarScanning(true);
    
    // Parse input fields features
    const data = {
        app_name: document.getElementById('appName').value.trim(),
        internet: document.getElementById('internet').checked ? 1 : 0,
        sms: document.getElementById('sms').checked ? 1 : 0,
        contacts: document.getElementById('contacts').checked ? 1 : 0,
        camera: document.getElementById('camera').checked ? 1 : 0,
        audio: document.getElementById('audio').checked ? 1 : 0
    };
    
    try {
        // Asynchronous POST call to the Flask Server endpoint
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        // Remove 'hidden' so animation triggers
        resultBox.classList.remove('hidden');
        resultBox.className = ''; // reset classes

        if (response.ok) {
            // Success State Handling
            predictionText.textContent = result.prediction;
            if (result.prediction === 'Malicious') {
                resultBox.classList.add('malicious');
            } else {
                resultBox.classList.add('benign');
            }

            if (typeof result.malware_score === 'number' && typeof result.threshold === 'number') {
                const scorePercent = (result.malware_score * 100).toFixed(1);
                const thresholdPercent = (result.threshold * 100).toFixed(1);
                const mode = result.threshold >= 0.45 ? 'Strict' : 'Balanced/Recall-focused';
                resultMeta.textContent = `Malware score: ${scorePercent}% | Threshold: ${thresholdPercent}% | Mode: ${mode}`;
                resultMeta.classList.remove('hidden');
            }

            setGauge(result);
            if (aiExplain) {
                aiExplain.textContent = buildExplanation(result.features, result);
            }
            
            // Refresh history after a successful prediction
            await loadHistory();
            await loadTimeline();

            const score = typeof result.score_0_100 === 'number'
                ? result.score_0_100
                : (typeof result.malware_score === 'number' ? Math.round((1 - result.malware_score) * 100) : null);

            if (result.prediction === 'Malicious' || (typeof score === 'number' && score < 70)) {
                notifyUser(
                    'Warning: High-risk app detected',
                    `${result.app_name ? result.app_name + ': ' : ''}${result.prediction} (Score ${score ?? '--'}/100)`
                );
            }
        } else {
            // Error handling returned from Flask
            predictionText.textContent = 'Error: ' + (result.error || 'Server error');
            resultBox.classList.add('malicious');
            setGauge(null);
            if (aiExplain) aiExplain.textContent = 'Scan failed. Please try again.';
        }
    } catch (error) {
        // Backend failure (e.g. offline)
        console.error('Error fetching prediction:', error);
        resultBox.classList.remove('hidden');
        resultBox.className = 'malicious';
        predictionText.textContent = 'Failed to connect to backend server.';
        setGauge(null);
        if (aiExplain) aiExplain.textContent = 'Backend unreachable. Start the Flask server and retry.';
    } finally {
        // Restore interactive input
        btn.textContent = originalBtnText;
        btn.disabled = false;
        setRadarScanning(false);
    }
});

// Function to fetch and display prediction history
async function loadHistory() {
    const historyList = document.getElementById('historyList');
    try {
        const response = await fetch('/history');
        if (!response.ok) return;
        
        const historyData = await response.json();
        
        if (!historyData || historyData.length === 0) {
            historyList.innerHTML = '<p class="subtitle">No recent checks found.</p>';
            return;
        }

        historyList.innerHTML = ''; // Clear default message
        
        historyData.forEach(item => {
            const pred = item.prediction;
            const features = item.features;
            
            const isMalicious = pred === 'Malicious';
            const statusClass = isMalicious ? 'malicious' : 'benign';
            
            // Create badges for enabled permissions
            let badgesHtml = '';
            for (const [key, val] of Object.entries(features)) {
                if (val === 1) {
                    badgesHtml += `<span class="perm-badge">${key}</span>`;
                }
            }
            if (badgesHtml === '') {
                badgesHtml = '<span class="perm-badge" style="opacity:0.5; border:none; background:transparent; padding:0;">No permissions</span>';
            }
            
            const scoreText = item.score_0_100 !== undefined
                ? ` (Security: ${item.score_0_100}/100)`
                : (item.malware_score !== undefined ? ` (Risk: ${(item.malware_score * 100).toFixed(1)}%)` : '');
            const appNameDisplay = item.app_name ? `<strong>${item.app_name}</strong> - ` : '';

            const historyItem = document.createElement('div');
            historyItem.className = `history-item ${statusClass}`;
            historyItem.innerHTML = `
                <div class="item-status ${statusClass}">${appNameDisplay}${pred}${scoreText}</div>
                <div class="item-badges">${badgesHtml}</div>
            `;
            
            historyList.appendChild(historyItem);
        });
    } catch (e) {
        console.error("Failed to load history:", e);
    }
}

async function loadTimeline() {
    const list = document.getElementById('timelineList');
    if (!list) return;
    try {
        const resp = await fetch('/timeline');
        if (!resp.ok) return;
        const events = await resp.json();
        if (!events || events.length === 0) {
            list.innerHTML = '<p class="subtitle">No events yet.</p>';
            return;
        }
        list.innerHTML = '';

        events.slice(0, 30).forEach(ev => {
            const item = document.createElement('div');
            item.className = 'timeline-item';

            const ts = ev.timestamp ? formatTime(ev.timestamp) : '';
            const appName = ev.app_name ? ev.app_name : 'Unnamed app';

            let title = 'Event';
            let body = '';
            if (ev.type === 'scan') {
                title = 'Scan completed';
                const scoreText = typeof ev.score_0_100 === 'number' ? `${ev.score_0_100}/100` : '--/100';
                body = `${appName} → ${ev.prediction || 'Unknown'} • Score ${scoreText} • ${ev.tier || 'Unknown'} / ${ev.reputation || 'Unknown'}`;
            } else if (ev.type === 'permission_change') {
                title = 'Permission change';
                const changes = Array.isArray(ev.changes) ? ev.changes : [];
                const added = changes.filter(c => c && c.from === 0 && c.to === 1).map(c => c.permission);
                const removed = changes.filter(c => c && c.from === 1 && c.to === 0).map(c => c.permission);
                const parts = [];
                if (added.length) parts.push(`Added: ${added.join(', ')}`);
                if (removed.length) parts.push(`Removed: ${removed.join(', ')}`);
                body = `${appName} • ${parts.join(' • ') || 'Permissions updated'}`;

                if (added.includes('sms') || added.includes('contacts') || added.includes('audio') || added.includes('camera')) {
                    notifyUser(
                        'Warning: Permission change detected',
                        `${appName} requested new sensitive permissions (${added.join(', ')}).`
                    );
                }
            } else {
                body = `${appName}`;
            }

            item.innerHTML = `
                <div class="timeline-top">
                    <div class="timeline-title">${escapeHtml(title)}</div>
                    <div class="timeline-time">${escapeHtml(ts)}</div>
                </div>
                <div class="timeline-body">${escapeHtml(body)}</div>
            `;

            list.appendChild(item);
        });
    } catch (e) {
        console.error('Failed to load timeline:', e);
    }
}

function formatTime(isoString) {
    try {
        const d = new Date(isoString);
        return d.toLocaleString();
    } catch {
        return isoString || '';
    }
}

function escapeHtml(str) {
    return String(str ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}