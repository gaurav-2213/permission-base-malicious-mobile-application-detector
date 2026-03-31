document.addEventListener('DOMContentLoaded', loadHistory);

document.getElementById('permissionForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    // Get interactive elements
    const btn = document.getElementById('submitBtn');
    const resultBox = document.getElementById('resultBox');
    const predictionText = document.getElementById('predictionText');
    const resultMeta = document.getElementById('resultMeta');
    
    // Set active/loading state visually
    const originalBtnText = btn.textContent;
    btn.textContent = 'Analyzing...';
    btn.disabled = true;
    resultBox.classList.add('hidden');
    resultMeta.classList.add('hidden');
    resultMeta.textContent = '';
    
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
            
            // Refresh history after a successful prediction
            await loadHistory();
        } else {
            // Error handling returned from Flask
            predictionText.textContent = 'Error: ' + (result.error || 'Server error');
            resultBox.classList.add('malicious');
        }
    } catch (error) {
        // Backend failure (e.g. offline)
        console.error('Error fetching prediction:', error);
        resultBox.classList.remove('hidden');
        resultBox.className = 'malicious';
        predictionText.textContent = 'Failed to connect to backend server.';
    } finally {
        // Restore interactive input
        btn.textContent = originalBtnText;
        btn.disabled = false;
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
            
            const scoreText = item.malware_score !== undefined ? ` (Score: ${(item.malware_score * 100).toFixed(1)}%)` : '';
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