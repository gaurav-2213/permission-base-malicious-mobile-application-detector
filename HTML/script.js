document.getElementById('permissionForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    // Get interactive elements
    const btn = document.getElementById('submitBtn');
    const resultBox = document.getElementById('resultBox');
    const predictionText = document.getElementById('predictionText');
    
    // Set active/loading state visually
    const originalBtnText = btn.textContent;
    btn.textContent = 'Analyzing...';
    btn.disabled = true;
    resultBox.classList.add('hidden');
    
    // Parse input fields features
    const data = {
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