from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# Enable CORS so the local HTML file can communicate with the backend
CORS(app)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        
        # Extract features (cast to int, treating missing values as 0)
        internet = int(data.get('internet', 0))
        sms = int(data.get('sms', 0))
        contacts = int(data.get('contacts', 0))
        camera = int(data.get('camera', 0))
        audio = int(data.get('audio', 0))
        
        # Simple rule-based logic to detect malicious activity based on permissions.
        # Often, malware asks for SMS, Contacts, and other sensitive permissions together.
        suspicious_score = internet + sms + contacts + camera + audio
        
        if suspicious_score >= 3:
            prediction = "Malicious App Detected"
        elif sms == 1 and contacts == 1:
            # High risk combination
            prediction = "Malicious App Detected"
        else:
            prediction = "Benign App"
            
        return jsonify({
            'prediction': prediction,
            'score': suspicious_score
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    # Run the Flask app on localhost (127.0.0.1) on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
