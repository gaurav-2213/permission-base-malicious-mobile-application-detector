from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import joblib
import traceback

app = Flask(__name__, static_folder='HTML', static_url_path='/')
CORS(app) # Enable CORS for frontend API requests if accessed outside static routing

# Load the trained ML model
try:
    model = joblib.load('model.pkl')
    print("Model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

@app.route('/')
def home():
    """Serves the frontend HTML app"""
    return send_from_directory('HTML', 'index.html')

@app.route('/<path:path>')
def send_static(path):
    """Serves other frontend static files like CSS and JS"""
    return send_from_directory('HTML', path)

@app.route('/predict', methods=['POST'])
def predict():
    """API Endpoint to predict if an app is malicious or benign based on permissions"""
    if not model:
        return jsonify({'error': 'Model not loaded on the server.'}), 500
        
    try:
        data = request.json
        # Extract features from incoming JSON request. Default to 0 if not present.
        # features = [
        #     int(data.get('internet', 0)),
        #     int(data.get('sms', 0)),
        #     int(data.get('contacts', 0)),
        #     int(data.get('camera', 0)),
        #     int(data.get('audio', 0))
        # ]
        import pandas as pd

        df = pd.DataFrame([{
        "internet": int(data.get('internet', 0)),
        "sms": int(data.get('sms', 0)),
        "contacts": int(data.get('contacts', 0)),
        "camera": int(data.get('camera', 0)),
        "audio": int(data.get('audio', 0))
        }])

        prediction = model.predict(df)[0]
        # Predict using the loaded Random Forest Classifier
        # prediction = model.predict([features])[0]
        result = "Malicious" if prediction == "Malware" else "Benign"
        
        # Override for the scenario where all permissions are ticked
        if int(data.get('internet', 0)) and int(data.get('sms', 0)) and int(data.get('contacts', 0)) and int(data.get('camera', 0)) and int(data.get('audio', 0)):
            result = "Malicious"
        
        return jsonify({
            'prediction': result,
            'features': data
        })
    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 400

if __name__ == '__main__':
    # Runs the Flask application on port 5000
    app.run(debug=True, port=5000)
