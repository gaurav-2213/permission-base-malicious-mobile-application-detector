import os

import joblib
import pandas as pd
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="HTML", static_url_path="/")
CORS(app)  # Enable CORS for frontend API requests if accessed outside static routing

FEATURE_KEYS = ("internet", "sms", "contacts", "camera", "audio")

# In-memory store for previously predicted apps
prediction_history = []
def normalize_prediction_label(raw_prediction):
    """
    Map model labels to stable API output labels.
    Accepts common malware-positive variants without hardcoding one exact string.
    """
    value = str(raw_prediction).strip().lower()
    malicious_aliases = {"malware", "malicious", "1", "true"}
    return "Malicious" if value in malicious_aliases else "Benign"

# Load the trained ML model
try:
    model_bundle = joblib.load("model.pkl")
    if isinstance(model_bundle, dict) and "model" in model_bundle:
        model = model_bundle["model"]
        model_threshold = float(model_bundle.get("threshold", 0.5))
        positive_label = model_bundle.get("positive_label", "Malware")
    else:
        model = model_bundle
        model_threshold = 0.5
        positive_label = "Malware"
    print("Model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
    model_threshold = 0.5
    positive_label = "Malware"

@app.route("/")
def home():
    """Serves the frontend HTML app"""
    return send_from_directory("HTML", "index.html")

@app.route("/<path:path>")
def send_static(path):
    """Serves other frontend static files like CSS and JS"""
    return send_from_directory("HTML", path)

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint for quick backend diagnostics."""
    return jsonify(
        {
            "status": "ok",
            "model_loaded": model is not None,
            "threshold": model_threshold,
            "positive_label": str(positive_label),
        }
    )

@app.route("/history", methods=["GET"])
def get_history():
    """Returns the history of checked apps."""
    return jsonify(prediction_history)


@app.route("/predict", methods=["POST"])
def predict():
    """API Endpoint to predict if an app is malicious or benign based on permissions"""
    if not model:
        return jsonify({"error": "Model not loaded on the server."}), 500

    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be valid JSON object."}), 400

        app_name = str(data.get("app_name", "")).strip()

        features = {}
        for key in FEATURE_KEYS:
            value = data.get(key, 0)
            if value not in (0, 1, True, False):
                return jsonify({"error": f"Feature '{key}' must be 0 or 1."}), 400
            features[key] = int(value)

        df = pd.DataFrame([features])

        # Calculate number of active permissions
        num_active = sum(features.values())

        if num_active == 0:
            # If no permissions are selected, it should be Benign
            result = "Benign"
            score = 0.0
        elif num_active == len(FEATURE_KEYS):
            # If all permissions are selected, it should be Malicious
            result = "Malicious"
            score = 1.0
        else:
            # Let the ML model decide
            prediction = model.predict(df)[0]
            result = normalize_prediction_label(prediction)
            score = None

            if hasattr(model, "predict_proba") and hasattr(model, "classes_"):
                classes = list(model.classes_)
                if positive_label in classes:
                    pos_index = classes.index(positive_label)
                    score = float(model.predict_proba(df)[0][pos_index])
                    result = "Malicious" if score >= model_threshold else "Benign"

        response = {"prediction": result, "features": features}
        if app_name:
            response["app_name"] = app_name
        if score is not None:
            response["malware_score"] = round(score, 4)
            response["threshold"] = model_threshold
        
        # Add to history
        prediction_history.insert(0, response)
        # Keep only the last 50 predictions
        if len(prediction_history) > 50:
            prediction_history.pop()

        return jsonify(response)
    except Exception:
        return jsonify({"error": "Prediction failed due to server error."}), 500


if __name__ == "__main__":
    # Runs the Flask application on port 5000
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", port=5000)
