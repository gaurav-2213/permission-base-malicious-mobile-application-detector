import os

import csv
import io
import json
from datetime import datetime, timezone

import joblib
import pandas as pd
from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="HTML", static_url_path="/")
CORS(app)  # Enable CORS for frontend API requests if accessed outside static routing

FEATURE_KEYS = ("internet", "sms", "contacts", "camera", "audio")

# In-memory store for previously predicted apps
prediction_history = []
timeline_events = []
last_features_by_app_name = {}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def clamp_int(value, lo, hi):
    try:
        v = int(value)
    except Exception:
        v = lo
    return max(lo, min(hi, v))


def compute_security_score_0_100(malware_score):
    """
    Convert malware probability to a human-friendly security score.
    100 = safest, 0 = riskiest.
    """
    if malware_score is None:
        return None
    return clamp_int(round((1.0 - float(malware_score)) * 100), 0, 100)


def compute_tier(score_0_100):
    if score_0_100 is None:
        return "Unknown"
    if score_0_100 >= 90:
        return "Excellent"
    if score_0_100 >= 70:
        return "Moderate"
    return "Vulnerable"


def compute_reputation(score_0_100, prediction_label):
    if prediction_label == "Malicious":
        return "Dangerous"
    if score_0_100 is None:
        return "Unknown"
    if score_0_100 >= 90:
        return "Trusted"
    if score_0_100 >= 70:
        return "Unknown"
    return "Dangerous"


def diff_permission_changes(before_features, after_features):
    changes = []
    for key in FEATURE_KEYS:
        before = int(before_features.get(key, 0)) if isinstance(before_features, dict) else 0
        after = int(after_features.get(key, 0)) if isinstance(after_features, dict) else 0
        if before != after:
            changes.append({"permission": key, "from": before, "to": after})
    return changes


def add_timeline_event(event):
    timeline_events.insert(0, event)
    if len(timeline_events) > 200:
        timeline_events.pop()


def build_export_payload():
    return {"generated_at": utc_now_iso(), "history": prediction_history, "timeline": timeline_events}


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


@app.route("/timeline", methods=["GET"])
def get_timeline():
    """Returns the threat timeline events."""
    return jsonify(timeline_events)


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

        timestamp = utc_now_iso()
        security_score_0_100 = compute_security_score_0_100(score)
        tier = compute_tier(security_score_0_100)
        reputation = compute_reputation(security_score_0_100, result)

        response = {
            "prediction": result,
            "features": features,
            "timestamp": timestamp,
            "score_0_100": security_score_0_100,
            "tier": tier,
            "reputation": reputation,
        }
        if app_name:
            response["app_name"] = app_name
        if score is not None:
            response["malware_score"] = round(score, 4)
            response["threshold"] = model_threshold

        if score is not None:
            response["malware_risk_0_100"] = clamp_int(round(float(score) * 100), 0, 100)
        
        # Timeline: scan event
        add_timeline_event(
            {
                "type": "scan",
                "timestamp": timestamp,
                "app_name": app_name or None,
                "prediction": result,
                "score_0_100": security_score_0_100,
                "tier": tier,
                "reputation": reputation,
            }
        )

        # Timeline: permission changes for same app name
        if app_name:
            previous = last_features_by_app_name.get(app_name)
            if isinstance(previous, dict):
                changes = diff_permission_changes(previous, features)
                if changes:
                    add_timeline_event(
                        {
                            "type": "permission_change",
                            "timestamp": timestamp,
                            "app_name": app_name,
                            "changes": changes,
                        }
                    )
            last_features_by_app_name[app_name] = dict(features)

        # Add to history
        prediction_history.insert(0, response)
        # Keep only the last 50 predictions
        if len(prediction_history) > 50:
            prediction_history.pop()

        return jsonify(response)
    except Exception:
        return jsonify({"error": "Prediction failed due to server error."}), 500


@app.route("/export/json", methods=["GET"])
def export_json():
    payload = build_export_payload()
    data = json.dumps(payload, indent=2).encode("utf-8")
    return send_file(
        io.BytesIO(data),
        mimetype="application/json",
        as_attachment=True,
        download_name="scan_report.json",
    )


@app.route("/export/csv", methods=["GET"])
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "timestamp",
            "app_name",
            "prediction",
            "score_0_100",
            "tier",
            "reputation",
            "malware_score",
            "threshold",
            "internet",
            "sms",
            "contacts",
            "camera",
            "audio",
        ]
    )
    for item in prediction_history:
        features = item.get("features") if isinstance(item, dict) else {}
        writer.writerow(
            [
                item.get("timestamp"),
                item.get("app_name"),
                item.get("prediction"),
                item.get("score_0_100"),
                item.get("tier"),
                item.get("reputation"),
                item.get("malware_score"),
                item.get("threshold"),
                int(bool(features.get("internet", 0))),
                int(bool(features.get("sms", 0))),
                int(bool(features.get("contacts", 0))),
                int(bool(features.get("camera", 0))),
                int(bool(features.get("audio", 0))),
            ]
        )

    data = output.getvalue().encode("utf-8")
    return send_file(
        io.BytesIO(data),
        mimetype="text/csv",
        as_attachment=True,
        download_name="scan_history.csv",
    )


@app.route("/export/pdf", methods=["GET"])
def export_pdf():
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.pdfbase.pdfmetrics import stringWidth
        from reportlab.pdfgen import canvas
    except Exception:
        return jsonify(
            {
                "error": "PDF export requires 'reportlab'. Install dependencies from requirements.txt and restart the server."
            }
        ), 500

    payload = build_export_payload()
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 0.75 * inch
    c.setFont("Helvetica-Bold", 16)
    c.drawString(0.75 * inch, y, "Malicious App Detector — Scan Report")
    y -= 0.35 * inch

    c.setFont("Helvetica", 10)
    c.drawString(0.75 * inch, y, f"Generated (UTC): {payload['generated_at']}")
    y -= 0.4 * inch

    c.setFont("Helvetica-Bold", 12)
    c.drawString(0.75 * inch, y, "Recent scans (most recent first)")
    y -= 0.25 * inch

    c.setFont("Helvetica", 9)

    def draw_wrapped_line(x, y_pos, text, max_width):
        words = str(text).split()
        line = ""
        while words:
            test = (line + " " + words[0]).strip()
            if stringWidth(test, "Helvetica", 9) <= max_width:
                line = test
                words.pop(0)
            else:
                break
        c.drawString(x, y_pos, line)
        return " ".join(words)

    max_width = width - 1.5 * inch
    for item in payload["history"][:12]:
        if y < 1.0 * inch:
            c.showPage()
            y = height - 0.75 * inch
            c.setFont("Helvetica", 9)

        app_name = item.get("app_name") or "(unnamed app)"
        ts = item.get("timestamp") or ""
        pred = item.get("prediction") or ""
        score = item.get("score_0_100")
        tier = item.get("tier") or ""
        rep = item.get("reputation") or ""

        header = f"{ts} — {app_name} — {pred} — Score: {score} ({tier}, {rep})"
        remaining = header
        while remaining:
            remaining = draw_wrapped_line(0.75 * inch, y, remaining, max_width)
            y -= 0.18 * inch

        feats = item.get("features") or {}
        enabled = [k for k, v in feats.items() if v == 1]
        perms_line = "Permissions: " + (", ".join(enabled) if enabled else "none")
        remaining = perms_line
        while remaining:
            remaining = draw_wrapped_line(0.75 * inch, y, remaining, max_width)
            y -= 0.18 * inch

        y -= 0.1 * inch

    c.save()
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="scan_report.pdf",
    )


if __name__ == "__main__":
    # Runs the Flask application on port 5000
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", port=5000)
