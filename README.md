# Malicious Mobile Application Detection System

This Machine Learning project predicts whether a mobile application is "Malicious" or "Benign" based purely on the set of permissions it asks for (such as *Internet, Send SMS, Read Contacts, Camera Access, Audio Recording*).

## Tech Stack Overview
- **Frontend**: HTML5, Vanilla CSS (Glassmorphism Dark Theme), Vanilla JavaScript
- **Backend / API Server**: Python & Flask (with CORS)
- **Machine Learning**: Scikit-Learn (`RandomForestClassifier`)

---

## 🛠 Setup & Installation Instructions

### 1. Requirements
- Install Python 3.8+ on your system.
- Recommended IDE: Visual Studio Code.

### 2. Install Project Dependencies
Open your VS Code terminal within the root `project/` directory and install the required modules by running:
```bash
pip install -r requirements.txt
```

### 3. Repository Folder Structure
```
project/
│
├── HTML/                 # Frontend Website
│   ├── index.html        # App user interface
│   ├── style.css         # Modern styling & animations
│   └── script.js         # Fetch actions & JSON payloads
│
├── graphs/               # Auto-generated visualization graphs
│   ├── accuracy_graph.png
│   ├── confusion_matrix.png
│   └── feature_importance.png
│
├── app.py                # Main backend API logic (Flask Server)
├── train_model.py        # ML data training & plotting script
├── Android_Malware_Benign.csv  # Dataset used for training
├── requirements.txt      # List of target python tools mapped to pip
└── README.md             # Standard operation manual
```

---

## 🚀 Running the Project (Step-by-Step)

### Step 1: Train the Machine Learning Model
First, you need to compile the dataset and train the Random Forest Classifier. This command will output `model.pkl` and automatically draw research paper graphs in the `graphs/` folder.
```bash
python train_model.py
```
The training script also prints a classification report (precision/recall/F1) so you can evaluate model quality beyond just accuracy.
It now performs cross-validated model tuning and stores the selected malware probability threshold inside `model.pkl`.

### Step 2: Start the Web App Server
Spin up the Flask engine that serves both the frontend GUI and RESTful API backend.
```bash
python app.py
```

### Step 3: Use the Detector
Once Flask reports it's running via terminal (usually *Running on http://127.0.0.1:5000/*):
1. Navigate directly to [http://127.0.0.1:5000/](http://127.0.0.1:5000/) inside a web browser.
2. Form interactively with the different checkbox inputs to pass mock user request permissions.
3. Click **"Analyze Application"** and see the UI interact instantly referencing `model.pkl`.

### Optional: Backend Health Check
Use this endpoint to verify that Flask is up and the model was loaded:
```bash
GET http://127.0.0.1:5000/health
```
The `/predict` response may include `malware_score` and `threshold` when probability-based prediction is available.

### Threshold Analysis (strict vs balanced)
To compare operating points and generate threshold curves:
```bash
python evaluate.py
```
This writes:
- `graphs/threshold_metrics.csv`
- `graphs/threshold_metrics.png`
