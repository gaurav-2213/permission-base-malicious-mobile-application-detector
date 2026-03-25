import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Create graphs directory if it doesn't exist
os.makedirs('graphs', exist_ok=True)

# 1. Load dataset
print("Android_Malware_Benign.csv...")
df = pd.read_csv('Android_Malware_Benign.csv')
df.columns=df.columns.str.lower()
print(df.columns)
# Features and target
features_map = {
    'android.permission.internet': 'internet',
    'android.permission.send_sms': 'sms',
    'android.permission.read_contacts': 'contacts',
    'android.permission.camera': 'camera',
    'android.permission.record_audio': 'audio'
}
X = df[list(features_map.keys())].rename(columns=features_map)
y = df['label']

# 2. Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train RandomForestClassifier
print("Training Random Forest Classifier...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 4. Model Accuracy
y_pred = rf_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# 5. Save Model
print("Saving model to model.pkl...")
joblib.dump(rf_model, 'model.pkl')

# --- Generate Graphs for Research Paper ---
print("Generating graphs...")

# Graph 1: Accuracy Graph (Bar chart comparing Train and Test accuracy)
train_acc = accuracy_score(y_train, rf_model.predict(X_train))
plt.figure(figsize=(6, 4))
sns.barplot(x=['Training Accuracy', 'Test Accuracy'], y=[train_acc, accuracy])
plt.ylim(0, 1)
plt.title('Model Accuracy')
plt.ylabel('Accuracy Score')
plt.savefig('graphs/accuracy_graph.png')
plt.close()

# Graph 2: Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Malicious'], yticklabels=['Benign', 'Malicious'])
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.savefig('graphs/confusion_matrix.png')
plt.close()

# Graph 3: Feature Importance Chart
importances = rf_model.feature_importances_
features = X.columns
plt.figure(figsize=(8, 5))
sns.barplot(x=importances, y=features, palette='viridis')
plt.title('Feature Importance')
plt.xlabel('Importance')
plt.ylabel('Features')
plt.savefig('graphs/feature_importance.png')
# plt.show()

print("Training complete! Model 'model.pkl' and graphs saved successfully.")
