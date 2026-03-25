import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

df = pd.read_csv('Android_Malware_Benign.csv')
df.columns = df.columns.str.lower()
features_map = {
    'android.permission.internet': 'internet',
    'android.permission.send_sms': 'sms',
    'android.permission.read_contacts': 'contacts',
    'android.permission.camera': 'camera',
    'android.permission.record_audio': 'audio'
}
X = df[list(features_map.keys())].rename(columns=features_map)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = joblib.load('model.pkl')
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(classification_report(y_test, y_pred))
