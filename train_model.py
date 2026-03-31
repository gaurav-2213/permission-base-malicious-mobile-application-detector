import pandas as pd
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Create graphs directory if it doesn't exist
os.makedirs("graphs", exist_ok=True)

# 1. Load dataset
print("Loading Android_Malware_Benign.csv...")
df = pd.read_csv("Android_Malware_Benign.csv")
df.columns = df.columns.str.lower()
print(df.columns)
# Features and target
features_map = {
    "android.permission.internet": "internet",
    "android.permission.send_sms": "sms",
    "android.permission.read_contacts": "contacts",
    "android.permission.camera": "camera",
    "android.permission.record_audio": "audio",
}
X = df[list(features_map.keys())].rename(columns=features_map)
y = df["label"]

# 2. Split data (train/validation/test)
X_train_val, X_test, y_train_val, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
X_train, X_val, y_train, y_val = train_test_split(
    X_train_val, y_train_val, test_size=0.25, random_state=42, stratify=y_train_val
)

# 3. Model search with cross-validation
print("Tuning Random Forest with cross-validation...")
base_model = RandomForestClassifier(
    random_state=42,
    class_weight="balanced",
)
param_grid = {
    "n_estimators": [200, 300, 500],
    "max_depth": [None, 8, 12],
    "min_samples_leaf": [1, 2, 4],
    "min_samples_split": [2, 5, 10],
}
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
grid = GridSearchCV(
    estimator=base_model,
    param_grid=param_grid,
    scoring="recall_macro",
    cv=cv,
    n_jobs=-1,
)
grid.fit(X_train, y_train)
rf_model = grid.best_estimator_
print(f"Best parameters: {grid.best_params_}")


def choose_positive_label(labels):
    """Pick malware-like class label from dataset labels."""
    malware_aliases = {"malware", "malicious", "1", "true"}
    for label in labels:
        if str(label).strip().lower() in malware_aliases:
            return label
    return sorted(labels)[-1]


def tune_threshold(model, x_val, y_val, positive_label):
    """Tune probability threshold to improve positive-class recall."""
    classes = list(model.classes_)
    positive_index = classes.index(positive_label)
    y_prob = model.predict_proba(x_val)[:, positive_index]

    best_threshold = 0.5
    best_recall = -1.0
    best_precision = 0.0
    for threshold in [i / 100 for i in range(20, 81)]:
        y_pred_bin = (y_prob >= threshold).astype(int)
        y_true_bin = (y_val == positive_label).astype(int)
        tp = ((y_pred_bin == 1) & (y_true_bin == 1)).sum()
        fp = ((y_pred_bin == 1) & (y_true_bin == 0)).sum()
        fn = ((y_pred_bin == 0) & (y_true_bin == 1)).sum()
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0

        # Prefer high recall while keeping useful precision.
        if precision >= 0.60 and recall > best_recall:
            best_threshold = threshold
            best_recall = recall
            best_precision = precision

    if best_recall < 0:
        best_threshold = 0.5
        best_recall = 0.0
        best_precision = 0.0
    return best_threshold, best_precision, best_recall


positive_label = choose_positive_label(y.unique())
negative_candidates = [label for label in rf_model.classes_ if label != positive_label]
negative_label = negative_candidates[0] if negative_candidates else positive_label
threshold, val_precision, val_recall = tune_threshold(
    rf_model, X_val, y_val, positive_label
)
print(
    f"Selected positive label='{positive_label}', threshold={threshold:.2f}, "
    f"validation precision={val_precision:.3f}, recall={val_recall:.3f}"
)

# 4. Evaluate on test set with tuned threshold
positive_index = list(rf_model.classes_).index(positive_label)
y_prob_test = rf_model.predict_proba(X_test)[:, positive_index]
y_pred = pd.Series(
    [positive_label if prob >= threshold else negative_label for prob in y_prob_test],
    index=y_test.index,
)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# 5. Save Model
print("Saving model to model.pkl...")
joblib.dump(
    {
        "model": rf_model,
        "threshold": threshold,
        "positive_label": positive_label,
        "feature_keys": list(X.columns),
    },
    "model.pkl",
)

# --- Generate Graphs for Research Paper ---
print("Generating graphs...")

# Graph 1: Accuracy Graph (Bar chart comparing Train and Test accuracy)
train_acc = accuracy_score(y_train, rf_model.predict(X_train))
plt.figure(figsize=(6, 4))
sns.barplot(x=["Training Accuracy", "Test Accuracy"], y=[train_acc, accuracy])
plt.ylim(0, 1)
plt.title("Model Accuracy")
plt.ylabel("Accuracy Score")
plt.savefig("graphs/accuracy_graph.png")
plt.close()

# Graph 2: Confusion Matrix
labels = sorted(y.unique())
cm = confusion_matrix(y_test, y_pred, labels=labels)
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.savefig("graphs/confusion_matrix.png")
plt.close()

# Graph 3: Feature Importance Chart
importances = rf_model.feature_importances_
features = X.columns
plt.figure(figsize=(8, 5))
sns.barplot(x=importances, y=features, hue=features, palette="viridis", legend=False)
plt.title("Feature Importance")
plt.xlabel("Importance")
plt.ylabel("Features")
plt.savefig("graphs/feature_importance.png")
# plt.show()

print("Training complete! Model 'model.pkl' and graphs saved successfully.")
