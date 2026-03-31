import os

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.model_selection import train_test_split


os.makedirs("graphs", exist_ok=True)


def choose_positive_label(labels):
    malware_aliases = {"malware", "malicious", "1", "true"}
    for label in labels:
        if str(label).strip().lower() in malware_aliases:
            return label
    return sorted(labels)[-1]


def metrics_at_threshold(y_true_bin, y_prob, threshold):
    y_pred_bin = (y_prob >= threshold).astype(int)
    tp = int(((y_pred_bin == 1) & (y_true_bin == 1)).sum())
    fp = int(((y_pred_bin == 1) & (y_true_bin == 0)).sum())
    fn = int(((y_pred_bin == 0) & (y_true_bin == 1)).sum())
    tn = int(((y_pred_bin == 0) & (y_true_bin == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(y_true_bin) if len(y_true_bin) else 0.0
    return precision, recall, f1, accuracy


print("Loading model bundle from model.pkl...")
bundle = joblib.load("model.pkl")
model = bundle["model"] if isinstance(bundle, dict) else bundle
saved_threshold = float(bundle.get("threshold", 0.5)) if isinstance(bundle, dict) else 0.5
saved_positive_label = bundle.get("positive_label") if isinstance(bundle, dict) else None

print("Loading Android_Malware_Benign.csv...")
df = pd.read_csv("Android_Malware_Benign.csv")
df.columns = df.columns.str.lower()

features_map = {
    "android.permission.internet": "internet",
    "android.permission.send_sms": "sms",
    "android.permission.read_contacts": "contacts",
    "android.permission.camera": "camera",
    "android.permission.record_audio": "audio",
}

X = df[list(features_map.keys())].rename(columns=features_map)
y = df["label"]

_, X_test, _, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

positive_label = saved_positive_label or choose_positive_label(model.classes_)
positive_index = list(model.classes_).index(positive_label)
y_prob = model.predict_proba(X_test)[:, positive_index]
y_true_bin = (y_test == positive_label).astype(int).to_numpy()

rows = []
for threshold in [i / 100 for i in range(5, 96)]:
    precision, recall, f1, accuracy = metrics_at_threshold(y_true_bin, y_prob, threshold)
    rows.append(
        {
            "threshold": threshold,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
        }
    )

results = pd.DataFrame(rows)
results.to_csv("graphs/threshold_metrics.csv", index=False)

# Suggested operating points
strict = results[results["precision"] >= 0.8].sort_values(
    ["recall", "f1"], ascending=False
).head(1)
balanced = results.sort_values(["f1", "recall"], ascending=False).head(1)
recall_focused = results[results["precision"] >= 0.6].sort_values(
    ["recall", "f1"], ascending=False
).head(1)

print("\nSuggested thresholds:")
if not strict.empty:
    r = strict.iloc[0]
    print(
        f"- strict: threshold={r['threshold']:.2f}, precision={r['precision']:.3f}, "
        f"recall={r['recall']:.3f}, f1={r['f1']:.3f}"
    )
else:
    print("- strict: no threshold reached precision >= 0.80")

rb = balanced.iloc[0]
print(
    f"- balanced: threshold={rb['threshold']:.2f}, precision={rb['precision']:.3f}, "
    f"recall={rb['recall']:.3f}, f1={rb['f1']:.3f}"
)

if not recall_focused.empty:
    rr = recall_focused.iloc[0]
    print(
        f"- recall_focused: threshold={rr['threshold']:.2f}, precision={rr['precision']:.3f}, "
        f"recall={rr['recall']:.3f}, f1={rr['f1']:.3f}"
    )
else:
    print("- recall_focused: no threshold reached precision >= 0.60")

print(
    f"- currently_saved: threshold={saved_threshold:.2f}, "
    f"positive_label={positive_label}"
)

# Plot thresholds vs metrics
plot_df = results.melt(
    id_vars="threshold",
    value_vars=["precision", "recall", "f1", "accuracy"],
    var_name="metric",
    value_name="score",
)
plt.figure(figsize=(10, 6))
sns.lineplot(data=plot_df, x="threshold", y="score", hue="metric")
plt.axvline(saved_threshold, color="black", linestyle="--", label="saved_threshold")
plt.title("Threshold vs Evaluation Metrics")
plt.xlabel("Malware Probability Threshold")
plt.ylabel("Score")
plt.ylim(0, 1)
plt.legend()
plt.tight_layout()
plt.savefig("graphs/threshold_metrics.png")
plt.close()

print("Saved:")
print("- graphs/threshold_metrics.csv")
print("- graphs/threshold_metrics.png")
