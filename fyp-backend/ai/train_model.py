import os
import json
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import GroupKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")

RF_MODEL_PATH = os.path.join(BASE_DIR, "rf_model.pkl")
LR_MODEL_PATH = os.path.join(BASE_DIR, "lr_model.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "model_metrics.json")

df = pd.read_csv(DATASET_PATH)

feature_columns = [
    "packet_count",
    "total_bytes",
    "avg_pkt_len",
    "std_pkt_len",
    "mean_ttl",
    "mean_window",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "syn_count",
    "ack_count",
    "fin_count",
    "psh_count",
    "rst_count",
    "unique_dst_ports",
    "avg_src_port",
    "avg_dst_port",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "psh_ratio"
]

for col in feature_columns + ["label", "capture_id"]:
    if col not in df.columns:
        raise ValueError(f"Missing required column in dataset.csv: {col}")

X = df[feature_columns]
y = df["label"]
groups = df["capture_id"]

gkf = GroupKFold(n_splits=5)

rf_scores = {"accuracy": [], "precision": [], "recall": [], "f1": []}
lr_scores = {"accuracy": [], "precision": [], "recall": [], "f1": []}

for train_idx, test_idx in gkf.split(X, y, groups):
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=6,
        min_samples_leaf=3,
        random_state=42,
        class_weight="balanced_subsample"
    )
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)

    lr_model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=2000, C=0.5, class_weight="balanced"))
    ])
    lr_model.fit(X_train, y_train)
    lr_preds = lr_model.predict(X_test)

    rf_scores["accuracy"].append(accuracy_score(y_test, rf_preds))
    rf_scores["precision"].append(precision_score(y_test, rf_preds, zero_division=0))
    rf_scores["recall"].append(recall_score(y_test, rf_preds, zero_division=0))
    rf_scores["f1"].append(f1_score(y_test, rf_preds, zero_division=0))

    lr_scores["accuracy"].append(accuracy_score(y_test, lr_preds))
    lr_scores["precision"].append(precision_score(y_test, lr_preds, zero_division=0))
    lr_scores["recall"].append(recall_score(y_test, lr_preds, zero_division=0))
    lr_scores["f1"].append(f1_score(y_test, lr_preds, zero_division=0))

metrics = {
    "RandomForest": {
        "accuracy": float(np.mean(rf_scores["accuracy"])),
        "precision": float(np.mean(rf_scores["precision"])),
        "recall": float(np.mean(rf_scores["recall"])),
        "f1": float(np.mean(rf_scores["f1"]))
    },
    "LogisticRegression": {
        "accuracy": float(np.mean(lr_scores["accuracy"])),
        "precision": float(np.mean(lr_scores["precision"])),
        "recall": float(np.mean(lr_scores["recall"])),
        "f1": float(np.mean(lr_scores["f1"]))
    }
}

rf_final = RandomForestClassifier(
    n_estimators=150,
    max_depth=6,
    min_samples_leaf=3,
    random_state=42,
    class_weight="balanced_subsample"
)
rf_final.fit(X, y)

lr_final = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", LogisticRegression(max_iter=2000, C=0.5, class_weight="balanced"))
])
lr_final.fit(X, y)

joblib.dump(rf_final, RF_MODEL_PATH)
joblib.dump(lr_final, LR_MODEL_PATH)

with open(METRICS_PATH, "w") as f:
    json.dump(metrics, f, indent=4)

print("Training complete.")
print(json.dumps(metrics, indent=4))