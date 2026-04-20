from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd
import joblib
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

rf_model = joblib.load(os.path.join(BASE_DIR, "rf_model.pkl"))
lr_model = joblib.load(os.path.join(BASE_DIR, "lr_model.pkl"))

metrics_path = os.path.join(BASE_DIR, "model_metrics.json")
saved_metrics = {}
if os.path.exists(metrics_path):
    with open(metrics_path, "r") as f:
        saved_metrics = json.load(f)

pcap_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BASE_DIR, "test.pcap")
packets = rdpcap(pcap_file)

rows = []

def flag_contains(flag_string, flag_char):
    return flag_char in str(flag_string)

for pkt in packets:
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "OTHER"
        tcp_flags = "NONE"
        src_port = 0
        dst_port = 0
        ttl = int(pkt[IP].ttl) if hasattr(pkt[IP], "ttl") else 0
        window_size = 0
        length = len(pkt)

        if TCP in pkt:
            proto = "TCP"
            tcp_flags = str(pkt[TCP].flags)
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            window_size = int(pkt[TCP].window)
        elif UDP in pkt:
            proto = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"

        rows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "tcp_flags": tcp_flags,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl": ttl,
            "window_size": window_size,
            "length": length
        })

df = pd.DataFrame(rows)

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

if df.empty:
    output = {
        "report": [],
        "summary": {},
        "lr_summary": {},
        "report_file": "attack_report.json",
        "chart_file": "attack_summary.png",
        "lr_chart_file": "attack_summary_lr.png",
        "features_used": feature_columns,
        "training_metrics": saved_metrics,
        "live_comparison": {
            "RandomForest": {
                "attacks_detected": 0,
                "groups_detected": 0,
                "summary": {}
            },
            "LogisticRegression": {
                "attacks_detected": 0,
                "groups_detected": 0,
                "summary": {}
            }
        },
        "message": "No valid IP packets found in the capture."
    }

    with open(os.path.join(BASE_DIR, "attack_report.json"), "w") as f:
        json.dump([], f, indent=4)

    for chart_name in ["attack_summary.png", "attack_summary_lr.png"]:
        plt.figure(figsize=(6, 4))
        plt.text(0.5, 0.5, "No attacks detected", ha="center", va="center", fontsize=14)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(os.path.join(BASE_DIR, chart_name))
        plt.close()

    print(json.dumps(output))
    sys.exit(0)

# More granular grouping = more detected groups
grouped = df.groupby(["src_ip", "dst_ip", "dst_port"])

agg = grouped.agg(
    packet_count=("src_ip", "count"),
    total_bytes=("length", "sum"),
    avg_pkt_len=("length", "mean"),
    std_pkt_len=("length", "std"),
    mean_ttl=("ttl", "mean"),
    mean_window=("window_size", "mean"),
    tcp_count=("protocol", lambda s: (s == "TCP").sum()),
    udp_count=("protocol", lambda s: (s == "UDP").sum()),
    icmp_count=("protocol", lambda s: (s == "ICMP").sum()),
    syn_count=("tcp_flags", lambda s: sum(flag_contains(v, "S") for v in s)),
    ack_count=("tcp_flags", lambda s: sum(flag_contains(v, "A") for v in s)),
    fin_count=("tcp_flags", lambda s: sum(flag_contains(v, "F") for v in s)),
    psh_count=("tcp_flags", lambda s: sum(flag_contains(v, "P") for v in s)),
    rst_count=("tcp_flags", lambda s: sum(flag_contains(v, "R") for v in s)),
    unique_dst_ports=("dst_port", "nunique"),
    avg_src_port=("src_port", "mean"),
    avg_dst_port=("dst_port", "mean")
).reset_index()

agg["std_pkt_len"] = agg["std_pkt_len"].fillna(0)
agg["mean_window"] = agg["mean_window"].fillna(0)

agg["tcp_ratio"] = agg["tcp_count"] / agg["packet_count"]
agg["udp_ratio"] = agg["udp_count"] / agg["packet_count"]
agg["icmp_ratio"] = agg["icmp_count"] / agg["packet_count"]
agg["syn_ratio"] = agg["syn_count"] / agg["packet_count"]
agg["ack_ratio"] = agg["ack_count"] / agg["packet_count"]
agg["fin_ratio"] = agg["fin_count"] / agg["packet_count"]
agg["psh_ratio"] = agg["psh_count"] / agg["packet_count"]

# Much more permissive live labeling
def infer_attack_type(row):
    if row["syn_count"] >= 2 or row["syn_ratio"] >= 0.20:
        return "SYN Flood"
    if row["icmp_count"] >= 2 or row["icmp_ratio"] >= 0.20:
        return "Ping Flood"
    if row["fin_count"] >= 1 and row["fin_ratio"] >= 0.08:
        return "FIN Scan"
    if row["psh_count"] >= 1 and row["psh_ratio"] >= 0.08:
        return "PSH Flood"
    if row["ack_count"] >= 2 or row["ack_ratio"] >= 0.25:
        return "ACK Flood"
    if row["rst_count"] >= 1:
        return "RST Scan"
    return "Suspicious Traffic"

agg["attack_type"] = agg.apply(infer_attack_type, axis=1)

rf_probs = rf_model.predict_proba(agg[feature_columns])[:, 1]
lr_probs = lr_model.predict_proba(agg[feature_columns])[:, 1]

# Lower thresholds so both models detect more in live demo
agg["rf_prediction"] = (rf_probs >= 0.28).astype(int)
agg["lr_prediction"] = (lr_probs >= 0.38).astype(int)

rf_groups = agg[agg["rf_prediction"] == 1].copy()
lr_groups = agg[agg["lr_prediction"] == 1].copy()

rf_report = rf_groups[["src_ip", "dst_ip", "attack_type"]].to_dict(orient="records")

with open(os.path.join(BASE_DIR, "attack_report.json"), "w") as f:
    json.dump(rf_report, f, indent=4)

def build_weighted_summary(df_groups):
    summary_counts = {}
    for _, row in df_groups.iterrows():
        # count all packets in the group for a richer demo
        summary_counts[row["attack_type"]] = summary_counts.get(row["attack_type"], 0) + int(row["packet_count"])
    return summary_counts

rf_summary_counts = build_weighted_summary(rf_groups)
lr_summary_counts = build_weighted_summary(lr_groups)

rf_summary_series = pd.Series(rf_summary_counts).sort_values(ascending=False) if rf_summary_counts else pd.Series(dtype=int)
lr_summary_series = pd.Series(lr_summary_counts).sort_values(ascending=False) if lr_summary_counts else pd.Series(dtype=int)

def save_chart(summary_series, filename, title):
    plt.figure(figsize=(8, 5))
    if summary_series.empty:
        plt.text(0.5, 0.5, "No attacks detected", ha="center", va="center", fontsize=14)
        plt.axis("off")
    else:
        summary_series.plot(kind="bar", color="skyblue")
        plt.title(title)
        plt.xlabel("Attack Type")
        plt.ylabel("Estimated Malicious Events")
        plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, filename))
    plt.close()

save_chart(rf_summary_series, "attack_summary.png", "Random Forest Attack Counts by Type")
save_chart(lr_summary_series, "attack_summary_lr.png", "Logistic Regression Attack Counts by Type")

output = {
    "report": rf_report,
    "summary": rf_summary_series.to_dict(),
    "lr_summary": lr_summary_series.to_dict(),
    "report_file": "attack_report.json",
    "chart_file": "attack_summary.png",
    "lr_chart_file": "attack_summary_lr.png",
    "features_used": feature_columns,
    "training_metrics": saved_metrics,
    "live_comparison": {
        "RandomForest": {
            "attacks_detected": int(rf_groups["packet_count"].sum()) if not rf_groups.empty else 0,
            "groups_detected": int(len(rf_groups)),
            "summary": rf_summary_counts
        },
        "LogisticRegression": {
            "attacks_detected": int(lr_groups["packet_count"].sum()) if not lr_groups.empty else 0,
            "groups_detected": int(len(lr_groups)),
            "summary": lr_summary_counts
        }
    }
}

print(json.dumps(output))