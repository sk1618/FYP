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

# --- Base folder of this script ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Load trained model and encoders ---
model = joblib.load(os.path.join(BASE_DIR, "rf_model.pkl"))
le_proto = joblib.load(os.path.join(BASE_DIR, "le_proto.pkl"))
le_flags = joblib.load(os.path.join(BASE_DIR, "le_flags.pkl"))

# --- Read PCAP file ---
pcap_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BASE_DIR, "test.pcap")
packets = rdpcap(pcap_file)

# --- Extract features from packets ---
data = []
for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "OTHER"
        tcp_flags = ""
        length = len(pkt)

        if TCP in pkt:
            proto = "TCP"
            tcp_flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
        elif ICMP in pkt:
            proto = "ICMP"

        if tcp_flags == "":
            tcp_flags = "NONE"

        data.append([src, dst, proto, tcp_flags, length])

# --- Create DataFrame ---
df = pd.DataFrame(data, columns=["src_ip", "dst_ip", "protocol", "tcp_flags", "length"])

# --- If no IP packets were found ---
if df.empty:
    output = {
        "report": [],
        "summary": {},
        "report_file": "attack_report.json",
        "chart_file": "attack_summary.png",
        "message": "No valid IP packets found in the capture."
    }

    with open(os.path.join(BASE_DIR, "attack_report.json"), "w") as f:
        json.dump([], f, indent=4)

    plt.figure(figsize=(6, 4))
    plt.text(0.5, 0.5, "No attacks detected", ha="center", va="center", fontsize=14)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, "attack_summary.png"))
    plt.close()

    print(json.dumps(output))
    sys.exit(0)

# --- Step 1: Assign attack type based on raw protocol and tcp_flags (before encoding) ---
def get_attack_type_raw(row):
    if row["protocol"] == "TCP":
        flag = row["tcp_flags"]
        if flag == "S":
            return "SYN Flood"
        elif flag == "F":
            return "FIN Scan"
        elif flag == "R":
            return "RST Scan"
        elif flag == "P":
            return "PSH Flood"
        elif flag == "A":
            return "ACK Flood"
        elif flag == "U":
            return "URG Flood"
        elif "S" in flag:
            return "SYN Flood"
        elif "F" in flag:
            return "FIN Scan"
        elif "R" in flag:
            return "RST Scan"
        elif "P" in flag:
            return "PSH Flood"
        elif "A" in flag:
            return "ACK Flood"
        elif "U" in flag:
            return "URG Flood"
        else:
            return "Unknown TCP Attack"
    elif row["protocol"] == "ICMP":
        return "Ping Flood"
    else:
        return "Unknown Attack"

df["attack_type"] = df.apply(get_attack_type_raw, axis=1)

# --- Safe encoder helper ---
def safe_transform(value, encoder, default_value):
    value = str(value)

    # If the value exists in the encoder, use it directly
    if value in encoder.classes_:
        return encoder.transform([value])[0]

    # If the requested default exists, use it
    if default_value in encoder.classes_:
        return encoder.transform([default_value])[0]

    # Otherwise fall back to the first known class in the encoder
    fallback = str(encoder.classes_[0])
    return encoder.transform([fallback])[0]

# --- Step 2: Encode categorical features safely for model ---
df["protocol"] = df["protocol"].apply(lambda x: safe_transform(x, le_proto, "OTHER"))
df["tcp_flags"] = df["tcp_flags"].apply(lambda x: safe_transform(x, le_flags, "NONE"))

# --- Step 3: Predict attacks using the trained model ---
df["prediction"] = model.predict(df[["protocol", "tcp_flags", "length"]])

# --- Step 4: Filter only detected attacks ---
attacks = df[df["prediction"] == 1].copy()

# --- Step 5: Generate JSON report ---
report = attacks[["src_ip", "dst_ip", "attack_type"]].to_dict(orient="records")
with open(os.path.join(BASE_DIR, "attack_report.json"), "w") as f:
    json.dump(report, f, indent=4)

# --- Step 6: Summary statistics ---
summary = attacks["attack_type"].value_counts()

# --- Step 7: Visualize attacks safely ---
plt.figure(figsize=(8, 5))

if summary.empty:
    plt.text(0.5, 0.5, "No attacks detected", ha="center", va="center", fontsize=14)
    plt.axis("off")
else:
    summary.plot(kind="bar", color="skyblue")
    plt.title("Attack Counts by Type")
    plt.xlabel("Attack Type")
    plt.ylabel("Number of Packets")
    plt.xticks(rotation=45)

plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, "attack_summary.png"))
plt.close()

# --- Step 8: Return clean JSON output for backend ---
output = {
    "report": report,
    "summary": summary.to_dict(),
    "report_file": "attack_report.json",
    "chart_file": "attack_summary.png"
}

print(json.dumps(output))