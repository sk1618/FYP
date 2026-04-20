from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_DIR = os.path.join(BASE_DIR, "training_pcaps")
OUTPUT_CSV = os.path.join(BASE_DIR, "dataset.csv")

rows = []

def flag_contains(flag_string, flag_char):
    return flag_char in str(flag_string)

def label_from_src_ip(src_ip):
    if src_ip.startswith("10.10.10."):
        return 1, "SYN Flood"
    if src_ip.startswith("10.20.20."):
        return 1, "Ping Flood"
    if src_ip.startswith("10.30.30."):
        return 1, "FIN Scan"
    if src_ip.startswith("10.40.40."):
        return 1, "PSH Flood"
    if src_ip.startswith("10.50.50."):
        return 1, "ACK Flood"
    return 0, "Normal"

pcap_files = sorted([f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")])

if not pcap_files:
    raise ValueError("No training PCAP files found in training_pcaps/")

for pcap_name in pcap_files:
    packets = rdpcap(os.path.join(PCAP_DIR, pcap_name))
    packet_rows = []

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

            packet_rows.append({
                "capture_id": pcap_name,
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

    df = pd.DataFrame(packet_rows)
    if df.empty:
        continue

    grouped = df.groupby(["capture_id", "src_ip", "dst_ip"])

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

    labels = agg["src_ip"].apply(label_from_src_ip)
    agg["label"] = labels.apply(lambda x: x[0])
    agg["attack_type"] = labels.apply(lambda x: x[1])

    rows.append(agg)

dataset = pd.concat(rows, ignore_index=True)
dataset.to_csv(OUTPUT_CSV, index=False)

print(f"dataset.csv created successfully at: {OUTPUT_CSV}")
print(dataset["attack_type"].value_counts())
print(dataset.head())