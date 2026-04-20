from scapy.all import IP, TCP, UDP, ICMP, wrpcap
import os
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "training_pcaps")
os.makedirs(OUT_DIR, exist_ok=True)

random.seed(42)

def rand_ip(prefix):
    return f"{prefix}.{random.randint(1, 254)}"

def benign_web_client(src_ip, dst_ips, packet_count):
    packets = []
    for _ in range(packet_count):
        dst_ip = random.choice(dst_ips)
        mode = random.choices(
            ["ACK", "SYN", "PSH", "UDP", "ICMP"],
            weights=[45, 20, 10, 15, 10],
            k=1
        )[0]

        if mode == "ACK":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(50, 128)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 8080]),
                               flags="A", window=random.randint(1024, 8192)))
        elif mode == "SYN":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(50, 128)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 22]),
                               flags="S", window=random.randint(1024, 8192)))
        elif mode == "PSH":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(50, 128)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443]),
                               flags="PA", window=random.randint(1024, 8192)))
        elif mode == "UDP":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(50, 128)) /
                           UDP(sport=random.randint(1024, 65535), dport=random.choice([53, 123])) / b"ok")
        else:
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(50, 128)) / ICMP())
    return packets

def benign_noisy_client(src_ip, dst_ips, packet_count):
    packets = []
    for _ in range(packet_count):
        dst_ip = random.choice(dst_ips)
        mode = random.choices(
            ["ACK", "SYN", "FIN", "PSH", "UDP", "ICMP"],
            weights=[30, 20, 10, 15, 15, 10],
            k=1
        )[0]

        if mode == "ACK":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(45, 128)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 25]),
                               flags="A", window=random.randint(1024, 8192)))
        elif mode == "SYN":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(45, 128)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 22]),
                               flags="S", window=random.randint(1024, 8192)))
        elif mode == "FIN":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(45, 128)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 110]),
                               flags="F", window=random.randint(1024, 8192)))
        elif mode == "PSH":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(45, 128)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443]),
                               flags="P", window=random.randint(1024, 8192)))
        elif mode == "UDP":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(45, 128)) /
                           UDP(sport=random.randint(1024, 65535), dport=random.choice([53, 161, 123])) / b"ok")
        else:
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(45, 128)) / ICMP())
    return packets

def syn_attacker(src_ip, dst_ips, packet_count):
    packets = []
    for _ in range(packet_count):
        dst_ip = random.choice(dst_ips)
        mode = random.choices(["SYN", "ACK", "UDP"], weights=[70, 20, 10], k=1)[0]
        if mode == "SYN":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 22]),
                               flags="S", window=random.randint(512, 4096)))
        elif mode == "ACK":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443]),
                               flags="A", window=random.randint(512, 4096)))
        else:
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           UDP(sport=random.randint(1024, 65535), dport=53) / b"x")
    return packets

def ping_attacker(src_ip, dst_ips, packet_count):
    packets = []
    for _ in range(packet_count):
        dst_ip = random.choice(dst_ips)
        mode = random.choices(["ICMP", "ACK"], weights=[75, 25], k=1)[0]
        if mode == "ICMP":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) / ICMP())
        else:
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=80,
                               flags="A", window=random.randint(512, 4096)))
    return packets

def fin_scanner(src_ip, dst_ips, packet_count):
    packets = []
    candidate_ports = list(range(20, 400))
    random.shuffle(candidate_ports)
    for i in range(packet_count):
        dst_ip = random.choice(dst_ips)
        port = candidate_ports[i % len(candidate_ports)]
        mode = random.choices(["FIN", "SYN"], weights=[70, 30], k=1)[0]
        if mode == "FIN":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=port,
                               flags="F", window=random.randint(512, 4096)))
        else:
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=port,
                               flags="S", window=random.randint(512, 4096)))
    return packets

def psh_attacker(src_ip, dst_ips, packet_count):
    packets = []
    for _ in range(packet_count):
        dst_ip = random.choice(dst_ips)
        mode = random.choices(["PSH", "ACK"], weights=[65, 35], k=1)[0]
        if mode == "PSH":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443]),
                               flags="P", window=random.randint(512, 4096)))
        else:
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443]),
                               flags="A", window=random.randint(512, 4096)))
    return packets

def ack_attacker(src_ip, dst_ips, packet_count):
    packets = []
    for _ in range(packet_count):
        dst_ip = random.choice(dst_ips)
        mode = random.choices(["ACK", "SYN"], weights=[75, 25], k=1)[0]
        if mode == "ACK":
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443]),
                               flags="A", window=random.randint(512, 4096)))
        else:
            packets.append(IP(src=src_ip, dst=dst_ip, ttl=random.randint(40, 90)) /
                           TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443]),
                               flags="S", window=random.randint(512, 4096)))
    return packets

captures = [f"capture_{i:02d}.pcap" for i in range(1, 21)]

for capture_name in captures:
    packets = []
    dst_ips = [f"192.168.1.{i}" for i in range(20, 30)]

    # many benign users
    for _ in range(random.randint(10, 16)):
        benign_ip = rand_ip("172.16.10")
        if random.random() < 0.5:
            packets.extend(benign_web_client(benign_ip, dst_ips, random.randint(18, 55)))
        else:
            packets.extend(benign_noisy_client(benign_ip, dst_ips, random.randint(18, 55)))

    # some attacks, not always all
    if random.random() < 0.8:
        packets.extend(syn_attacker(rand_ip("10.10.10"), dst_ips, random.randint(25, 75)))
    if random.random() < 0.7:
        packets.extend(ping_attacker(rand_ip("10.20.20"), dst_ips, random.randint(25, 75)))
    if random.random() < 0.7:
        packets.extend(fin_scanner(rand_ip("10.30.30"), dst_ips, random.randint(20, 50)))
    if random.random() < 0.6:
        packets.extend(psh_attacker(rand_ip("10.40.40"), dst_ips, random.randint(20, 60)))
    if random.random() < 0.6:
        packets.extend(ack_attacker(rand_ip("10.50.50"), dst_ips, random.randint(20, 60)))

    random.shuffle(packets)
    wrpcap(os.path.join(OUT_DIR, capture_name), packets)

print(f"Training PCAPs created in: {OUT_DIR}")