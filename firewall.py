from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP
import json
from datetime import datetime

# Load firewall rules
with open("rules.json", "r") as f:
    rules = json.load(f)

def match_rule(pkt):
    ip_layer = pkt.getlayer(IP)
    tcp_layer = pkt.getlayer(TCP)
    udp_layer = pkt.getlayer(UDP)

    src_ip = ip_layer.src
    dst_port = None
    proto = None

    if tcp_layer:
        dst_port = tcp_layer.dport
        proto = "TCP"
    elif udp_layer:
        dst_port = udp_layer.dport
        proto = "UDP"

    for rule in rules:
        r_ip = rule["src_ip"]
        r_port = rule["dst_port"]
        r_proto = rule["protocol"]

        ip_match = r_ip == "ANY" or r_ip == src_ip
        port_match = r_port == "ANY" or int(r_port) == dst_port
        proto_match = r_proto == "ANY" or r_proto == proto

        if ip_match and port_match and proto_match:
            return rule["action"]
    return "ALLOW"

def process(pkt):
    scapy_pkt = IP(pkt.get_payload())
    action = match_rule(scapy_pkt)

    src_ip = scapy_pkt.src
    dst_ip = scapy_pkt.dst
    dst_port = None

    if scapy_pkt.haslayer(TCP):
        dst_port = scapy_pkt[TCP].dport
        proto_name = "TCP"
    elif scapy_pkt.haslayer(UDP):
        dst_port = scapy_pkt[UDP].dport
        proto_name = "UDP"
    else:
        proto_name = f"IP({scapy_pkt.proto})"

    # Detailed log
    log = f"[{datetime.now()}] {action}: {src_ip} -> {dst_ip}:{dst_port} ({proto_name})"
    print(log)

    with open("log.txt", "a") as f:
        f.write(log + "\n")

    # Explicit messages
    if action == "DENY":
        print(f"❌ Dropped packet from {src_ip} to {dst_ip}:{dst_port}")
        pkt.drop()
    else:
        print(f"✅ Accepted packet from {src_ip} to {dst_ip}:{dst_port}")
        pkt.accept()

print("🔥 NetfilterQueue-based Firewall is running… (Ctrl+C to stop)")
nfqueue = NetfilterQueue()
nfqueue.bind(1, process)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("\n[!] Firewall stopped.")
    nfqueue.unbind()
