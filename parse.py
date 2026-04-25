from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime
import json

# load the pcap file
packets = rdpcap("traffic.pcapng")

parsed = []

for packet in packets:
    if IP in packet:
        entry = {
            "timestamp": datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S'),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "size": len(packet),
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER",
            "src_port": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None,
            "dst_port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None,
        }
        parsed.append(entry)

print(f"Parsed {len(parsed)} packets")

# save to json
with open("traffic_data.json", "w") as f:
    json.dump(parsed, f, indent=2)

print("Saved to traffic_data.json")