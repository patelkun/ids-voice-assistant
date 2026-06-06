from scapy.all import sniff, IP, TCP, UDP
import datetime
import csv

print("Network capture shuru ho raha hai...")
print("Ctrl+C dabaao band karne ke liye\n")

captured = []

def analyze_packet(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
        length = len(pkt)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        if TCP in pkt:
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        else:
            dst_port = 0
            flags = "N/A"

        info = {
            "time": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "port": dst_port,
            "length": length,
            "flags": flags
        }

        captured.append(info)
        print(f"[{timestamp}] {src_ip} → {dst_ip} | {protocol} | Port:{dst_port} | Size:{length}")

try:
    sniff(prn=analyze_packet, store=False, timeout=30)
except KeyboardInterrupt:
    pass

# CSV mein save karo
if captured:
    with open("traffic.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=captured[0].keys())
        writer.writeheader()
        writer.writerows(captured)
    print(f"\n{len(captured)} packets capture hue — traffic.csv mein save ho gaye!")