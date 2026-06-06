import csv
from collections import Counter

def speak(text):
    import pyttsx3
    engine = pyttsx3.init()
    engine.setProperty('rate', 160)
    engine.say(text)
    engine.runAndWait()
    del engine

MY_IP = "10.229.38.182"  # tumhara apna laptop IP

print("Traffic analyze ho raha hai...\n")

src_ips = []
ports = []
suspicious = []

with open("traffic.csv", "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row["src_ip"] != MY_IP:
            src_ips.append(row["src_ip"])
        ports.append(row["port"])

ip_count = Counter(src_ips)
port_count = Counter(ports)

print("=== TOP EXTERNAL IPs ===")
for ip, count in ip_count.most_common(5):
    print(f"{ip} → {count} packets")
    if count > 10:
        suspicious.append(f"Warning! IP {ip} ne {count} packets bheje — suspicious activity!")

print("\n=== TOP PORTS ===")
for port, count in port_count.most_common(5):
    print(f"Port {port} → {count} packets")
    if port == "22" and count > 3:
        suspicious.append("Critical! SSH Brute Force detected on Port 22!")
    if port == "23" and count > 3:
        suspicious.append("Critical! Telnet attack detected on Port 23!")

print("\n=== ALERTS ===")
if suspicious:
    for alert in suspicious:
        print(f"⚠️  {alert}")
        speak(alert)
else:
    print("✅ Network safe hai!")
    speak("Network safe hai. Koi suspicious activity nahi mili.")