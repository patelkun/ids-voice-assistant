from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import datetime
import csv
import pyttsx3
import threading



MY_IP = "10.229.38.182"  # tumhara laptop IP

def speak(text):
    try:
        engine = pyttsx3.init()
        engine.setProperty('rate', 160)
        engine.say(text)
        engine.runAndWait()
        engine.stop()
        del engine
    except:
        print(f"Alert: {text}")

captured = []
ip_counter = Counter()
port_counter = Counter()
alerted_ips = set()

def analyze_packet(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "TCP" if TCP in pkt else "UDP"
        length = len(pkt)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        if TCP in pkt:
            dst_port = pkt[TCP].dport
        else:
            dst_port = 0

        print(f"[{timestamp}] {src_ip} → {dst_ip} | {protocol} | Port:{dst_port}")

        if src_ip != MY_IP:
            ip_counter[src_ip] += 1

            if ip_counter[src_ip] == 15 and src_ip not in alerted_ips:
                alerted_ips.add(src_ip)
                alert = f"Warning! Suspicious IP {src_ip} ne bahut packets bheje!"
                print(f"\n⚠️  {alert}\n")
                threading.Thread(target=speak, args=(alert,)).start()

            if dst_port == 22:
                port_counter["SSH"] += 1
                if port_counter["SSH"] == 3:
                    alert = "Critical! SSH Brute Force attack detect hua!"
                    print(f"\n🚨 {alert}\n")
                    threading.Thread(target=speak, args=(alert,)).start()

speak("IDS system shuru ho gaya. Network monitor ho raha hai.")
print("=== IDS SYSTEM ACTIVE ===")
print("Ctrl+C dabaao band karne ke liye\n")

try:
    sniff(prn=analyze_packet, store=False, timeout=60)
except KeyboardInterrupt:
    pass

print(f"\n=== SUMMARY ===")
print(f"Total IPs dekhe: {len(ip_counter)}")
speak("Monitoring complete. System band ho raha hai.")