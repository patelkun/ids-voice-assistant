import streamlit as st
import pyttsx3
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import threading
import time

st.set_page_config(page_title="IDS Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Intrusion Detection System")
st.subheader("Real-time Network Monitor — Kunj Patel")

MY_IP = "10.229.38.182"

if "packets" not in st.session_state:
    st.session_state.packets = []
if "alerts" not in st.session_state:
    st.session_state.alerts = []

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Total Packets", len(st.session_state.packets))
with col2:
    st.metric("Alerts", len(st.session_state.alerts))
with col3:
    st.metric("Status", "🟢 Active")

st.divider()

if st.button("🔍 Start Network Scan (15 sec)"):
    ip_counter = Counter()
    alerted = set()
    new_packets = []

    def capture(pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "TCP" if TCP in pkt else "UDP"
            new_packets.append({
                "Source IP": src,
                "Destination IP": dst,
                "Protocol": proto,
                "Size": len(pkt)
            })
            if src != MY_IP:
                ip_counter[src] += 1
                if ip_counter[src] == 10 and src not in alerted:
                    alerted.add(src)
                    st.session_state.alerts.append({
                        "IP": src,
                        "Alert": f"Suspicious! {src} ne 10+ packets bheje"
                    })
                    import threading
                    import pyttsx3
                    def say_alert(ip):
                        try:
                            engine = pyttsx3.init()
                            engine.setProperty('rate', 160)
                            engine.say(f"Warning! Suspicious IP {ip} detected!")
                            engine.runAndWait()
                            engine.stop()
                            del engine
                        except:
                            pass
                    threading.Thread(target=say_alert, args=(src,)).start()

    with st.spinner("Scanning network..."):
        sniff(prn=capture, store=False, timeout=15)

    st.session_state.packets.extend(new_packets)
    st.success(f"Scan complete! {len(new_packets)} packets captured.")
    st.rerun()

st.divider()

if st.session_state.alerts:
    st.subheader("⚠️ Alerts")
    df_alerts = pd.DataFrame(st.session_state.alerts)
    st.dataframe(df_alerts, use_container_width=True)

if st.session_state.packets:
    st.subheader("📊 Network Traffic")
    df = pd.DataFrame(st.session_state.packets)
    st.dataframe(df.tail(20), use_container_width=True)

    st.subheader("📈 Top IPs")
    ip_counts = df["Source IP"].value_counts().head(10)
    st.bar_chart(ip_counts)

if st.button("🗑️ Clear Data"):
    st.session_state.packets = []
    st.session_state.alerts = []
    st.rerun()