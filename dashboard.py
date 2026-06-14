from dl_predict import dl_predict
from honeypot import start_honeypot
import json
from geopy.distance import geodesic
import requests
import folium
from streamlit_folium import st_folium
import whisper
import sounddevice as sd
import scipy.io.wavfile as wav
import webbrowser
import os
from dotenv import load_dotenv
load_dotenv()
from email_alert import send_alert
import streamlit as st
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import threading
import pickle
from database import save_alert, get_all_alerts
import subprocess

with open("ids_model.pkl", "rb") as f:
    ml_model = pickle.load(f)

def predict_attack(packet_count, avg_size, port_443, port_22, udp_ratio):
    features = [[packet_count, avg_size, port_443, port_22, udp_ratio]]
    return ml_model.predict(features)[0]

st.set_page_config(page_title="IDS Dashboard", page_icon="🛡️", layout="wide")
# Login system
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("🔐 IDS Dashboard Login")
    st.subheader("Sirf authorized user access kar sakta hai")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username == "kunj" and password == "ids@2024":
            st.session_state.logged_in = True
            st.success("Login successful!")
            st.rerun()
        else:
            st.error("Wrong username or password!")
    st.stop()
st.markdown("""
<style>
    /* Dark mode */
    .stApp {
        background-color: #0e1117;
        color: #ffffff;
    }
    .stMetric {
        background-color: #1e2130;
        border-radius: 10px;
        padding: 10px;
        border: 1px solid #2d3250;
    }
    .stDataFrame {
        background-color: #1e2130;
    }
    .stButton button {
        background-color: #2d3250;
        color: white;
        border: 1px solid #4a5080;
        border-radius: 8px;
    }
    .stButton button:hover {
        background-color: #4a5080;
        border-color: #6a70a0;
    }
    h1, h2, h3 {
        color: #00ff88 !important;
    }
    .stAlert {
        background-color: #1e2130;
    }
    /* Sidebar */
    .css-1d391kg {
        background-color: #1e2130;
    }
    /* Chat */
    .stChatMessage {
        background-color: #1e2130;
        border-radius: 10px;
        border: 1px solid #2d3250;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AI Intrusion Detection System")
st.subheader("Real-time Network Monitor — Kunj Patel")

MY_IP = "10.229.38.182"

if "packets" not in st.session_state:
    st.session_state.packets = []
if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

# Threat level calculate karo
alert_count = len(st.session_state.alerts)
if alert_count == 0:
    threat_level = "🟢 LOW"
    threat_color = "green"
elif alert_count <= 2:
    threat_level = "🟡 MEDIUM"
    threat_color = "orange"
elif alert_count <= 5:
    threat_level = "🔴 HIGH"
    threat_color = "red"
else:
    threat_level = "🚨 CRITICAL"
    threat_color = "darkred"

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Packets", len(st.session_state.packets))
with col2:
    st.metric("Alerts", len(st.session_state.alerts))
with col3:
    st.metric("Status", "🟢 Active")
with col4:
    st.metric("Threat Level", threat_level)

st.divider()
st.divider()
st.subheader("🍯 Honeypot System")
col_h1, col_h2 = st.columns(2)

with col_h1:
    if st.button("🍯 Start Honeypot"):
        if "honeypot_running" not in st.session_state:
            start_honeypot()
            st.session_state.honeypot_running = True
            st.success("Honeypot active! Ports: SSH-2222, HTTP-8080, FTP-2121")

with col_h2:
    # Honeypot logs dikhao
    try:
        with open("honeypot_logs.json", "r") as f:
            logs = json.load(f)
        if logs:
            st.warning(f"⚠️ {len(logs)} honeypot hits detected!")
            st.dataframe(pd.DataFrame(logs), use_container_width=True)
    except:
        st.info("Koi honeypot logs nahi hain abhi.")

st.subheader("🎤 Voice Command")
col_v1, col_v2 = st.columns([1, 3])

with col_v1:
    if st.button("🎤 Bolo (5 sec)"):
        with st.spinner("Sun raha hoon..."):
            sample_rate = 16000
            audio = sd.rec(int(5 * sample_rate),
                          samplerate=sample_rate,
                          channels=1, dtype='int16')
            sd.wait()
            wav.write("dashboard_input.wav", sample_rate, audio)
            
            model = whisper.load_model("base")
            result = model.transcribe("dashboard_input.wav")
            command = result["text"].strip().lower()
            
            st.success(f"Tumne kaha: {command}")
            
            if "youtube" in command:
                st.info("YouTube khul raha hai!")
                webbrowser.open("https://www.youtube.com")
            elif "google" in command:
                st.info("Google khul raha hai!")
                webbrowser.open("https://www.google.com")
            elif "check" in command or "scan" in command or "network" in command:
                st.info("Network scan shuru ho raha hai!")
            elif "alert" in command:
                st.info("Alerts dekh rahe hain!")
            else:
                st.warning(f"Command samajh nahi aaya: {command}")


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

                    # Threat Intelligence check
                    try:
                        threat = check_ip_threat(src)
                        if threat["is_malicious"]:
                            st.session_state.alerts.append({
                                "IP": src,
                                "Alert": f"🌍 Threat Intel: {threat['threat_type']} | Score: {threat['abuse_score']}/100 | Country: {threat['country']} | ISP: {threat['isp']}"
                            })
                    except:
                        pass

                    save_alert(src, "Suspicious IP")

                    send_alert(src, "Suspicious IP detected")
                    # Auto IP block
                    try:
                        block_cmd = f'netsh advfirewall firewall add rule name="IDS_BLOCK_{src}" dir=in action=block remoteip={src}'
                        subprocess.run(block_cmd, shell=True, capture_output=True)
                        st.session_state.alerts.append({
                            "IP": src,
                            "Alert": f"🚫 IP {src} automatically blocked!"
                        })
                        print(f"Blocked: {src}")
                    except Exception as e:
                        print(f"Block error: {e}")
                        
                    st.session_state.alerts.append({
                        "IP": src,
                        "Alert": f"Suspicious! {src} ne 10+ packets bheje"
                    })
                    def say_alert(ip):
                        try:
                            import pyttsx3
                            engine = pyttsx3.init()
                            engine.setProperty('rate', 160)
                            engine.say(f"Warning! Suspicious IP {ip} detected!")
                            engine.runAndWait()
                            engine.stop()
                            del engine
                        except:
                            pass
                    threading.Thread(target=say_alert, args=(src,)).start()

                    port_443 = 1 if (TCP in pkt and pkt[TCP].dport == 443) else 0
                    port_22 = 1 if (TCP in pkt and pkt[TCP].dport == 22) else 0
                    udp_ratio = 1.0 if UDP in pkt else 0.0
                    # Old ML prediction
                    prediction = predict_attack(
                      packet_count=ip_counter.get(src, 1),
                      avg_size=len(pkt),
                      port_443=port_443,
                      port_22=port_22,
                      udp_ratio=udp_ratio
                    )
                    if prediction != "normal":
                       st.session_state.alerts.append({
                          "IP": src,
                          "Alert": f"ML Detection: {prediction} from {src}!"
                            })

                     # Deep Learning prediction
                    dl_attack, confidence = dl_predict(
                        packet_count=ip_counter.get(src, 1),
                        avg_size=len(pkt),
                        port_443=port_443,
                        port_22=port_22,
                        port_80=0,
                        udp_ratio=udp_ratio,
                        inter_arrival=0.1,
                        burst_size=ip_counter.get(src, 1)
                    )
                    if dl_attack != "normal":
                        st.session_state.alerts.append({
                        "IP": src,
                        "Alert": f"🧠 Deep Learning: {dl_attack} ({confidence:.1f}% confidence) from {src}!"
                   })
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

st.divider()
st.subheader("🗺️ Suspicious IP Geo Location Map")

if st.session_state.alerts:
    m = folium.Map(location=[20, 0], zoom_start=2)
    
    located_ips = set()
    
    for alert in st.session_state.alerts:
        ip = alert.get("IP", "")
        if ip and ip not in located_ips:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                data = response.json()
                
                if data["status"] == "success":
                    lat = data["lat"]
                    lon = data["lon"]
                    country = data["country"]
                    city = data["city"]
                    
                    # Tumhari location — Ahmedabad
                    my_location = (23.0225, 72.5714)
                    attack_location = (lat, lon)
                    distance = round(geodesic(my_location, attack_location).km, 2)

                    # Tumhari location blue marker
                    folium.Marker(
                        location=[23.0225, 72.5714],
                        popup="📍 Tumhari Location — Ahmedabad",
                        tooltip="Aap yahan hain",
                        icon=folium.Icon(color="blue", icon="home")
                    ).add_to(m)

                    # Line — tumse attack tak
                    folium.PolyLine(
                        locations=[my_location, attack_location],
                        color="red",
                        weight=2,
                        opacity=0.8,
                        tooltip=f"Distance: {distance} km"
                    ).add_to(m)

                    # Attack red marker
                    folium.Marker(
                        location=[lat, lon],
                        popup=f"🚨 {ip}\n{city}, {country}\nDistance: {distance} km door",
                        tooltip=f"{ip} — {distance} km door",
                        icon=folium.Icon(color="red", icon="exclamation-sign")
                    ).add_to(m)
                    
                    located_ips.add(ip)
            except:
                pass
    
    st_folium(m, width=1400, height=450, returned_objects=[])
else:
    st.info("Pehle network scan karo — phir map pe IPs dikhenge!")

st.subheader("📜 Attack History — All Time")
all_alerts = get_all_alerts()
if all_alerts:
    history_data = [{
        "IP": a.ip,
        "Attack": a.attack_type,
        "Time": a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    } for a in all_alerts]
    st.dataframe(pd.DataFrame(history_data), use_container_width=True)
else:
    st.info("Abhi koi history nahi hai.")

if st.button("🗑️ Clear Data"):
    st.session_state.packets = []
    st.session_state.alerts = []
    st.session_state.chat_history = []
    st.rerun()

st.divider()
st.subheader("🤖 AI Security Chatbot")

for msg in st.session_state.chat_history:
    if msg["role"] == "user":
        st.chat_message("user").write(msg["content"])
    else:
        st.chat_message("assistant").write(msg["content"])

user_question = st.chat_input("Network ke baare mein kuch poochho...")

if user_question:
    st.session_state.chat_history.append({
        "role": "user",
        "content": user_question
    })

    alert_context = f"Alerts: {st.session_state.alerts}" if st.session_state.alerts else "Koi alerts nahi hain."

    try:
        from groq import Groq
        groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": f"""Tu ek cybersecurity expert AI assistant hai.
                    User ka IDS system chal raha hai. {alert_context}
                    Sirf ek baar jawab de — Hinglish mein — matlab Hindi aur English mix karke simple language mein.
                    Jaise normal baat karte hain waise likho. Koi heading mat banao jaise 'English' ya 'Hindi'.
                    Short aur simple jawab do — maximum 3-4 lines."""
                },
                {"role": "user", "content": user_question}
            ],
            max_tokens=500
        )
        answer = response.choices[0].message.content
    except Exception as e:
        answer = f"Error: {e}"

    st.session_state.chat_history.append({
        "role": "assistant",
        "content": answer
    })
    st.rerun()