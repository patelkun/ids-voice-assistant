from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import whisper
import sounddevice as sd
import scipy.io.wavfile as wav
import pyttsx3
import webbrowser
import datetime
import time
import random
import threading

model = whisper.load_model("base")

def speak(text):
    engine = pyttsx3.init()
    engine.setProperty('rate', 160)
    engine.say(text)
    engine.runAndWait()
    del engine

def listen():
    print("Bolo... (5 seconds)")
    duration = 5
    sample_rate = 16000
    audio = sd.rec(int(duration * sample_rate),
                   samplerate=sample_rate,
                   channels=1, dtype='int16')
    sd.wait()
    wav.write("input.wav", sample_rate, audio)
    result = model.transcribe("input.wav")
    text = result["text"].strip().lower()
    print("Tumne kaha:", text)
    return text

def handle_command(command):
    if "youtube" in command:
        speak("YouTube khol raha hoon!")
        webbrowser.open("https://www.youtube.com")

    elif "time" in command or "kitne baje" in command:
        now = datetime.datetime.now().strftime("%I:%M %p")
        speak(f"Abhi time hai {now}")

    elif "alert" in command:
        attacks = [
            ("Port Scan",  "192.168.1.105", "HIGH"),
            ("SSH Brute",  "10.0.0.23",     "CRITICAL"),
            ("Ping Flood", "172.16.0.8",    "MEDIUM"),
        ]
        name, ip, level = random.choice(attacks)
        msg = f"Alert! {level} severity. {name} detected from IP {ip}."
        print(msg)
        speak(msg)

    elif "google" in command:
        speak("Google khol raha hoon!")
        webbrowser.open("https://www.google.com")

    elif "band" in command or "stop" in command or "exit" in command or "quit" in command:
        speak("Assistant stop ho raha hai. Bye!")
        return False

    elif "facebook" in command:
        speak("Facebook khol raha hoon!")
        webbrowser.open("https://www.facebook.com")

    elif "instagram" in command:
        speak("Instagram khol raha hoon!")
        webbrowser.open("https://www.instagram.com")

    elif "kunj" in command:
        speak("Hello Kunj! Kaise ho? Main tumhara AI assistant hoon!")

    elif "weather" in command or "mausam" in command:
        speak("Weather check karne ke liye Google khol raha hoon!")
        webbrowser.open("https://www.google.com/search?q=ahmedabad+weather")

    elif "network" in command or "scan" in command or "check" in command or "checknetwork" in command:
        speak("Network scan shuru ho raha hai. 15 seconds ruko.")
        
        from scapy.all import sniff, IP, TCP
        from collections import Counter

        MY_IP = "10.229.38.182"
        ip_counter = Counter()
        alerted_ips = set()
        results = []

        def analyze(pkt):
            if IP in pkt and pkt[IP].src != MY_IP:
                ip = pkt[IP].src
                ip_counter[ip] += 1
                if ip_counter[ip] == 10 and ip not in alerted_ips:
                    alerted_ips.add(ip)
                    alert = f"Warning! Suspicious IP {ip} detected!"
                    print(f"⚠️  {alert}")
                    results.append(alert)

        print("Scanning...")
        sniff(prn=analyze, store=False, timeout=15)

        if results:
            for r in results:
                speak(r)
        else:
            speak("Network safe hai. Koi suspicious activity nahi mili.")
    else:
        speak(f"Samjha nahi. Tumne kaha: {command}")

    return True

# Main loop
speak("Hello Kunj! Main ready hoon. Kuch bolo.")

while True:
    command = listen()
    if command:
        running = handle_command(command)
        if not running:
            break
    time.sleep(1)