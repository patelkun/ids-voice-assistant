import pyttsx3
import random
import time

def speak(text):
    engine = pyttsx3.init()
    engine.setProperty('rate', 160)
    engine.say(text)
    engine.runAndWait()
    del engine

fake_attacks = [
    ("Port Scan",  "192.168.1.105", "HIGH"),
    ("SSH Brute",  "10.0.0.23",     "CRITICAL"),
    ("Ping Flood", "172.16.0.8",    "MEDIUM"),
]

attack = random.choice(fake_attacks)
name, ip, level = attack

msg = f"Alert! {level} severity. {name} detected from IP {ip}."
print(msg)
speak(msg)

time.sleep(1)
speak("System monitoring active.")