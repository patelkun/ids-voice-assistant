import pyttsx3
import time

def speak(text):
    engine = pyttsx3.init()
    engine.setProperty('rate', 160)
    engine.say(text)
    engine.runAndWait()
    del engine

speak("Hello! Main tumhara AI assistant hoon.")
time.sleep(1)
speak("Project shuru ho gaya hai.")

print("Done!")
