import whisper
import sounddevice as sd
import numpy as np
import scipy.io.wavfile as wav
import pyttsx3
import time

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
    text = result["text"].strip()
    print("Tumne kaha:", text)
    return text

speak("Main sun raha hoon. Kuch bolo.")
command = listen()
speak(f"Tumne kaha: {command}")