import whisper
import sounddevice as sd
import numpy as np
import scipy.io.wavfile as wav

print("Model load ho raha hai... wait karo")
model = whisper.load_model("base")

print("Taiyaar! 5 seconds mein bolo...")
duration = 5
sample_rate = 16000

audio = sd.rec(int(duration * sample_rate),
               samplerate=sample_rate,
               channels=1, dtype='int16')
sd.wait()

wav.write("test.wav", sample_rate, audio)
print("Recording complete!")

result = model.transcribe("test.wav")
print("Tumne kaha:", result["text"])