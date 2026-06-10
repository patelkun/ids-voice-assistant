import numpy as np
import pickle
import tensorflow as tf

# Models load karo
model = tf.keras.models.load_model("deep_ids_model.keras")

with open("dl_scaler.pkl", "rb") as f:
    scaler = pickle.load(f)
with open("dl_encoder.pkl", "rb") as f:
    le = pickle.load(f)

def dl_predict(packet_count, avg_size, port_443, port_22, 
               port_80, udp_ratio, inter_arrival, burst_size):
    features = np.array([[packet_count, avg_size, port_443, port_22,
                          port_80, udp_ratio, inter_arrival, burst_size]])
    scaled = scaler.transform(features)
    lstm_input = scaled.reshape(1, 1, 8)
    pred = model.predict(lstm_input, verbose=0)
    confidence = float(np.max(pred) * 100)
    attack_type = le.inverse_transform([np.argmax(pred)])[0]
    return attack_type, confidence