import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import warnings
warnings.filterwarnings('ignore')

print("Deep Learning IDS — LSTM + Transformer Model")
print("=" * 50)

# ============================================
# 1. ADVANCED DATASET BANAO
# ============================================
np.random.seed(42)
n_samples = 5000

print("Advanced dataset bana raha hoon...")

# Normal traffic
normal = {
    "packet_count": np.random.randint(1, 8, 3000),
    "avg_size": np.random.randint(40, 120, 3000),
    "port_443": np.random.randint(0, 2, 3000),
    "port_22": np.zeros(3000),
    "port_80": np.random.randint(0, 2, 3000),
    "udp_ratio": np.random.uniform(0, 0.3, 3000),
    "inter_arrival": np.random.uniform(0.1, 2.0, 3000),
    "burst_size": np.random.randint(1, 5, 3000),
    "label": ["normal"] * 3000
}

# Port scan attack
port_scan = {
    "packet_count": np.random.randint(50, 200, 500),
    "avg_size": np.random.randint(40, 60, 500),
    "port_443": np.zeros(500),
    "port_22": np.random.randint(0, 2, 500),
    "port_80": np.random.randint(0, 2, 500),
    "udp_ratio": np.random.uniform(0, 0.1, 500),
    "inter_arrival": np.random.uniform(0.001, 0.01, 500),
    "burst_size": np.random.randint(20, 100, 500),
    "label": ["port_scan"] * 500
}

# SSH Brute Force
ssh_brute = {
    "packet_count": np.random.randint(30, 100, 500),
    "avg_size": np.random.randint(40, 80, 500),
    "port_443": np.zeros(500),
    "port_22": np.ones(500),
    "port_80": np.zeros(500),
    "udp_ratio": np.zeros(500),
    "inter_arrival": np.random.uniform(0.01, 0.1, 500),
    "burst_size": np.random.randint(10, 50, 500),
    "label": ["ssh_brute"] * 500
}

# Ping Flood / DDoS
ping_flood = {
    "packet_count": np.random.randint(100, 500, 500),
    "avg_size": np.random.randint(60, 100, 500),
    "port_443": np.zeros(500),
    "port_22": np.zeros(500),
    "port_80": np.zeros(500),
    "udp_ratio": np.random.uniform(0.7, 1.0, 500),
    "inter_arrival": np.random.uniform(0.0001, 0.001, 500),
    "burst_size": np.random.randint(50, 200, 500),
    "label": ["ping_flood"] * 500
}

# Zero Day — Unknown attack pattern
zero_day = {
    "packet_count": np.random.randint(10, 300, 500),
    "avg_size": np.random.randint(200, 1500, 500),
    "port_443": np.random.randint(0, 2, 500),
    "port_22": np.random.randint(0, 2, 500),
    "port_80": np.random.randint(0, 2, 500),
    "udp_ratio": np.random.uniform(0.3, 0.7, 500),
    "inter_arrival": np.random.uniform(0.005, 0.05, 500),
    "burst_size": np.random.randint(5, 150, 500),
    "label": ["zero_day"] * 500
}

# Combine sab
dfs = [pd.DataFrame(d) for d in [normal, port_scan, ssh_brute, ping_flood, zero_day]]
df = pd.concat(dfs, ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"Dataset ready: {len(df)} samples")
print(df["label"].value_counts())

# ============================================
# 2. PREPROCESSING
# ============================================
features = ["packet_count", "avg_size", "port_443", "port_22", 
            "port_80", "udp_ratio", "inter_arrival", "burst_size"]

X = df[features].values
y = df["label"].values

le = LabelEncoder()
y_encoded = le.fit_transform(y)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# Save scaler and encoder
with open("dl_scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)
with open("dl_encoder.pkl", "wb") as f:
    pickle.dump(le, f)

print(f"\nClasses: {le.classes_}")

# ============================================
# 3. LSTM + TRANSFORMER MODEL
# ============================================
print("\nModel build kar raha hoon...")

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Reshape for LSTM — (samples, timesteps, features)
X_train_lstm = X_train.reshape(X_train.shape[0], 1, X_train.shape[1])
X_test_lstm = X_test.reshape(X_test.shape[0], 1, X_test.shape[1])

n_classes = len(le.classes_)

# Model architecture
inputs = keras.Input(shape=(1, len(features)))

# LSTM layer
lstm_out = layers.LSTM(128, return_sequences=True)(inputs)
lstm_out = layers.Dropout(0.3)(lstm_out)
lstm_out = layers.LSTM(64, return_sequences=True)(lstm_out)

# Transformer — Multi Head Attention
attention_out = layers.MultiHeadAttention(
    num_heads=4, key_dim=16
)(lstm_out, lstm_out)
attention_out = layers.LayerNormalization()(attention_out + lstm_out)

# Flatten and Dense
flat = layers.Flatten()(attention_out)
dense = layers.Dense(128, activation="relu")(flat)
dense = layers.Dropout(0.3)(dense)
dense = layers.Dense(64, activation="relu")(dense)
outputs = layers.Dense(n_classes, activation="softmax")(dense)

model = keras.Model(inputs, outputs)

model.compile(
    optimizer=keras.optimizers.Adam(learning_rate=0.001),
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)

model.summary()

# ============================================
# 4. TRAIN
# ============================================
print("\nModel train ho raha hai...")

early_stop = keras.callbacks.EarlyStopping(
    monitor="val_accuracy", patience=5, restore_best_weights=True
)

history = model.fit(
    X_train_lstm, y_train,
    epochs=30,
    batch_size=32,
    validation_split=0.2,
    callbacks=[early_stop],
    verbose=1
)

# ============================================
# 5. EVALUATE
# ============================================
y_pred = np.argmax(model.predict(X_test_lstm), axis=1)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n{'='*50}")
print(f"Model Accuracy: {accuracy*100:.2f}%")
print(f"{'='*50}")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# Save model
model.save("deep_ids_model.keras")
print("\nModel saved — deep_ids_model.keras")
print("Scaler saved — dl_scaler.pkl")
print("Encoder saved — dl_encoder.pkl")