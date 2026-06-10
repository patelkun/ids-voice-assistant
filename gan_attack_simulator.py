import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt
import pickle
import warnings
warnings.filterwarnings('ignore')

print("GAN Attack Simulator — AI se naye attacks generate karo")
print("=" * 60)

# ============================================
# 1. REAL ATTACK DATA PREPARE KARO
# ============================================
np.random.seed(42)

features = ["packet_count", "avg_size", "port_443", "port_22",
            "port_80", "udp_ratio", "inter_arrival", "burst_size"]

# Real attack samples
real_attacks = np.array([
    # SSH Brute Force patterns
    *[[np.random.randint(30,100), np.random.randint(40,80), 0, 1, 0,
       0, np.random.uniform(0.01,0.1), np.random.randint(10,50)] for _ in range(500)],
    # Ping Flood patterns
    *[[np.random.randint(100,500), np.random.randint(60,100), 0, 0, 0,
       np.random.uniform(0.7,1.0), np.random.uniform(0.0001,0.001), np.random.randint(50,200)] for _ in range(500)],
    # Port Scan patterns
    *[[np.random.randint(50,200), np.random.randint(40,60), 0, np.random.randint(0,2), np.random.randint(0,2),
       0, np.random.uniform(0.001,0.01), np.random.randint(20,100)] for _ in range(500)],
])

# Normalize
from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
real_attacks_scaled = scaler.fit_transform(real_attacks)

n_features = len(features)
latent_dim = 32

print(f"Real attack samples: {len(real_attacks)}")

# ============================================
# 2. GENERATOR — Fake attacks banata hai
# ============================================
def build_generator():
    model = keras.Sequential([
        layers.Dense(64, activation="relu", input_shape=(latent_dim,)),
        layers.BatchNormalization(),
        layers.Dense(128, activation="relu"),
        layers.BatchNormalization(),
        layers.Dense(256, activation="relu"),
        layers.BatchNormalization(),
        layers.Dense(n_features, activation="sigmoid")
    ], name="Generator")
    return model

# ============================================
# 3. DISCRIMINATOR — Real ya fake decide karta hai
# ============================================
def build_discriminator():
    model = keras.Sequential([
        layers.Dense(256, activation="leaky_relu", input_shape=(n_features,)),
        layers.Dropout(0.3),
        layers.Dense(128, activation="leaky_relu"),
        layers.Dropout(0.3),
        layers.Dense(64, activation="leaky_relu"),
        layers.Dense(1, activation="sigmoid")
    ], name="Discriminator")
    return model

# ============================================
# 4. GAN TRAINING
# ============================================
generator = build_generator()
discriminator = build_discriminator()

discriminator.compile(
    optimizer=keras.optimizers.Adam(0.0002, 0.5),
    loss="binary_crossentropy",
    metrics=["accuracy"]
)

# GAN — Generator + Discriminator
z = keras.Input(shape=(latent_dim,))
fake_attack = generator(z)
discriminator.trainable = False
validity = discriminator(fake_attack)

gan = keras.Model(z, validity)
gan.compile(
    optimizer=keras.optimizers.Adam(0.0002, 0.5),
    loss="binary_crossentropy"
)

print("\nGAN Training shuru ho raha hai...")
print("Generator aur Discriminator lad rahe hain!")

epochs = 2000
batch_size = 64
d_losses = []
g_losses = []

for epoch in range(epochs):
    # Train Discriminator
    idx = np.random.randint(0, real_attacks_scaled.shape[0], batch_size)
    real = real_attacks_scaled[idx]
    noise = np.random.normal(0, 1, (batch_size, latent_dim))
    fake = generator.predict(noise, verbose=0)
    
    real_labels = np.ones((batch_size, 1)) * 0.9  # Label smoothing
    fake_labels = np.zeros((batch_size, 1))
    
    d_loss_real = discriminator.train_on_batch(real, real_labels)
    d_loss_fake = discriminator.train_on_batch(fake, fake_labels)
    d_loss = 0.5 * np.add(d_loss_real, d_loss_fake)
    
    # Train Generator
    noise = np.random.normal(0, 1, (batch_size, latent_dim))
    g_loss = gan.train_on_batch(noise, np.ones((batch_size, 1)))
    
    d_losses.append(d_loss[0])
    g_losses.append(g_loss)
    
    if epoch % 200 == 0:
        print(f"Epoch {epoch}/{epochs} | D Loss: {d_loss[0]:.4f} | G Loss: {g_loss:.4f}")

print("\nGAN Training complete!")

# ============================================
# 5. FAKE ATTACKS GENERATE KARO
# ============================================
print("\nNaye attack patterns generate kar raha hoon...")
noise = np.random.normal(0, 1, (100, latent_dim))
generated_attacks = generator.predict(noise, verbose=0)
generated_attacks_original = scaler.inverse_transform(generated_attacks)

df_generated = pd.DataFrame(generated_attacks_original, columns=features)
df_generated = df_generated.round(2)
df_generated["label"] = "GAN_generated"
df_generated.to_csv("gan_generated_attacks.csv", index=False)

print(f"100 naye attack patterns generate hue!")
print(df_generated.head())

# ============================================
# 6. TRAINING GRAPH
# ============================================
plt.figure(figsize=(10, 4))
plt.plot(d_losses, label="Discriminator Loss", color="red", alpha=0.7)
plt.plot(g_losses, label="Generator Loss", color="blue", alpha=0.7)
plt.title("GAN Training — Generator vs Discriminator")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.legend()
plt.savefig("gan_training.png")
plt.close()
print("Training graph saved — gan_training.png")

# ============================================
# 7. MODELS SAVE KARO
# ============================================
generator.save("gan_generator.keras")
print("Generator saved — gan_generator.keras")

print("\n" + "="*60)
print("GAN Attack Simulator Complete!")
print(f"Generated attacks saved: gan_generated_attacks.csv")
print(f"Training graph saved: gan_training.png")
print("="*60)