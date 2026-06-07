import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle

print("Training data bana raha hoon...")

# Synthetic training data — real attacks ki tarah
np.random.seed(42)
n = 1000

data = {
    "packet_count":  list(np.random.randint(1, 5, 700)) + 
                     list(np.random.randint(10, 50, 150)) + 
                     list(np.random.randint(50, 200, 150)),
    "avg_size":      list(np.random.randint(40, 100, 700)) + 
                     list(np.random.randint(40, 80, 150)) + 
                     list(np.random.randint(60, 100, 150)),
    "port_443":      list(np.random.randint(0, 2, 700)) + 
                     list(np.random.randint(0, 2, 150)) + 
                     list(np.random.randint(0, 2, 150)),
    "port_22":       [0]*700 + list(np.random.randint(1, 5, 150)) + [0]*150,
    "udp_ratio":     list(np.random.uniform(0, 0.3, 700)) + 
                     list(np.random.uniform(0, 0.2, 150)) + 
                     list(np.random.uniform(0.7, 1.0, 150)),
    "label":         ["normal"]*700 + ["ssh_brute"]*150 + ["ping_flood"]*150
}

df = pd.DataFrame(data)
print(f"Dataset ready: {len(df)} samples")
print(df["label"].value_counts())

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("\nModel train ho raha hai...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nModel Accuracy: {accuracy*100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred))

# Model save karo
with open("ids_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("\nModel saved — ids_model.pkl")