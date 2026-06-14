import numpy as np
import shap
import pickle
import warnings
warnings.filterwarnings('ignore')

print("Explainable AI (XAI) — Microsoft Defender jaisa")
print("=" * 60)

with open("ids_model.pkl", "rb") as f:
    ml_model = pickle.load(f)

features = ["packet_count", "avg_size", "port_443", "port_22", "udp_ratio"]

print("SHAP initialize ho raha hai...")
explainer = shap.TreeExplainer(ml_model)

def explain_prediction(packet_count, avg_size, port_443, port_22, udp_ratio):
    input_data = np.array([[packet_count, avg_size, port_443, port_22, udp_ratio]])
    
    prediction = ml_model.predict(input_data)[0]
    confidence = round(max(ml_model.predict_proba(input_data)[0]) * 100, 2)
    
    shap_values = explainer.shap_values(input_data)
    
    # Debug — shape dekho
    print(f"SHAP type: {type(shap_values)}")
    if isinstance(shap_values, list):
        print(f"SHAP list length: {len(shap_values)}")
        print(f"SHAP[0] shape: {np.array(shap_values[0]).shape}")
        class_idx = list(ml_model.classes_).index(prediction)
        raw = shap_values[class_idx]
    else:
        print(f"SHAP shape: {np.array(shap_values).shape}")
        raw = shap_values
    
    # Flatten
    raw = np.array(raw).flatten()
    importance = np.abs(raw[:len(features)])
    total = float(np.sum(importance))
    
    reasons = []
    for i, feature in enumerate(features):
        pct = round((float(importance[i]) / total) * 100, 1) if total > 0 else 0
        val = float(input_data[0][i])
        reasons.append({
            "feature": feature,
            "value": round(val, 3),
            "importance": f"{pct}%"
        })
    
    reasons = sorted(reasons, key=lambda x: float(x["importance"].replace("%", "")), reverse=True)
    
    return {"prediction": prediction, "confidence": confidence, "reasons": reasons}

# Test
result = explain_prediction(2, 80, 1, 0, 0.1)
print(f"\nTest 1 — Normal Traffic:")
print(f"Prediction: {result['prediction']} ({result['confidence']}% confidence)")
for r in result["reasons"]:
    print(f"  - {r['feature']}: {r['value']} → {r['importance']} impact")

result = explain_prediction(50, 60, 0, 1, 0)
print(f"\nTest 2 — SSH Brute Force:")
print(f"Prediction: {result['prediction']} ({result['confidence']}% confidence)")
for r in result["reasons"]:
    print(f"  - {r['feature']}: {r['value']} → {r['importance']} impact")

result = explain_prediction(150, 80, 0, 0, 0.9)
print(f"\nTest 3 — Ping Flood:")
print(f"Prediction: {result['prediction']} ({result['confidence']}% confidence)")
for r in result["reasons"]:
    print(f"  - {r['feature']}: {r['value']} → {r['importance']} impact")

with open("xai_explainer.pkl", "wb") as f:
    pickle.dump(explainer, f)

print("\nXAI Complete!")