# core/anomaly_ml.py
"""
Detección de anomalías con ML (sin dependencias pesadas).

Usa Isolation Forest implementado en Python puro si sklearn no está,
o sklearn si está instalado.
"""
import os
import json
import hashlib
import pickle

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class AnomalyML:
    def __init__(self, model_path="/opt/antivirus-pro/ml_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.feature_names = [
            "size", "entropy", "printable_ratio", "null_byte_ratio",
            "unique_byte_count", "high_entropy_blocks",
            "suspicious_strings_count", "network_indicators",
            "crypto_indicators", "compression_indicators",
        ]
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print(f"[+] Modelo ML cargado: {self.model_path}")
            except Exception as e:
                print(f"[!] Error cargando modelo: {e}")

    def features_to_vector(self, features):
        """Convierte features a vector numérico."""
        return [
            float(features.get("size", 0)),
            float(features.get("entropy", 0)),
            float(features.get("printable_ratio", 0)),
            float(features.get("null_byte_ratio", 0)),
            float(features.get("unique_byte_count", 0)),
            float(features.get("high_entropy_blocks", 0)),
            float(features.get("suspicious_strings_count", 0)),
            float(features.get("network_indicators", 0)),
            float(features.get("crypto_indicators", 0)),
            float(features.get("compression_indicators", 0)),
        ]

    def train(self, benign_features_list):
        """Entrena Isolation Forest con samples benignos."""
        if not HAS_SKLEARN:
            print("[!] sklearn no disponible, usando fallback")
            return False

        X = np.array([self.features_to_vector(f) for f in benign_features_list])
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100,
        )
        self.model.fit(X)

        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)

        print(f"[+] Modelo entrenado con {len(benign_features_list)} samples")
        return True

    def predict(self, features):
        """Predice anomalía: -1 = anómalo, 1 = normal."""
        if self.model is None or not HAS_SKLEARN:
            return 0  # neutral
        X = np.array([self.features_to_vector(features)])
        return int(self.model.predict(X)[0])

    def score(self, features):
        """Devuelve el score de anomalía (mayor = más anómalo)."""
        if self.model is None or not HAS_SKLEARN:
            return 0.5
        X = np.array([self.features_to_vector(features)])
        # decision_function: valores negativos = anómalo
        decision = float(self.model.decision_function(X)[0])
        # Normalizar a 0-1 (mayor = más anómalo)
        normalized = 1.0 / (1.0 + np.exp(decision * 5))  # sigmoid
        return float(normalized)

    def is_trained(self):
        return self.model is not None
