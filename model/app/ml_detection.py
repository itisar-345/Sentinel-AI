# ml_detection.py
import os
import pickle
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import logging
from datetime import datetime
from pathlib import Path
from performance_cache import performance_monitor, cache_result

class MLDetectionEngine:
    def __init__(self):
        # CORRECT PATH: from app/ → ../models/
        self.model_path = str(Path(__file__).parent.parent / "models")
        self.model = None
        self.scaler = None
        self.feature_columns = None
        self.isolation_forest = None
        self.logger = logging.getLogger(__name__)
        self.load_enhanced_models()

    def load_enhanced_models(self):
        try:
            # Load feature columns
            fc_path = os.path.join(self.model_path, 'feature_columns.pkl')
            if not os.path.exists(fc_path):
                raise FileNotFoundError(f"Missing: {fc_path}")
            with open(fc_path, 'rb') as f:
                self.feature_columns = pickle.load(f)
            self.logger.info(f"Loaded {len(self.feature_columns)} features")

            # Load scaler
            scaler_path = os.path.join(self.model_path, 'scaler_enhanced.pkl')
            if not os.path.exists(scaler_path):
                raise FileNotFoundError(f"Missing: {scaler_path}")
            self.scaler = joblib.load(scaler_path)

            # Load model
            rf_path = os.path.join(self.model_path, 'randomforest_enhanced.pkl')
            if not os.path.exists(rf_path):
                raise FileNotFoundError(f"Missing: {rf_path}")
            self.model = joblib.load(rf_path)

            # Isolation Forest
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)

            self.logger.info("All models loaded")
        except Exception as e:
            self.logger.error(f"Load failed: {e}")
            self.initialize_fallback_models()

    def initialize_fallback_models(self):
        self.logger.warning("Using fallback model")
        self.feature_columns = [
            'duration', 'total_packets', 'total_bytes', 'packets_per_second',
            'bytes_per_second', 'avg_packet_size', 'std_packet_size',
            'min_packet_size', 'max_packet_size', 'avg_iat', 'std_iat',
            'syn_flag_count', 'psh_flag_count', 'ack_flag_count',
            'is_tcp', 'is_udp', 'is_icmp'
        ]
        X = np.random.randn(200, len(self.feature_columns))
        y = (np.random.rand(200) > 0.7).astype(int)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.model.fit(X_scaled, y)

    def preprocess_features(self, flow_features):
        if isinstance(flow_features, dict):
            df = pd.DataFrame([flow_features])
        else:
            df = pd.DataFrame(flow_features)
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        df = df[self.feature_columns].fillna(0)
        return df

    @performance_monitor
    @cache_result(ttl=10)
    def detect_ddos(self, flow_features):
        try:
            df = self.preprocess_features(flow_features)
            X = df.values.astype(np.float32)
            X_scaled = self.scaler.transform(X)
            proba = self.model.predict_proba(X_scaled)[0]
            pred = int(self.model.predict(X_scaled)[0])
            confidence = float(max(proba))
            prediction = "ddos" if pred == 1 else "normal"
            threat = "HIGH" if confidence > 0.85 else "MEDIUM" if confidence > 0.6 else "LOW"

            return {
                "prediction": prediction,
                "confidence": round(confidence, 4),
                "threat_level": threat,
                "timestamp": datetime.now().isoformat(),
                "model_version": "3.0.0"
            }
        except Exception as e:
            self.logger.error(f"Detection error: {e}")
            return {
                "prediction": "unknown",
                "confidence": 0.0,
                "threat_level": "UNKNOWN",
                "error": str(e)
            }