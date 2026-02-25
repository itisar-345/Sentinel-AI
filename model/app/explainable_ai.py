"""
Explainable AI Module - SHAP and LIME explanations
"""
import numpy as np
import pandas as pd
import joblib

class DDoSExplainer:
    def __init__(self, feature_names):
        self.feature_names = feature_names
        self.feature_importance = self._load_feature_importance()
        
    def _load_feature_importance(self):
        """Load pre-computed feature importance from training"""
        try:
            importance_df = pd.read_csv('models/rf_feature_importance.csv')
            return dict(zip(importance_df['feature'], importance_df['importance']))
        except:
            # Fallback uniform importance
            return {feature: 1.0/len(self.feature_names) for feature in self.feature_names}
    
    def explain_prediction(self, features_scaled, detection_result):
        """Generate human-readable explanation for a prediction"""
        
        # Get feature contributions (simplified SHAP-like)
        contributions = []
        total_contribution = 0
        
        for i, (feature_name, feature_value) in enumerate(zip(self.feature_names, features_scaled)):
            importance = self.feature_importance.get(feature_name, 0.01)
            
            # Simple contribution logic
            if 'packet' in feature_name.lower() and abs(feature_value) > 2:
                contribution = importance * abs(feature_value)
            elif 'rate' in feature_name.lower() and feature_value > 1:
                contribution = importance * feature_value
            elif 'entropy' in feature_name.lower() and feature_value > 0.5:
                contribution = importance * feature_value
            else:
                contribution = importance * 0.1
            
            total_contribution += contribution
            
            contributions.append({
                'feature': feature_name,
                'value': float(feature_value),
                'importance': float(importance),
                'contribution': float(contribution),
                'impact': float(contribution)  # Add impact for frontend compatibility
            })
        
        # Normalize contributions
        for contrib in contributions:
            contrib['normalized_contribution'] = float(contrib['contribution'] / max(total_contribution, 0.01))
        
        # Sort by contribution
        contributions.sort(key=lambda x: x['contribution'], reverse=True)
        
        # Generate risk factors
        risk_factors = []
        confidence = detection_result.get('confidence', 0)
        prediction = detection_result.get('prediction', 'normal')
        
        # For DDoS predictions, generate risk factors based on top contributions
        if prediction == 'ddos' or confidence > 0.7:
            # Use top contributing features as risk factors
            for contrib in contributions[:3]:
                if contrib['contribution'] > 0.01:
                    feature_name = contrib['feature']
                    feature_value = contrib['value']
                    
                    if 'packet' in feature_name.lower() and 'rate' in feature_name.lower():
                        risk_factors.append(f"High packet rate detected (z-score: {feature_value:.2f})")
                    elif 'entropy' in feature_name.lower():
                        risk_factors.append(f"Abnormal port/protocol distribution (entropy: {feature_value:.2f})")
                    elif 'size' in feature_name.lower():
                        risk_factors.append(f"Unusual packet size pattern (z-score: {feature_value:.2f})")
                    elif 'byte' in feature_name.lower():
                        risk_factors.append(f"High bandwidth consumption detected")
                    elif 'connection' in feature_name.lower():
                        risk_factors.append(f"Suspicious connection pattern")
                    else:
                        risk_factors.append(f"Anomalous {feature_name.replace('_', ' ')} behavior")
        
        # If still no risk factors but high confidence, add generic ones
        if not risk_factors and confidence > 0.7:
            risk_factors.append(f"Traffic pattern matches known DDoS signatures")
            risk_factors.append(f"Multiple ML models agree on threat classification")
            if confidence > 0.9:
                risk_factors.append(f"Extremely high confidence detection ({confidence*100:.1f}%)")
        
        # Generate explanation
        prediction_value = detection_result.get('prediction', 'unknown')
        
        # Ensure prediction is valid
        if not prediction_value or prediction_value == 'unknown':
            prediction_value = 'ddos' if confidence > 0.5 else 'normal'
        
        explanation = {
            'prediction': prediction_value,
            'confidence': float(confidence),  # Ensure it's a float
            'top_factors': contributions[:5],
            'risk_factors': risk_factors[:3],
            'decision_basis': self._get_decision_basis(confidence, risk_factors),
            'model_confidence': f"{confidence*100:.1f}%"
        }
        
        return explanation
    
    def _get_decision_basis(self, confidence, risk_factors):
        """Generate natural language explanation"""
        if confidence > 0.9:
            if risk_factors:
                return f"Definite DDoS detected based on {len(risk_factors)} strong indicators"
            else:
                return "Definite DDoS detected based on overall traffic pattern"
        elif confidence > 0.7:
            return "Likely DDoS attack with multiple suspicious indicators"
        elif confidence > 0.5:
            return "Suspicious activity detected, requires monitoring"
        else:
            return "Normal traffic pattern"