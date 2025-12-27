"""
Anomaly Detection Module - ML-based behavioral analysis
Uses Isolation Forest for unsupervised anomaly detection
"""

import numpy as np
import logging
from typing import Dict, List, Tuple
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

logger = logging.getLogger(__name__)


class AnomalyDetectionEngine:
    """ML-based anomaly detection using Isolation Forest"""
    
    def __init__(self, model_path: str = None, contamination: float = 0.1):
        """
        Initialize anomaly detection engine
        
        Args:
            model_path: Path to pre-trained model
            contamination: Expected proportion of anomalies (0.05-0.2)
        """
        self.contamination = contamination
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'packet_size',
            'protocol_type',
            'src_port',
            'dst_port',
            'ttl',
            'window_size',
            'payload_entropy',
            'inter_arrival_time'
        ]
        self.baseline_stats = {}
        
        # Load pre-trained model if available
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)
    
    def extract_features(self, packet_data: Dict) -> np.ndarray:
        """Extract numerical features from packet"""
        try:
            ip_info = packet_data.get('layers', {}).get('ip', {})
            tcp_info = packet_data.get('layers', {}).get('tcp', {})
            udp_info = packet_data.get('layers', {}).get('udp', {})
            
            # Basic features
            packet_size = packet_data.get('size', 64)
            
            # Protocol encoding: IP=1, TCP=2, UDP=3, ICMP=4
            protocol = ip_info.get('protocol', 0)
            protocol_type = 2 if tcp_info else (3 if udp_info else 4)
            
            src_port = tcp_info.get('src_port') or udp_info.get('src_port') or 0
            dst_port = tcp_info.get('dst_port') or udp_info.get('dst_port') or 0
            
            ttl = ip_info.get('ttl', 64)
            window_size = tcp_info.get('window_size', 65535) if tcp_info else 0
            
            # Payload entropy (0-8 for 8-bit values)
            payload = packet_data.get('layers', {}).get('payload', b'')
            payload_entropy = self._calculate_entropy(payload)
            
            # Inter-arrival time (simplified - would track in production)
            inter_arrival_time = 0.001  # Default 1ms
            
            features = np.array([
                packet_size,
                protocol_type,
                min(src_port, 65535),  # Normalize ports
                min(dst_port, 65535),
                ttl,
                window_size,
                payload_entropy,
                inter_arrival_time
            ], dtype=np.float32)
            
            return features
        
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return np.zeros(len(self.feature_names), dtype=np.float32)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of payload"""
        if len(data) == 0:
            return 0.0
        
        # Calculate frequency of each byte value
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        
        # Shannon entropy: -Σ(p * log2(p))
        entropy = -np.sum(probabilities[probabilities > 0] * np.log2(probabilities[probabilities > 0]))
        
        return min(entropy, 8.0)  # Max entropy is 8 for 8-bit values
    
    def train(self, training_packets: List[Dict]) -> Dict:
        """Train the anomaly detection model"""
        logger.info(f"Training anomaly model with {len(training_packets)} packets")
        
        try:
            # Extract features from all packets
            X = np.array([self.extract_features(p) for p in training_packets])
            
            if X.shape[0] < 10:
                logger.warning("Insufficient training data")
                return {'success': False, 'message': 'Need at least 10 samples'}
            
            # Normalize features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
                max_samples='auto'
            )
            self.model.fit(X_scaled)
            
            # Calculate baseline statistics
            self._calculate_baseline_stats(X)
            
            self.is_trained = True
            
            logger.info("Anomaly model training completed")
            return {'success': True, 'samples_trained': X.shape[0]}
        
        except Exception as e:
            logger.error(f"Training error: {e}")
            return {'success': False, 'message': str(e)}
    
    def _calculate_baseline_stats(self, X: np.ndarray):
        """Calculate baseline statistics for anomaly scoring"""
        for i, name in enumerate(self.feature_names):
            self.baseline_stats[name] = {
                'mean': float(np.mean(X[:, i])),
                'std': float(np.std(X[:, i])),
                'min': float(np.min(X[:, i])),
                'max': float(np.max(X[:, i]))
            }
    
    def detect(self, packet_data: Dict) -> Dict:
        """Detect anomaly in single packet"""
        try:
            # Extract features
            features = self.extract_features(packet_data).reshape(1, -1)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            result = {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'deviation': {},
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Statistical deviation (always available)
            result['deviation'] = self._calculate_deviation(features[0])
            
            # ML-based detection (if model is trained)
            if self.is_trained and self.model:
                # Isolation Forest prediction: -1 for anomalies, 1 for normal
                prediction = self.model.predict(features_scaled)[0]
                anomaly_score = self.model.score_samples(features_scaled)[0]
                
                # Convert to 0-100 scale
                anomaly_score_normalized = max(0, min(100, (-anomaly_score * 10)))
                
                result['is_anomaly'] = prediction == -1
                result['anomaly_score'] = float(anomaly_score_normalized)
                result['confidence'] = 0.85 if result['is_anomaly'] else 0.95
            else:
                # Use statistical deviation if no model
                max_deviation = max([d.get('z_score', 0) for d in result['deviation'].values()])
                result['is_anomaly'] = max_deviation > 2.5  # > 2.5 sigma
                result['anomaly_score'] = min(100, max_deviation * 20)
                result['confidence'] = 0.70
            
            return result
        
        except Exception as e:
            logger.error(f"Detection error: {e}")
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _calculate_deviation(self, features: np.ndarray) -> Dict:
        """Calculate statistical deviation from baseline"""
        deviation = {}
        
        for i, name in enumerate(self.feature_names):
            if name in self.baseline_stats:
                stats = self.baseline_stats[name]
                mean = stats['mean']
                std = stats['std']
                
                if std > 0:
                    z_score = (features[i] - mean) / std
                else:
                    z_score = 0
                
                deviation[name] = {
                    'value': float(features[i]),
                    'baseline_mean': mean,
                    'z_score': float(z_score),
                    'is_deviant': abs(z_score) > 2.0
                }
        
        return deviation
    
    def batch_detect(self, packets: List[Dict]) -> List[Dict]:
        """Detect anomalies in batch of packets"""
        results = []
        for packet in packets:
            result = self.detect(packet)
            results.append(result)
        return results
    
    def save_model(self, model_path: str) -> bool:
        """Save trained model to disk"""
        try:
            if self.model and self.is_trained:
                joblib.dump(self.model, model_path)
                logger.info(f"Model saved to {model_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def _load_model(self, model_path: str) -> bool:
        """Load pre-trained model from disk"""
        try:
            self.model = joblib.load(model_path)
            self.is_trained = True
            logger.info(f"Model loaded from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get anomaly detection statistics"""
        return {
            'is_trained': self.is_trained,
            'contamination_rate': self.contamination,
            'feature_count': len(self.feature_names),
            'baseline_available': len(self.baseline_stats) > 0
        }


class StatisticalAnomalyDetector:
    """Complementary statistical anomaly detection without ML"""
    
    def __init__(self):
        self.traffic_history = []
        self.max_history = 1000
        self.baseline_pps = None  # packets per second
    
    def update_traffic_rate(self, packet_count: int, time_window: float = 1.0) -> Dict:
        """Update traffic statistics"""
        pps = packet_count / time_window if time_window > 0 else 0
        self.traffic_history.append(pps)
        
        if len(self.traffic_history) > self.max_history:
            self.traffic_history.pop(0)
        
        # Calculate baseline
        if len(self.traffic_history) > 10:
            self.baseline_pps = np.mean(self.traffic_history[:-10])  # Exclude current
        
        return {
            'current_pps': pps,
            'baseline_pps': self.baseline_pps,
            'is_anomalous': self._check_traffic_anomaly(pps)
        }
    
    def _check_traffic_anomaly(self, current_pps: float) -> bool:
        """Check if current traffic rate is anomalous"""
        if self.baseline_pps is None:
            return False
        
        # Flag if traffic is 3x above baseline or 0.5x below
        ratio = current_pps / self.baseline_pps if self.baseline_pps > 0 else 0
        return ratio > 3.0 or (self.baseline_pps > 100 and ratio < 0.5)
