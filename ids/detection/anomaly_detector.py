"""
Anomaly-based Detector - Uses machine learning to detect unusual network behavior
"""

import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not available. Anomaly detection disabled.")

from ids.packet_capture.packet_sniffer import PacketSniffer


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.trained = False
        self.feature_data = []
        
        if SKLEARN_AVAILABLE:
            # Initialize the Isolation Forest model for anomaly detection
            self.model = IsolationForest(contamination=0.1, random_state=42)
            
    def detect(self, packet):
        """
        Detect anomalies in network traffic
        
        Args:
            packet: Scapy packet object
            
        Returns:
            list: List of alert dictionaries for anomalies detected
        """
        if not SKLEARN_AVAILABLE or not self.trained:
            return []
            
        # Extract features from packet
        features = self._extract_features(packet)
        if features is None:
            return []
            
        # Add to feature data for future training updates
        self.feature_data.append(features)
        
        # Scale features
        features_scaled = self.scaler.transform([features])
        
        # Predict anomaly
        prediction = self.model.predict(features_scaled)
        
        # If anomaly detected (-1), create alert
        if prediction[0] == -1:
            packet_info = PacketSniffer.extract_packet_info(packet)
            return [{
                'timestamp': packet_info.get('timestamp'),
                'src_ip': packet_info.get('src_ip'),
                'dst_ip': packet_info.get('dst_ip'),
                'protocol': packet_info.get('protocol'),
                'alert_type': 'ANOMALY',
                'description': 'Anomalous network traffic detected'
            }]
            
        return []
        
    def train_model(self, training_data):
        """
        Train the anomaly detection model with normal traffic data
        
        Args:
            training_data (list): List of feature vectors from normal traffic
        """
        if not SKLEARN_AVAILABLE:
            print("scikit-learn not available. Cannot train model.")
            return
            
        if len(training_data) == 0:
            print("No training data provided.")
            return
            
        # Convert to numpy array
        X = np.array(training_data)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train the model
        self.model.fit(X_scaled)
        self.trained = True
        print("Anomaly detection model trained successfully.")
        
    def _extract_features(self, packet):
        """
        Extract numerical features from a packet for ML model
        
        Args:
            packet: Scapy packet object
            
        Returns:
            list: Feature vector or None if features cannot be extracted
        """
        packet_info = PacketSniffer.extract_packet_info(packet)
        
        # Extract features for anomaly detection
        features = []
        
        # Packet size feature (assuming we can get it from raw packet)
        try:
            packet_size = len(packet)
            features.append(packet_size)
        except:
            features.append(0)
            
        # Source port (if available)
        src_port = packet_info.get('src_port')
        if src_port:
            features.append(src_port)
        else:
            features.append(0)
            
        # Destination port (if available)
        dst_port = packet_info.get('dst_port')
        if dst_port:
            features.append(dst_port)
        else:
            features.append(0)
            
        # Protocol as numeric (simplified)
        protocol = packet_info.get('protocol')
        if protocol == 'TCP':
            features.append(1)
        elif protocol == 'UDP':
            features.append(2)
        else:
            features.append(0)
            
        return features if len(features) > 0 else None
        
    def load_sample_data(self):
        """
        Load sample training data for demonstration purposes
        """
        # Generate some sample "normal" network traffic data
        # In a real scenario, this would come from actual network traffic
        sample_data = [
            [100, 80, 12345, 1],    # Small TCP packet
            [1500, 443, 56789, 1],  # Typical HTTPS packet
            [64, 53, 12345, 2],     # DNS query
            [800, 22, 12345, 1],    # SSH packet
            [1400, 80, 12345, 1],   # HTTP packet
            [100, 80, 54321, 1],    # Another small TCP packet
            [1500, 443, 98765, 1],  # Another HTTPS packet
            [64, 53, 54321, 2],     # Another DNS query
            [800, 22, 54321, 1],    # Another SSH packet
            [1400, 80, 98765, 1],   # Another HTTP packet
        ]
        
        self.train_model(sample_data)
        return sample_data