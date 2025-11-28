#!/usr/bin/env python3
"""
Initialize the Intrusion Detection System with sample data
"""

from ids.detection.anomaly_detector import AnomalyDetector


def main():
    """Initialize the IDS with sample training data"""
    print("Initializing IDS with sample training data...")
    
    # Create anomaly detector
    anomaly_detector = AnomalyDetector()
    
    # Load sample data to train the model
    sample_data = anomaly_detector.load_sample_data()
    
    print(f"Loaded {len(sample_data)} sample data points for training.")
    print("IDS initialization complete!")
    print("\nYou can now run the IDS with:")
    print("  python main.py")


if __name__ == "__main__":
    main()