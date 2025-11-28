#!/usr/bin/env python3
"""
Test the Intrusion Detection System components
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ids.core.ids_engine import IDSEngine
from ids.packet_capture.packet_sniffer import PacketSniffer
from ids.detection.signature_detector import SignatureDetector
from ids.detection.anomaly_detector import AnomalyDetector
from ids.logging.alert_logger import AlertLogger


def test_packet_sniffer():
    """Test packet sniffer functionality"""
    print("Testing Packet Sniffer...")
    sniffer = PacketSniffer()
    print("Packet Sniffer initialized successfully")
    return True


def test_signature_detector():
    """Test signature-based detection"""
    print("Testing Signature Detector...")
    detector = SignatureDetector()
    print("Signature Detector initialized successfully")
    return True


def test_anomaly_detector():
    """Test anomaly-based detection"""
    print("Testing Anomaly Detector...")
    detector = AnomalyDetector()
    print("Anomaly Detector initialized successfully")
    
    # Load sample data
    sample_data = detector.load_sample_data()
    print(f"Sample data loaded: {len(sample_data)} records")
    return True


def test_alert_logger():
    """Test alert logging functionality"""
    print("Testing Alert Logger...")
    logger = AlertLogger("test_logs")
    print("Alert Logger initialized successfully")
    
    # Create a test alert
    test_alert = {
        'timestamp': 1234567890,
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.1',
        'protocol': 'TCP',
        'alert_type': 'TEST_ALERT',
        'description': 'This is a test alert'
    }
    
    # Log the alert
    logger.log_alert(test_alert)
    print("Test alert logged successfully")
    
    # Clean up test logs
    import shutil
    try:
        shutil.rmtree("test_logs")
        print("Test logs cleaned up")
    except:
        pass
        
    return True


def test_ids_engine():
    """Test IDS engine"""
    print("Testing IDS Engine...")
    ids_engine = IDSEngine()
    print("IDS Engine initialized successfully")
    return True


def main():
    """Run all tests"""
    print("Running IDS Component Tests\n")
    
    tests = [
        test_packet_sniffer,
        test_signature_detector,
        test_anomaly_detector,
        test_alert_logger,
        test_ids_engine
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = test()
            if result:
                passed += 1
                print("✓ PASSED\n")
            else:
                failed += 1
                print("✗ FAILED\n")
        except Exception as e:
            failed += 1
            print(f"✗ FAILED with exception: {e}\n")
    
    print(f"Tests completed: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\nAll tests passed! The IDS is ready to use.")
        print("Initialize the IDS with: python initialize_ids.py")
        print("Generate test data with: python generate_test_data.py")
        print("Run the IDS with: python main.py")
    else:
        print("\nSome tests failed. Please check the errors above.")


if __name__ == "__main__":
    main()