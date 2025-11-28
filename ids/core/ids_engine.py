"""
IDS Engine - Main orchestrator for the Intrusion Detection System
"""

import time
import threading
from ids.packet_capture.packet_sniffer import PacketSniffer
from ids.detection.signature_detector import SignatureDetector
from ids.detection.anomaly_detector import AnomalyDetector
from ids.logging.alert_logger import AlertLogger


class IDSEngine:
    def __init__(self):
        self.packet_sniffer = PacketSniffer()
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.alert_logger = AlertLogger()
        self.is_running = False
        
    def start_live_monitoring(self, interface=None, duration=60):
        """Start live traffic monitoring"""
        self.is_running = True
        
        # Start packet sniffer in a separate thread
        sniffer_thread = threading.Thread(
            target=self._sniff_packets, 
            args=(interface,)
        )
        sniffer_thread.daemon = True
        sniffer_thread.start()
        
        # Monitor for specified duration
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < duration:
            time.sleep(1)
            
        self.stop_monitoring()
        
    def _sniff_packets(self, interface=None):
        """Internal method to sniff packets"""
        def packet_handler(packet):
            if not self.is_running:
                return
                
            # Process packet with signature-based detection
            signature_alerts = self.signature_detector.detect(packet)
            for alert in signature_alerts:
                self.alert_logger.log_alert(alert)
                
            # Process packet with anomaly-based detection
            anomaly_alerts = self.anomaly_detector.detect(packet)
            for alert in anomaly_alerts:
                self.alert_logger.log_alert(alert)
                
        self.packet_sniffer.sniff(interface=interface, packet_handler=packet_handler)
        
    def analyze_pcap_file(self, pcap_file):
        """Analyze packets from a PCAP file"""
        packets = self.packet_sniffer.read_pcap(pcap_file)
        
        for packet in packets:
            # Process packet with signature-based detection
            signature_alerts = self.signature_detector.detect(packet)
            for alert in signature_alerts:
                self.alert_logger.log_alert(alert)
                
            # Process packet with anomaly-based detection
            anomaly_alerts = self.anomaly_detector.detect(packet)
            for alert in anomaly_alerts:
                self.alert_logger.log_alert(alert)
                
        print(f"Analysis complete. Found {self.alert_logger.get_alert_count()} alerts.")
        self.alert_logger.display_recent_alerts()
        
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.is_running = False
        self.packet_sniffer.stop()
        print("Monitoring stopped.")