"""
Signature-based Detector - Detects known attack patterns
"""

import time
from collections import defaultdict
from ids.packet_capture.packet_sniffer import PacketSniffer


class SignatureDetector:
    def __init__(self):
        # Track connections for port scan detection
        self.connection_attempts = defaultdict(list)
        self.port_scan_threshold = 10  # Ports in 1 minute
        self.port_scan_time_window = 60  # Seconds
        
        # Track failed login attempts for brute force detection
        self.failed_logins = defaultdict(list)
        self.brute_force_threshold = 5  # Failed attempts
        self.brute_force_time_window = 60  # Seconds
        
    def detect(self, packet):
        """
        Detect signature-based threats in a packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            list: List of alert dictionaries
        """
        alerts = []
        
        # Extract packet info
        packet_info = PacketSniffer.extract_packet_info(packet)
        
        # Check for various attack signatures
        port_scan_alert = self._detect_port_scan(packet_info)
        if port_scan_alert:
            alerts.append(port_scan_alert)
            
        dos_alert = self._detect_dos(packet_info)
        if dos_alert:
            alerts.append(dos_alert)
            
        # Add more signature-based detections here
        # ...
        
        return alerts
        
    def _detect_port_scan(self, packet_info):
        """
        Detect potential port scanning activity
        
        Args:
            packet_info (dict): Packet information
            
        Returns:
            dict or None: Alert dictionary if port scan detected
        """
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        timestamp = packet_info.get('timestamp')
        
        if not src_ip or not dst_port or not timestamp:
            return None
            
        # Convert timestamp to float if it's not already
        if not isinstance(timestamp, (float, int)):
            try:
                timestamp = float(timestamp)
            except:
                return None
            
        # Record connection attempt
        self.connection_attempts[src_ip].append({
            'port': dst_port,
            'timestamp': timestamp
        })
        
        # Clean old entries outside time window
        cutoff_time = timestamp - self.port_scan_time_window
        self.connection_attempts[src_ip] = [
            attempt for attempt in self.connection_attempts[src_ip]
            if attempt['timestamp'] > cutoff_time
        ]
        
        # Check if threshold exceeded
        if len(self.connection_attempts[src_ip]) >= self.port_scan_threshold:
            # Get unique ports targeted
            unique_ports = set(attempt['port'] for attempt in self.connection_attempts[src_ip])
            if len(unique_ports) >= self.port_scan_threshold:
                return {
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': packet_info.get('dst_ip'),
                    'protocol': packet_info.get('protocol'),
                    'alert_type': 'PORT_SCAN',
                    'description': f'Potential port scan detected from {src_ip} targeting {len(unique_ports)} ports'
                }
                
        return None
        
    def _detect_dos(self, packet_info):
        """
        Detect potential DoS activity (simplified)
        
        Args:
            packet_info (dict): Packet information
            
        Returns:
            dict or None: Alert dictionary if DoS detected
        """
        # This is a simplified DoS detection
        # In a real implementation, this would be more complex
        return None
        
    def _detect_brute_force(self, packet_info):
        """
        Detect potential brute force attacks (placeholder)
        
        Args:
            packet_info (dict): Packet information
            
        Returns:
            dict or None: Alert dictionary if brute force detected
        """
        # Implementation would depend on specific protocols
        # This is a placeholder for SSH/FTP/HTTP brute force detection
        return None