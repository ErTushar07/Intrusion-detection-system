"""
Packet Sniffer - Handles network packet capture using Scapy
"""

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Live packet capture disabled.")


class PacketSniffer:
    def __init__(self):
        self.sniffing = False
        
    def sniff(self, interface=None, packet_handler=None, count=0):
        """
        Start sniffing network packets
        
        Args:
            interface (str): Network interface to sniff on
            packet_handler (function): Function to handle captured packets
            count (int): Number of packets to capture (0 = infinite)
        """
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot sniff packets.")
            return
            
        self.sniffing = True
        try:
            sniff(iface=interface, prn=packet_handler, count=count, stop_filter=self._should_stop)
        except PermissionError:
            print("Permission denied. Try running with elevated privileges.")
        except Exception as e:
            print(f"Error while sniffing: {e}")
            
    def read_pcap(self, pcap_file):
        """
        Read packets from a PCAP file
        
        Args:
            pcap_file (str): Path to the PCAP file
            
        Returns:
            list: List of packets
        """
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot read PCAP file.")
            return []
            
        try:
            packets = rdpcap(pcap_file)
            return packets
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return []
            
    def stop(self):
        """Stop packet sniffing"""
        self.sniffing = False
        
    def _should_stop(self, packet):
        """Check if sniffing should stop"""
        return not self.sniffing
        
    @staticmethod
    def extract_packet_info(packet):
        """
        Extract basic information from a packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Dictionary containing packet information
        """
        if not SCAPY_AVAILABLE:
            return {}
            
        info = {
            'timestamp': packet.time,
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'src_port': None,
            'dst_port': None
        }
        
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto
            
        if TCP in packet:
            info['protocol'] = 'TCP'
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
        elif UDP in packet:
            info['protocol'] = 'UDP'
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
            
        return info