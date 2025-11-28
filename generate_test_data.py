#!/usr/bin/env python3
"""
Generate test data for the Intrusion Detection System
"""

import random
import numpy as np
try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Cannot generate test PCAP files.")


def generate_normal_traffic(count=100):
    """Generate normal network traffic"""
    if not SCAPY_AVAILABLE:
        return []
        
    packets = []
    
    # Common ports for normal traffic
    common_ports = [80, 443, 22, 53, 25, 110, 143, 993, 995]
    
    for i in range(count):
        # Randomly choose protocol
        protocol = random.choice(['tcp', 'udp'])
        
        # Random IPs
        src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        dst_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Random ports
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(common_ports)
        
        # Create packet
        if protocol == 'tcp':
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
        else:
            packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
            
        # Add some payload
        payload = "Normal traffic data packet " + str(i)
        packet = packet / Raw(load=payload)
        
        packets.append(packet)
        
    return packets


def generate_port_scan_traffic(count=50):
    """Generate port scanning traffic"""
    if not SCAPY_AVAILABLE:
        return []
        
    packets = []
    
    scanner_ip = "10.0.0.100"  # Attacker IP
    
    for i in range(count):
        # Target IP
        dst_ip = f"192.168.1.{random.randint(1, 254)}"
        
        # Scan different ports
        dst_port = random.randint(1, 65535)
        
        # Create TCP SYN packet (typical port scan)
        packet = IP(src=scanner_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S")
        packet = packet / Raw(load="Port scan packet")
        
        packets.append(packet)
        
    return packets


def generate_mixed_traffic():
    """Generate a mix of normal and malicious traffic"""
    if not SCAPY_AVAILABLE:
        return []
        
    # 80% normal traffic, 20% port scan
    normal_packets = generate_normal_traffic(80)
    malicious_packets = generate_port_scan_traffic(20)
    
    # Combine and shuffle
    all_packets = normal_packets + malicious_packets
    random.shuffle(all_packets)
    
    return all_packets


def save_pcap_file(packets, filename):
    """Save packets to a PCAP file"""
    if not SCAPY_AVAILABLE:
        print("Scapy not available. Cannot save PCAP file.")
        return
        
    try:
        wrpcap(filename, packets)
        print(f"Saved {len(packets)} packets to {filename}")
    except Exception as e:
        print(f"Error saving PCAP file: {e}")


def main():
    """Generate test datasets"""
    print("Generating test data for IDS...")
    
    if not SCAPY_AVAILABLE:
        print("Scapy is required to generate test data. Please install it with: pip install scapy")
        return
    
    # Generate normal traffic
    normal_packets = generate_normal_traffic(100)
    save_pcap_file(normal_packets, "normal_traffic.pcap")
    
    # Generate port scan traffic
    port_scan_packets = generate_port_scan_traffic(50)
    save_pcap_file(port_scan_packets, "port_scan_traffic.pcap")
    
    # Generate mixed traffic
    mixed_packets = generate_mixed_traffic()
    save_pcap_file(mixed_packets, "mixed_traffic.pcap")
    
    print("Test data generation complete!")


if __name__ == "__main__":
    main()