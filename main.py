#!/usr/bin/env python3
"""
Main entry point for the Intrusion Detection System (IDS).

This script initializes and runs the IDS with both signature-based and 
anomaly-based detection methods.
"""

import argparse
import sys
from ids.core.ids_engine import IDSEngine


def main():
    parser = argparse.ArgumentParser(description='Python-based Intrusion Detection System')
    parser.add_argument('--mode', choices=['live', 'file'], default='live',
                        help='Monitoring mode: live traffic or from PCAP file')
    parser.add_argument('--interface', '-i', default=None,
                        help='Network interface to monitor (default: all)')
    parser.add_argument('--pcap-file', '-f', default=None,
                        help='PCAP file to analyze in file mode')
    parser.add_argument('--duration', '-d', type=int, default=60,
                        help='Duration to monitor in seconds (default: 60)')
    
    args = parser.parse_args()
    
    # Initialize IDS engine
    ids_engine = IDSEngine()
    
    try:
        if args.mode == 'live':
            print(f"Starting IDS in live mode on interface: {args.interface or 'all'}")
            ids_engine.start_live_monitoring(interface=args.interface, duration=args.duration)
        elif args.mode == 'file':
            if not args.pcap_file:
                print("Error: PCAP file required in file mode")
                sys.exit(1)
            print(f"Analyzing PCAP file: {args.pcap_file}")
            ids_engine.analyze_pcap_file(args.pcap_file)
            
    except KeyboardInterrupt:
        print("\nStopping IDS...")
    except Exception as e:
        print(f"Error running IDS: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()