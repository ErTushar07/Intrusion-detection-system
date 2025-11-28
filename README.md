# Python-based Intrusion Detection System (IDS)

A comprehensive Intrusion Detection System implemented in Python with both signature-based and anomaly-based detection techniques.

## Features

- **Signature-based Detection**: Detects known attack patterns like port scanning
- **Anomaly-based Detection**: Uses machine learning to identify unusual network behavior
- **Live Traffic Monitoring**: Captures and analyzes real-time network traffic
- **PCAP File Analysis**: Analyzes previously captured network traffic
- **Multiple Alert Formats**: Logs alerts in both CSV and JSON formats
- **Modular Design**: Well-organized codebase with separate modules for each functionality

## Requirements

- Python 3.6+
- Scapy for packet capture and manipulation
- Pandas and NumPy for data analysis
- Scikit-learn for machine learning-based anomaly detection

## Installation

1. Clone or download this repository
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

Run the IDS with different options:

```bash
# Monitor live traffic (requires root/administrator privileges)
python main.py

# Monitor live traffic on a specific interface for 300 seconds
python main.py --interface eth0 --duration 300

# Analyze a PCAP file
python main.py --mode file --pcap-file test_traffic.pcap
```

### Generating Test Data

To generate sample network traffic for testing:

```bash
python generate_test_data.py
```

This creates several PCAP files:
- `normal_traffic.pcap`: Normal network traffic
- `port_scan_traffic.pcap`: Port scanning traffic
- `mixed_traffic.pcap`: Combination of normal and malicious traffic

## Project Structure

```
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── generate_test_data.py   # Test data generator
├── README.md               # This file
├── ids/                    # IDS modules
│   ├── __init__.py
│   ├── core/               # Core IDS engine
│   │   ├── __init__.py
│   │   └── ids_engine.py
│   ├── packet_capture/     # Packet capture functionality
│   │   ├── __init__.py
│   │   └── packet_sniffer.py
│   ├── detection/          # Detection algorithms
│   │   ├── __init__.py
│   │   ├── signature_detector.py
│   │   └── anomaly_detector.py
│   └── logging/            # Alert logging
│       ├── __init__.py
│       └── alert_logger.py
└── logs/                   # Generated alert logs (created at runtime)
```

## Detection Capabilities

### Signature-based Detection
- Port scanning detection
- (Additional signatures can be added)

### Anomaly-based Detection
- Machine learning model using Isolation Forest
- Detects unusual traffic patterns
- Feature extraction from packet headers

## Limitations

1. **Permissions**: Live packet capture requires administrator/root privileges
2. **Performance**: Processing speed depends on hardware and network traffic volume
3. **Detection Coverage**: Current implementation focuses on common attack patterns
4. **Evasion**: Sophisticated attackers may evade detection

## Future Improvements

- Add more signature-based detection rules
- Implement deep packet inspection
- Enhance machine learning models with more features
- Add support for additional protocols
- Implement real-time alerting mechanisms
- Add a web-based dashboard for visualization

## License

This project is for educational purposes. Use responsibly and only on networks you own or have explicit permission to monitor.