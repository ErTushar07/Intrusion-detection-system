"""
Alert Logger - Handles logging of security alerts to files and console
"""

import json
import csv
import os
import time
from datetime import datetime


class AlertLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.alerts = []
        
        # Create log directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
    def log_alert(self, alert):
        """
        Log an alert to both console and file
        
        Args:
            alert (dict): Alert information
        """
        # Add to internal alert list
        self.alerts.append(alert)
        
        # Print to console
        self._print_alert(alert)
        
        # Save to files
        self._save_to_json(alert)
        self._save_to_csv(alert)
        
    def _print_alert(self, alert):
        """Print alert to console"""
        # Handle different timestamp formats
        timestamp = alert['timestamp']
        if isinstance(timestamp, (float, int)):
            formatted_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        else:
            # If it's already a string or other format, convert to float first
            try:
                formatted_time = datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
            except:
                formatted_time = str(timestamp)
                
        print(f"[{formatted_time}] ALERT: {alert['alert_type']} - {alert['description']}")
        print(f"  Source: {alert.get('src_ip', 'N/A')} -> Destination: {alert.get('dst_ip', 'N/A')}")
        print(f"  Protocol: {alert.get('protocol', 'N/A')}")
        print("-" * 50)
        
    def _save_to_json(self, alert):
        """Save alert to JSON file"""
        try:
            # Handle timestamp conversion for JSON serialization
            alert_copy = alert.copy()
            timestamp = alert_copy['timestamp']
            if isinstance(timestamp, (float, int)):
                alert_copy['timestamp'] = datetime.fromtimestamp(timestamp).isoformat()
            else:
                # If it's already a string or other format, try to convert
                try:
                    alert_copy['timestamp'] = datetime.fromtimestamp(float(timestamp)).isoformat()
                except:
                    alert_copy['timestamp'] = str(timestamp)
            
            filename = os.path.join(self.log_dir, "alerts.json")
            # If file exists, read existing data
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = []
            else:
                data = []
                
            # Append new alert
            data.append(alert_copy)
            
            # Write back to file
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving alert to JSON: {e}")
            
    def _save_to_csv(self, alert):
        """Save alert to CSV file"""
        try:
            filename = os.path.join(self.log_dir, "alerts.csv")
            file_exists = os.path.exists(filename)
            
            # Handle timestamp conversion for CSV
            timestamp = alert['timestamp']
            if isinstance(timestamp, (float, int)):
                formatted_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            else:
                # If it's already a string or other format, try to convert
                try:
                    formatted_time = datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    formatted_time = str(timestamp)
            
            with open(filename, 'a', newline='') as f:
                writer = csv.writer(f)
                
                # Write header if file is new
                if not file_exists:
                    writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'protocol', 'alert_type', 'description'])
                    
                # Write alert data
                writer.writerow([
                    formatted_time,
                    alert.get('src_ip', ''),
                    alert.get('dst_ip', ''),
                    alert.get('protocol', ''),
                    alert['alert_type'],
                    alert['description']
                ])
        except Exception as e:
            print(f"Error saving alert to CSV: {e}")
            
    def display_recent_alerts(self, count=10):
        """Display the most recent alerts"""
        recent_alerts = self.alerts[-count:] if len(self.alerts) > count else self.alerts
        
        print(f"\nRecent Alerts (last {len(recent_alerts)}):")
        print("=" * 50)
        
        for alert in reversed(recent_alerts):
            self._print_alert(alert)
            
    def get_alert_count(self):
        """Get the total number of alerts logged"""
        return len(self.alerts)
        
    def clear_alerts(self):
        """Clear the alert list"""
        self.alerts.clear()