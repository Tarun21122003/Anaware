import psutil
import socket
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Set
from scapy.all import *
import queue
import threading

class NetworkMonitor:
    def __init__(self):
        self.known_ports = {
            80: "HTTP", 443: "HTTPS", 53: "DNS",
            25: "SMTP", 110: "POP3", 143: "IMAP",
            21: "FTP", 22: "SSH", 3389: "RDP"
        }
        
        self.packet_queue = queue.Queue()
        self.results = {
            "unusual_ports": [],
            "connections": [],
            "protocol_anomalies": []
        }

    def monitor_file(self, file_path: str, duration: int = 60, interface: str = "eth0") -> Dict:
        """Monitor network activity when running/opening a file"""
        try:
            # Start network capture thread
            capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(interface, duration)
            )
            capture_thread.daemon = True
            capture_thread.start()
            
            # Start packet analysis thread
            analysis_thread = threading.Thread(target=self._analyze_packets)
            analysis_thread.daemon = True
            analysis_thread.start()
            
            # Try to open/execute the file
            try:
                os.startfile(file_path)  # Windows
            except AttributeError:
                os.system(f"xdg-open {file_path}")  # Linux
            
            # Wait for monitoring duration
            time.sleep(duration)
            
            return self._generate_report()
            
        except Exception as e:
            return {"error": str(e)}

    def _capture_packets(self, interface: str, duration: int):
        """Capture network packets."""
        def packet_callback(packet):
            self.packet_queue.put(packet)

        try:
            sniff(
                iface=interface,
                prn=packet_callback,
                store=0,
                timeout=duration
            )
        except Exception as e:
            print(f"Error during packet capture: {str(e)}")

    def _analyze_packets(self):
        """Analyze packets from the queue."""
        while True:
            try:
                packet = self.packet_queue.get(timeout=1)
                self._analyze_single_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error analyzing packet: {str(e)}")

    def _analyze_single_packet(self, packet):
        """Analyze a single packet for the three specific indicators."""
        try:
            if IP in packet:
                ip_packet = packet[IP]
                src_ip = ip_packet.src
                dst_ip = ip_packet.dst
                
                connection = {
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "protocol": ip_packet.proto
                }

                # Check for DNS queries
                if DNS in packet:
                    dns = packet[DNS]
                    if dns.qr == 0:  # This is a query
                        connection["type"] = "DNS"
                        if hasattr(dns, "qd") and dns.qd:
                            connection["domain"] = dns.qd.qname.decode()
                
                # Check TCP/UDP ports
                if TCP in packet:
                    tcp = packet[TCP]
                    connection["source_port"] = tcp.sport
                    connection["dest_port"] = tcp.dport
                    if tcp.dport not in self.known_ports:
                        self.results["unusual_ports"].append({
                            "ip": dst_ip,
                            "port": tcp.dport,
                            "protocol": "TCP"
                        })
                elif UDP in packet:
                    udp = packet[UDP]
                    connection["source_port"] = udp.sport
                    connection["dest_port"] = udp.dport
                    if udp.dport not in self.known_ports:
                        self.results["unusual_ports"].append({
                            "ip": dst_ip,
                            "port": udp.dport,
                            "protocol": "UDP"
                        })

                # Check for protocol anomalies
                if ip_packet.proto not in [6, 17, 1]:  # Not TCP, UDP, or ICMP
                    self.results["protocol_anomalies"].append({
                        "timestamp": datetime.now().isoformat(),
                        "protocol_number": ip_packet.proto,
                        "source_ip": src_ip,
                        "dest_ip": dst_ip
                    })

                self.results["connections"].append(connection)

        except Exception as e:
            print(f"Error analyzing packet: {str(e)}")

    def _generate_report(self) -> Dict:
        """Generate the summary report with only the requested information."""
        # Get unique IPs and domains
        unique_ips = set()
        unique_domains = set()
        
        for conn in self.results["connections"]:
            unique_ips.add(conn["dest_ip"])
            if "domain" in conn:
                unique_domains.add(conn["domain"])
        
        return {
            "summary": {
                "unusual_ports_count": len(self.results["unusual_ports"]),
                "unique_ips": list(unique_ips),
                "unique_domains": list(unique_domains),
                "protocol_anomalies_count": len(self.results["protocol_anomalies"])
            }
        }

def save_to_json(data: Dict, filename: str = "NetTraff.json", directory: str = "C:\\scripts\\results"):
    """Save the monitoring results to a JSON file."""
    try:
        # Create directory if it doesn't exist
        os.makedirs(directory, exist_ok=True)
        
        # Construct full file path
        file_path = os.path.join(directory, filename)
        
        # Save to JSON file
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Results saved to {file_path}")
    except Exception as e:
        print(f"Error saving results to JSON: {str(e)}")

def monitor_file(file_path: str, duration: int = 60, interface: str = None) -> Dict:
    """Main function to monitor network traffic while running a file."""
    if interface is None:
        interface = conf.iface
    
    monitor = NetworkMonitor()
    results = monitor.monitor_file(file_path, duration, interface)
    
    # Save results to JSON file
    save_to_json(results)
    
    return results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitor network traffic while running a file')
    parser.add_argument('file_path', help='Path to the file to monitor')
    parser.add_argument('--duration', type=int, default=60, help='Duration to monitor (seconds)')
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--output-dir', default="C:\\scripts\\results", help='Directory to save JSON output')
    
    args = parser.parse_args()
    
    results = monitor_file(args.file_path, args.duration, args.interface)
    
    # Print just the summary information
    summary = results["summary"]
    print("\nMonitoring Summary:")
    print(f"Number of unusual port connections: {summary['unusual_ports_count']}")
    print(f"Unique IPs contacted: {summary['unique_ips']}")
    print(f"Unique domains contacted: {summary['unique_domains']}")
    print(f"Number of protocol anomalies: {summary['protocol_anomalies_count']}")