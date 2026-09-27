#!/usr/bin/env python3
"""
Network Traffic Logger
-------------------------
Captures live network packets and logs key details: timestamp, source/
destination IP, protocol, ports, and packet size. This is a simplified,
code-level version of what Wireshark does visually — useful for building
real intuition about what's actually happening at the packet level.

Requires: scapy (pip install scapy)

IMPORTANT: Run this only on networks/machines you own or have explicit
permission to monitor. Capturing traffic on networks you don't control
or don't have permission for is illegal in most places.

Usage (Windows/Linux, needs admin/root privileges to capture packets):
    python network_traffic_logger.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
import os

LOG_FILE = "traffic_log.csv"


def init_log_file():
    """Create the CSV log file with headers if it doesn't already exist."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "src_ip", "dst_ip", "protocol",
                "src_port", "dst_port", "size_bytes"
            ])


def get_protocol_name(packet):
    """Identify the protocol of a packet in human-readable form."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def log_packet(packet):
    """
    Called automatically for every captured packet.
    Extracts key fields and appends a row to the CSV log, plus prints
    a live summary to the terminal.
    """
    if not packet.haslayer(IP):
        return  # skip non-IP packets (e.g. ARP) for this simple logger

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = get_protocol_name(packet)
    size = len(packet)

    src_port = ""
    dst_port = ""
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Print a live one-line summary, similar to Wireshark's packet list
    print(f"{timestamp} | {protocol:<5} | {src_ip}:{src_port} -> "
          f"{dst_ip}:{dst_port} | {size} bytes")

    # Append to CSV log for later analysis
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, protocol,
                          src_port, dst_port, size])


def main():
    print("=" * 60)
    print("NETWORK TRAFFIC LOGGER")
    print("=" * 60)
    print(f"Logging to: {LOG_FILE}")
    print("Press Ctrl+C to stop capturing.\n")

    init_log_file()

    count_input = input("How many packets to capture? (blank = unlimited): ").strip()
    packet_count = int(count_input) if count_input else 0  # 0 = infinite in scapy

    try:
        sniff(prn=log_packet, count=packet_count, store=False)
    except KeyboardInterrupt:
        print("\n\nCapture stopped by user.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Run this script as Administrator "
              "(Windows) or with sudo (Linux/Mac) — packet capture requires "
              "elevated privileges.")

    print(f"\nDone. Full log saved to {LOG_FILE}")


if __name__ == "__main__":
    main()
