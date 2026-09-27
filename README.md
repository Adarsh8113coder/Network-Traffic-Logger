# Network Traffic Logger

A Python tool that captures live network packets and logs key details 
(timestamps, IPs, protocols, ports, packet size) to CSV — a code-level, 
programmatic version of what Wireshark shows visually.

## How It Works

1. Uses `scapy` to sniff live network traffic in real time
2. For each captured packet, extracts:
   - Timestamp
   - Source and destination IP
   - Protocol (TCP, UDP, ICMP)
   - Source and destination port (for TCP/UDP)
   - Packet size in bytes
3. Prints a live one-line summary to the terminal as packets arrive
4. Appends every packet's details as a row in `traffic_log.csv` for 
   later analysis

## Features

- Real-time packet capture and logging
- CSV output for easy analysis in Excel, pandas, or other tools
- Protocol identification (TCP/UDP/ICMP)
- Configurable packet count (capture a fixed number or run until stopped)
- Graceful handling of permission errors and manual interruption (Ctrl+C)

## Requirements

- Python 3
- [scapy](https://scapy.net/) (`pip install scapy`)
- **Windows only:** [Npcap](https://npcap.com/) driver installed 
  (with WinPcap API-compatible mode enabled)
- Administrator/root privileges (required for packet capture)

## Usage

Run as Administrator (Windows) or with `sudo` (Linux/Mac):

```bash
python network_traffic_logger.py
```

You'll be prompted for how many packets to capture (leave blank for 
unlimited, stop anytime with Ctrl+C).

## Example Output

**Terminal (live view):**

**traffic_log.csv:**
| timestamp | src_ip | dst_ip | protocol | src_port | dst_port | size_bytes |
|---|---|---|---|---|---|---|
| 2026-09-27 14:32:01 | 192.168.1.10 | 142.250.x.x | TCP | 51322 | 443 | 66 |

## Why This Matters

Packet-level visibility is foundational to network security work — it's 
how anomalies, scans, and suspicious traffic patterns get detected in 
real environments. This project builds the same skill Wireshark teaches, 
but through code, which deepens understanding of what's actually 
happening at the protocol level.

## Ethical Use

**Only run this on networks and machines you own or have explicit 
permission to monitor.** Capturing traffic on networks you don't control 
without authorization is illegal in most jurisdictions.

## What I Learned

- Live packet capture using `scapy`
- Working with the `IP`, `TCP`, `UDP`, and `ICMP` protocol layers
- Structuring real-time data into CSV for later analysis
- Practical application of concepts from Wireshark study (protocols, 
  ports, packet structure)

## Tech Stack

- Python 3
- `scapy`
- `csv`
- `datetime`
