# PCAP Traffic Analyser (SOC-style)

Simple Python-based network traffic analyser for PCAP files.  
Designed as a mini SOC / SIEM-style pipeline.

## Features
- PCAP → CSV preprocessing via tshark
- Normalized packet parsing
- Detection of insecure protocols (HTTP, FTP, TELNET, etc.)
- High traffic volume detection
- Risk scoring
- JSON report output (SIEM-friendly)

## Project Structure
traffic_analyser/
├─ analyser/
├─ data/
├─ README.md

## Requirements
- Python 3.10+
- Wireshark (tshark must be installed and accessible)

## Usage

1. Place a PCAP file into `data/traffic.pcap`
2. Run analyser:

```bash
python analyser/main.py

## Notes
PCAP / CSV files are excluded from git
Designed for SOC / DFIR learning and portfolio use
Easily extensible for new detections

**## Update 07/02/2026**
Add port scan detections using TShark dst ports
