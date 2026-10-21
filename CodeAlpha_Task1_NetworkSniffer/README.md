# NETWORK SNIFFER
A Python-based network packet sniffer developed as part of the CodeAlpha Cyber Security Internship task 1.

# Overview
This project captures and analyzes authorized IPv4 network traffic using Scapy. It displays packet metadata, identifies common transport protocols, provides a limited hexadecimal payload preview, and generates CSV reports.

# Features
- Capture IPv4 packets on a selected network interface.
- Display source and destination IP addresses.
- Identify TCP, UDP, ICMP, and other IP traffic.
- Display source and destination ports where applicable.
- Show packet sizes and timestamps.
- Inspect up to 16 bytes of raw payload in hexadecimal.
- Filter captures by protocol.
- Generate CSV reports and protocol statistics.
- Stop a capture early with *Ctrl + C*.

# Technologies
- Python 3
- Scapy
- Npcap on Windows
- PowerShell

# Requirements
- Python 3
- Scapy
- Npcap installed on Windows
- Administrator privileges when required for packet capture

# Installation
Clone the repository:
```bash
git clone https://github.com/JoshuaN9/CodeAlpha_TASK1_NetworkSniffer.git
cd CodeAlpha_TASK1_NetworkSniffer
```
# Create and activate a virtual environment in PowerShell:
powershell
python -m venv venv
.\\venv\\Scripts\\Activate.ps1

# Install dependencies:

powershell
python -m pip install -r requirements.txt

# Usage
# Capture up to 100 IP packets
powershell
python sniffer.py

# Capture TCP packets:
powershell
python sniffer.py --protocol TCP --count 100

# Capture UDP packets:
powershell
python sniffer.py --protocol UDP --count 100

# Specify an output report:
powershell
python sniffer.py --protocol TCP --count 100 --output reports/tcp\_test.csv

# Display available options:
powershell
python sniffer.py --help

# Output
The terminal displays packet timestamps, IP addresses, protocol information, ports, packet sizes, and a limited hexadecimal payload preview.
The program also produces a CSV report containing captured packet metadata and a summary of packet counts and total bytes.

# Security and Privacy
Use this tool only on networks and devices you own or have explicit permission to monitor.
Packet captures and payload previews may contain sensitive information. Review and sanitize reports before sharing them publicly.
The tool is intended for educational network analysis and is not a replacement for a production intrusion detection system.

# Internship
Developed for the CodeAlpha Cybersecurity Internship task.

# License
This project is provided for educational purposes.