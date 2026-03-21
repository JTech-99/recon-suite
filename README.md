# ReconSuite 🔍

A network reconnaissance and vulnerability scanner built in Python.
Automatically discovers live hosts, scans open ports, fingerprints 
services and looks up real CVEs from the NIST NVD database.

## Features
- Host discovery using ARP (Scapy)
- TCP port scanning
- Service banner grabbing and fingerprinting
- Automatic CVE lookup via NIST NVD API
- JSON report generation with timestamps

## Usage
```bash
# Scan a single target
sudo python3 main.py --target 192.168.221.129

# Scan an entire subnet
sudo python3 main.py --subnet 192.168.221.0/24
```

## Example Output
- 10 open ports discovered on Metasploitable2
- CVE-2011-2523 (Score 9.8 CRITICAL) found on vsftpd 2.3.4
- Reports saved automatically to reports/ folder

## Legal Warning
Only use this tool on networks and systems you own or have 
explicit permission to test. Unauthorized scanning is illegal.

## Tools Used
- Python 3
- Scapy
- Requests
- Jinja2
- NIST NVD API