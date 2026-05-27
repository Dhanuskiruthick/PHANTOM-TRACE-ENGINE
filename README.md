# 🧠 Phantom Trace Engine – Passive Network Intelligence System
<img width="1022" height="698" alt="image" src="https://github.com/user-attachments/assets/d2e88252-e314-4cbf-99e5-90419f6c9dfb" />

A lightweight Python-based network intelligence tool that captures and analyzes real-time packet traffic, performing protocol-level analysis and basic threat detection at the packet layer.

> **What this is:** Not just a packet sniffer. A practical exploration of how real network communication happens, with threat detection capabilities.

---

## 📖 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation & Setup](#installation--setup)
- [How to Run](#how-to-run)
- [Project Structure](#project-structure)
- [What I Learned](#what-i-learned)
- [Future Enhancements](#future-enhancements)

---

## Overview

This project answers a simple question: **What does real network traffic actually look like?**

Most networking courses teach theory—OSI models, TCP handshakes, port numbers. But understanding *why* packets are structured the way they are requires seeing them in action.

**Phantom Trace Engine** captures live packets, parses them layer-by-layer (Ethernet → IP → TCP/UDP), detects suspicious port activity, and logs findings for forensic analysis.

**Key insight:** Networking isn't static diagrams. It's continuous, layered communication between systems.

---

## Features

✅ **Real-time Packet Capture** – Uses Scapy to intercept live traffic  
✅ **Multi-layer Protocol Parsing** – Extracts L2 (Ethernet), L3 (IP), L4 (TCP/UDP), L7 (HTTP)  
✅ **Threat Detection** – Identifies suspicious port activity using IOC-based logic  
✅ **Forensic Logging** – Maintains packet records for analysis  
✅ **Clean Architecture** – Modular design (sniffer → detector → logger)  
✅ **Human-readable Output** – Console output formatted for security analysts  

---

## Architecture

```
                    Network Interface
                          ↓
              Scapy Packet Capture Layer
                          ↓
              Protocol Parsing Engine
                    (L2, L3, L4, L7)
                          ↓
                  Detection Module
              (Suspicious Port Analysis)
                          ↓
                   Logging System
                    (packets.log)
                          ↓
              Console Output & Alerts
```

### Component Breakdown

| Component | Purpose | Key Method |
|-----------|---------|-----------|
| **sniffer.py** | Core packet capture engine | `process_packet()`, `start_sniffer()` |
| **detector.py** | Threat intelligence layer | `detect_suspicious_port()` |
| **logger.py** | Forensic logging system | `log_packet()` |

### Data Flow

```
Live Traffic
    ↓
[process_packet] extracts layers
    ↓
[Ethernet detected?] → Print MAC addresses
[IP detected?] → Print IP addresses
[TCP detected?] → Print ports, flags, check [detect_suspicious_port]
[UDP detected?] → Print ports
[Raw payload?] → Check for HTTP/GET
    ↓
[log_packet] writes to packets.log
    ↓
Console output (analyst-ready)
```

---

## Installation & Setup

### Prerequisites
- Python 3.7+
- Scapy library
- Linux/macOS (packet capture requires elevated privileges)
- Internet connection (to see actual traffic)

### Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/phantom-trace-engine.git
cd phantom-trace-engine
```

### Step 2: Install Dependencies
```bash
pip install scapy
```

Or use requirements.txt:
```bash
pip install -r requirements.txt
```

### Step 3: Verify Scapy Installation
```bash
python3 -c "from scapy.all import sniff; print('✓ Scapy installed')"
```

---

## How to Run

### Basic Execution (Requires Sudo)
```bash
sudo python3 main.py
```

**Why sudo?** Packet capture requires raw socket access (root/administrator privileges).

### What You'll See

```
[*] Phantom Trace Engine is running...

================ PACKET CAPTURED ================

[L2] SRC MAC : 08:00:27:4e:2a:1c
[L2] DST MAC : 52:54:00:12:35:02

[L3] SRC IP  : 192.168.1.100
[L3] DST IP  : 8.8.8.8

[L4] TCP SEGMENT
PORTS  : 54321 -> 443
FLAGS  : S

-------------------------------------------------
```

### Filter Specific Traffic (Optional)
Edit `sniffer.py` line in `start_sniffer()`:
```python
# Capture only TCP traffic to port 80
sniff(filter="tcp port 80", prn=process_packet, store=False)

# Capture UDP traffic
sniff(filter="udp", prn=process_packet, store=False)

# Capture traffic from specific IP
sniff(filter="host 192.168.1.100", prn=process_packet, store=False)
```

---

## Project Structure

```
phantom-trace-engine/
├── sniffer.py          # Core packet capture & parsing
├── detector.py         # Threat detection logic
├── logger.py           # Forensic logging
├── main.py             # Entry point
├── packets.log         # Generated log file
├── requirements.txt    # Dependencies
├── README.md           # This file
└── docs/
    ├── ARCHITECTURE.md # Detailed technical breakdown
    └── SETUP_GUIDE.md  # Troubleshooting & advanced config
```

---

## What I Learned

### Technical Skills
- **Scapy fundamentals** – Building packet capture systems from scratch
- **Protocol analysis** – How Ethernet, IP, TCP, and UDP actually work
- **Layer-based thinking** – Why the OSI model matters in real traffic
- **Detection logic** – Implementing IOC (Indicators of Compromise) checks
- **Logging & forensics** – Recording data for analysis

### Conceptual Breakthroughs
1. **HTTPS hides payload** – Even though we see the packet, encrypted traffic remains opaque
2. **Ports = application identity** – TCP/UDP ports tell you what protocol/service is communicating
3. **Real traffic is noisy** – Every browser tab, OS service, and background app generates packets
4. **TCP flags tell a story** – SYN, ACK, FIN flags reveal connection lifecycle
5. **Detection ≠ Deep Packet Inspection** – Basic port analysis detects threats without decryption

### Security Mindset Lessons
- Why packet capture is foundational to network security
- How IDS/IPS systems think about threat detection
- Why logging matters (forensic analysis requires records)
- The balance between observability and privacy

---

## Suspicious Port Detection

The detector checks for known-dangerous ports associated with malware C2 communication:

```python
suspicious_ports = {4444, 1337, 6666, 31337, 9001}
```

When traffic is detected on these ports, an alert is printed:
```
[ALERT] Suspicious Destination Port Detected!
```

**Note:** This is basic IOC matching. Production systems use more sophisticated analysis (flow analysis, ML models, threat intelligence feeds).

---

## Log Output Example

```
192.168.1.100:54321 -> 8.8.8.8:443 FLAGS=S
192.168.1.100:54322 -> 142.250.1.95:443 FLAGS=SA
192.168.1.100:60001 -> 192.168.1.1:53 FLAGS=None
```

View logs:
```bash
tail -f packets.log
```

---

## Future Enhancements

🔄 **v2.0 Ideas:**
- [ ] Real-time dashboard (using Tkinter/Flask)
- [ ] GeoIP mapping (visualize traffic sources)
- [ ] Flow-based analysis (session grouping)
- [ ] SQL injection detection in HTTP payloads
- [ ] DNS query analysis (domain lookups)
- [ ] Machine learning for anomaly detection
- [ ] Integration with threat intel APIs (VirusTotal, AbuseIPDB)
- [ ] Pcap file export (for Wireshark analysis)

---

## Troubleshooting

### Error: "No permission to sniff on [interface]"
```bash
# Run with sudo
sudo python3 main.py
```

### Error: "No module named scapy"
```bash
pip install scapy
# Or
sudo pip3 install scapy
```

### Capturing no packets?
- Ensure network interface is active
- Try different filter: `sniff(filter="", ...)` (no filter)
- Check firewall isn't blocking interfaces

### OSError: [Errno 24] Too many open files
- Reduce packet capture rate or add `timeout` parameter

---

## Learning Resources

**Understanding this project requires:**
- Basic Python (functions, classes, libraries)
- Network fundamentals (OSI model, TCP/IP)
- Linux command line (sudo, pip, file paths)

**Recommended resources:**
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [TCPDump/Wireshark basics](https://www.wireshark.org/download/)
- Prof. Messer's [Network+ Course](https://www.youtube.com/watch?v=OSIVnG7hWMY) (free)
- [OWASP Protocol Analysis](https://owasp.org/)

---

## License

MIT License – Feel free to use this for learning and portfolio projects.

---

## Author & Contact

**Built by:** Dhanus Kiruthick  
**Year:** 2026
**Institution:** VIT Bhopal University (Cybersecurity Specialization)

**Feedback & Questions:**
- Found a bug? Open an issue.
- Want to extend this? Feel free to fork and submit PRs.
- Learning from this? Drop a star ⭐

---

**Last Updated:** May 2026 
**Status:** Active Learning Project ✓
