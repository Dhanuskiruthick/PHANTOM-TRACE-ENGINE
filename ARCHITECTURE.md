# 🏗️ Phantom Trace Engine – Technical Architecture

## System Design & Implementation Details

---

## 1. High-Level System Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     PHANTOM TRACE ENGINE                       │
│                  (Passive Network Intelligence)                │
└──────────────────────────────────────────────────────────────┘
                              │
                              ↓
                    ┌─────────────────┐
                    │ Network Interface│ (eth0, wlan0, etc)
                    └────────┬────────┘
                             │
                             ↓
                    ┌─────────────────┐
                    │  Scapy Library  │ (Low-level packet access)
                    └────────┬────────┘
                             │
                             ↓
        ┌────────────────────────────────────────┐
        │      PACKET PROCESSING ENGINE          │
        │     (process_packet function)          │
        └────────────┬─────────────────────────┘
                     │
        ┌────────────┴────────────────────────┐
        │                                      │
        ↓                                      ↓
    Layer Analysis                    Feature Extraction
    • Ethernet (L2)                   • Protocol Detection
    • IP (L3)                         • Port Analysis
    • TCP/UDP (L4)                    • Payload Inspection
    • HTTP (L7)                       • Flag Analysis
        │                                      │
        └────────────┬─────────────────────┘
                     │
                     ↓
        ┌────────────────────────────────┐
        │   DETECTOR MODULE              │
        │  (detect_suspicious_port)      │
        └────────────┬───────────────────┘
                     │
                     ↓
        ┌────────────────────────────────┐
        │   LOGGER MODULE                │
        │   (log_packet)                 │
        └────────────┬───────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ↓                         ↓
    Console Output          packets.log
    (Real-time alerts)      (Forensic record)
```

---

## 2. Component Architecture

### 2.1 SNIFFER.PY – Core Engine

**Responsibility:** Capture, parse, and display packet information

**Key Functions:**

#### `process_packet(packet)`
- **Input:** Raw packet object from Scapy
- **Output:** Parsed information, alerts, logging
- **Logic Flow:**
  ```
  Raw Packet
      ↓
  Has Ethernet? → Extract MAC addresses
      ↓
  Has IP? → Extract IP addresses
      ↓
  Has TCP? → Extract ports, flags → Check detection
      ↓
  Has UDP? → Extract ports
      ↓
  Has Raw payload? → Check for HTTP
      ↓
  Log if safe → Print formatted output
  ```

#### `start_sniffer()`
- Initializes Scapy's sniff() function
- Sets filter (default: "ip" – IPv4 only)
- Calls process_packet on each captured packet
- Runs indefinitely until Ctrl+C

**Code Architecture:**
```python
def process_packet(packet):
    # Layer 2: Data Link
    if packet.haslayer(Ether):
        # MAC analysis
        
    # Layer 3: Network
    if packet.haslayer(IP):
        # IP routing analysis
        
    # Layer 4: Transport
    if packet.haslayer(TCP):
        # Connection-oriented analysis
    elif packet.haslayer(UDP):
        # Connectionless analysis
        
    # Layer 7: Application
    if packet.haslayer(Raw):
        # Payload inspection
```

**Why this structure?** 
- Follows OSI model layering (educational + practical)
- Each `if` is independent (one packet can have multiple layers)
- Easy to add/remove detection logic per layer

---

### 2.2 DETECTOR.PY – Threat Intelligence Layer

**Responsibility:** Identify suspicious patterns in traffic

**Current Implementation:**

```python
suspicious_ports = {4444, 1337, 6666, 31337, 9001}
```

**Why these ports?**
| Port | Association | Why Suspicious |
|------|-------------|---|
| 4444 | Metasploit Meterpreter | Common C2 callback port |
| 1337 | 31337 (Elite) / Backdoors | Historical malware port |
| 6666 | IRC Botnets | Botnet C2 communication |
| 31337 | BackOrifice RAT | Remote access trojan |
| 9001 | Tor relay / P2P | Used by several botnets |

**Function: `detect_suspicious_port(port)`**
- Takes destination port as input
- Returns True/False
- O(1) lookup (set membership)

**Detection Limitations & Notes:**
- ✅ **Effective for:** Known C2 ports, historically dangerous ports
- ❌ **Ineffective against:** Modern APTs (use high ports like 443, 8080), encrypted traffic (can't inspect payload)
- 🔄 **Real-world systems use:** ML models, behavioral analysis, threat intelligence feeds

---

### 2.3 LOGGER.PY – Forensic Layer

**Responsibility:** Maintain persistent records of suspicious activity

**Function: `log_packet(data)`**
```
data: "192.168.1.100:54321 -> 8.8.8.8:443 FLAGS=S"
                    ↓
         packets.log (append mode)
                    ↓
Forensic record maintained
```

**File handling:**
- Opens `packets.log` in append mode (`"a"`)
- Encodes as UTF-8 (handles special characters)
- Catches errors gracefully

**Why logging matters:**
- **Forensic analysis** – Post-incident investigation
- **Trend analysis** – Spot patterns over time
- **Compliance** – Regulatory requirements (PCI-DSS, HIPAA)
- **Debugging** – Understand what the sniffer captured

**Log entry format:**
```
SRC_IP:SRC_PORT -> DST_IP:DST_PORT FLAGS=FLAGS
```

**Example log file (packets.log):**
```
192.168.1.100:54321 -> 8.8.8.8:443 FLAGS=S
192.168.1.100:54322 -> 142.250.1.95:443 FLAGS=SA
10.0.0.50:60001 -> 192.168.1.1:53 FLAGS=None
192.168.1.101:48291 -> 8.8.4.4:53 FLAGS=None
```

---

## 3. Data Flow & Processing

### 3.1 Packet Capture Flow

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Network Interface Receives Frame                │
│ Example: Ethernet frame arrives at eth0                 │
└──────────┬──────────────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────────────────────────┐
│ Step 2: Scapy Intercepts Raw Bytes                      │
│ sniff() hook captures before OS network stack           │
└──────────┬──────────────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────────────────────────┐
│ Step 3: Packet Object Created                           │
│ Scapy parses binary data → Packet object with layers   │
└──────────┬──────────────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────────────────────────┐
│ Step 4: process_packet() Called                         │
│ Callback function executes for each packet              │
└──────────┬──────────────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────────────────────────┐
│ Step 5: Layer-by-Layer Inspection                       │
│ Check Ethernet → IP → TCP/UDP → Raw payload            │
└──────────┬──────────────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────────────────────────┐
│ Step 6: Detection & Logging (if applicable)             │
│ Run detect_suspicious_port() → log_packet()             │
└──────────┬──────────────────────────────────────────────┘
           │
           ↓
┌─────────────────────────────────────────────────────────┐
│ Step 7: Output & Archive                                │
│ Print to console + write to packets.log                 │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Example Packet Dissection

**Scenario:** Browser makes HTTPS request to google.com

**Real Packet Structure:**
```
┌─────────────────────────────────────────┐
│ Layer 2: Ethernet Frame                  │
│ ─────────────────────────────────────── │
│ Source MAC:      08:00:27:4e:2a:1c     │
│ Dest MAC:        52:54:00:12:35:02     │
│ Protocol:        IPv4 (0x0800)          │
├─────────────────────────────────────────┤
│ Layer 3: IPv4 Packet                    │
│ ─────────────────────────────────────── │
│ Source IP:       192.168.1.100          │
│ Dest IP:         142.250.1.95 (Google) │
│ TTL:             64                     │
│ Protocol:        TCP (6)                │
├─────────────────────────────────────────┤
│ Layer 4: TCP Segment                    │
│ ─────────────────────────────────────── │
│ Source Port:     54321                  │
│ Dest Port:       443 (HTTPS)            │
│ Flags:           S (SYN)                │
│ Seq Number:      1234567890             │
│ Ack Number:      0                      │
├─────────────────────────────────────────┤
│ Layer 7: Application Data                │
│ ─────────────────────────────────────── │
│ (Encrypted TLS handshake - not readable)│
│ [Binary data: \x16\x03\x01\x00...]     │
└─────────────────────────────────────────┘
```

**What Phantom Trace outputs:**
```
[L2] SRC MAC : 08:00:27:4e:2a:1c
[L2] DST MAC : 52:54:00:12:35:02
[L3] SRC IP  : 192.168.1.100
[L3] DST IP  : 142.250.1.95
[L4] TCP SEGMENT
PORTS  : 54321 -> 443
FLAGS  : S
```

---

## 4. Protocol Understanding

### 4.1 Why Layer-by-Layer Parsing Matters

```
┌─────────────────────────────────────────────────┐
│  Common Misconception:                          │
│  "Packets are single units"                     │
│                                                  │
│  Reality:                                       │
│  Packets are nested structures (encapsulation)  │
└─────────────────────────────────────────────────┘

Application Data (HTTP request)
    ↓ wrapped by
TCP Header (ports, sequence numbers)
    ↓ wrapped by
IP Header (source/destination IP)
    ↓ wrapped by
Ethernet Header (MAC addresses)
    ↓ wrapped by
Physical transmission (1s and 0s on the wire)
```

### 4.2 TCP vs UDP

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Requires handshake (3-way) | Connectionless (fire & forget) |
| Reliability | Guaranteed delivery | Best effort |
| Speed | Slower (error checking) | Faster (no overhead) |
| Flags | SYN, ACK, FIN, RST, etc. | None |
| Common Ports | 80 (HTTP), 443 (HTTPS), 22 (SSH) | 53 (DNS), 161 (SNMP), 5353 (mDNS) |
| Detection | Can inspect flags | Only see source/dest ports |

**What this means for Phantom Trace:**
- TCP connections tell a *story* (SYN → multiple ACKs → FIN)
- UDP is stateless (single packet per request/response pair)
- Only TCP analysis can detect incomplete handshakes

---

## 5. Security Considerations

### 5.1 What We Can See vs. Can't See

**✅ CAN SEE:**
- Source & destination IP addresses
- Source & destination ports
- TCP flags and connection behavior
- Unencrypted payload data (HTTP, DNS, plaintext protocols)
- Packet size and timing
- Protocol type (TCP/UDP/ICMP)

**❌ CANNOT SEE (Encrypted Traffic):**
- HTTPS/TLS payload (encrypted with certificate)
- Who the user is communicating with (only the endpoint IP)
- What command was sent (encrypted)
- SSH session contents (encrypted)
- DNS-over-HTTPS queries (encrypted)

### 5.2 Limitations of Port-Based Detection

```
Current approach:
if dst_port in suspicious_ports:
    ALERT

Why it works:
- Old malware was dumb (used fixed ports)

Why it fails:
1. Modern malware uses HTTPS (port 443)
   → Blends in with legitimate traffic
2. APTs use dynamic ports (9001 → 9999)
   → No pattern to detect
3. Proxy networks hide actual ports
   → Tor, VPNs, corporate proxies

Production detection uses:
- Behavioral analysis (connection patterns)
- Machine learning (flow classification)
- Threat intelligence feeds (known C2 IPs)
- Entropy analysis (encrypted vs plaintext)
- Time-based analysis (when connections happen)
```

---

## 6. Performance & Scalability

### 6.1 Current Performance

```
Packet Processing Speed: ~1000 packets/second (typical)
Memory per packet: ~1-2 KB (in memory)
CPU usage: Low-Medium (depends on payload inspection)
Log file growth: ~50-100 bytes per packet
```

### 6.2 Scalability Limitations

| Aspect | Current | Issue | Solution |
|--------|---------|-------|----------|
| **Real-time display** | Console printing | Slows down with high traffic | Use logging only, web dashboard |
| **Memory** | No limit | Will fill RAM on high-speed link | Ring buffer, rolling logs |
| **Detection** | Linear search | O(n) per packet | Use set (O(1)) ✓ already done |
| **Logging** | File append | Disk I/O bottleneck | Batch writes, async logging |

**Optimization for production:**
```python
# Current: Blocks on file I/O
log_packet(f"...")

# Better: Async queue
import queue
log_queue.put(f"...")
# Background thread writes to disk
```

---

## 7. Learning Outcomes & Educational Value

### What This Project Teaches

#### Network Fundamentals
- How real packets are structured
- Why OSI layers exist (not just theoretical)
- How TCP handshake appears in live traffic
- What ports actually represent

#### Python Skills
- Working with external libraries (Scapy)
- Callback functions (sniff callback pattern)
- File I/O and error handling
- Modular design principles

#### Security Mindset
- Detection logic (false positives vs false negatives)
- Logging for forensic analysis
- Why encryption matters
- Limitations of simple rule-based detection

#### Engineering Thinking
- Architecture planning (sniffer → detector → logger)
- Separation of concerns (each module has one job)
- Extensibility (easy to add new detection rules)
- Testing methodology (capture different scenarios)

---

## 8. Future Architecture Improvements

### 8.1 Real-time Dashboard

```
┌──────────────────────────────────────┐
│      PHANTASM TRACE DASHBOARD        │
├──────────────────────────────────────┤
│ Real-time Packet Count: 1,234        │
│ Alerts (last hour): 3                │
│ Top Source IPs:                      │
│   - 192.168.1.100 (890 packets)      │
│   - 10.0.0.50 (234 packets)          │
├──────────────────────────────────────┤
│ Recent Alerts:                       │
│ [14:23:45] 192.168.1.101 -> *:4444  │
│ [14:19:12] 10.0.0.88 -> *:31337     │
└──────────────────────────────────────┘
```

### 8.2 Flow-Based Analysis

```
Current: Packet-level (isolated)
Flow 1:  192.168.1.100 → 8.8.8.8:443
         - Packet 1: SYN
         - Packet 2: SYN-ACK
         - Packet 3: ACK
         - Packets 4-127: Data exchange
         - Packet 128: FIN

Flow detection would:
✓ Correlate related packets
✓ Detect incomplete handshakes
✓ Measure connection duration
✓ Count data packets per connection
```

### 8.3 Integration with Threat Intel

```
Current: Hardcoded list {4444, 1337, ...}

Better:
┌──────────────────────┐
│   Phantom Trace      │
└──────────┬───────────┘
           │
    ┌──────┴──────────────┐
    ↓                     ↓
[VirusTotal]      [AbuseIPDB]
  - Check IPs        - Reputation
  - Check ports      - Threat level

Output:
[CRITICAL] 192.168.1.100 → 5.8.3.4:445
   Threat Intel: Known ransomware C2
   Confidence: 98%
```

---

## 9. Testing & Validation

### 9.1 How to Test This Project

**Test Case 1: Basic Packet Capture**
```bash
# Terminal 1: Start sniffer
sudo python3 main.py

# Terminal 2: Generate traffic
ping 8.8.8.8
# Expected: ICMP packets visible in Terminal 1
```

**Test Case 2: TCP Connection**
```bash
# Terminal 1: Start sniffer
sudo python3 main.py

# Terminal 2: Make connection
curl -v https://google.com
# Expected: TCP SYN, SYN-ACK, ACK visible
```

**Test Case 3: Suspicious Port Detection**
```bash
# Terminal 1: Start sniffer
sudo python3 main.py

# Terminal 2: Connect to suspicious port (locally)
nc localhost 4444
# Expected: [ALERT] Suspicious Destination Port Detected!
```

---

## 10. Code Quality & Design Patterns

### 10.1 Why This Design Works

```python
# Pattern 1: Separation of Concerns
sniffer.py     → Responsibility: Capture & parse
detector.py    → Responsibility: Threat detection
logger.py      → Responsibility: Recording data

# Benefits:
# ✓ Each module can be tested independently
# ✓ Easy to swap detection logic
# ✓ Easy to change logging backend (file → database)
```

### 10.2 Extensibility Example

**Want to add SSL/TLS inspection?**
```python
# Add to sniffer.py
if packet.haslayer(SSL):
    ssl = packet[SSL]
    print(f"[L7] SSL Certificate: {ssl.cert}")
    # Can add custom detection
```

**Want to log to database instead of file?**
```python
# Change logger.py
# from: write to file
# to:   insert into PostgreSQL
def log_packet(data):
    db.execute("INSERT INTO packets VALUES (?)", (data,))
    db.commit()
```

---

## 11. Conclusion

**Phantom Trace Engine is:**
- ✅ Educational (teaches network fundamentals)
- ✅ Practical (real threat detection element)
- ✅ Extensible (easy to add features)
- ✅ Professional (modular, documented code)

**Not meant to be:**
- ❌ Production IDS (use Suricata, Zeek)
- ❌ Enterprise solution (limited detection)
- ❌ Malware analyst tool (use Wireshark/IDA Pro)

**Best used for:**
- Learning network security concepts
- Portfolio demonstration
- Foundation for building more complex tools
- Understanding how real tools work (Wireshark, Zeek, tcpdump)

---

**Architecture Last Updated:** May 2026  
**Learning Project Status:** Active ✓
