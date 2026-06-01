# Network Sniffer

Python program that captures live network traffic, analyzes packet structure, and displays source/destination IPs, protocols, ports, and payloads.

## Requirements covered

| Task requirement | Implementation |
|------------------|----------------|
| Capture network packets | `scapy.sniff()` in `network_sniffer.py` |
| Analyze structure & content | Layer stack, IP/TCP/UDP/ICMP/ARP details |
| Understand data flow & protocols | Printed protocol, ports, TTL, flags |
| Use `scapy` or `socket` | **scapy** (standard for packet capture) |
| Show IPs, protocols, payloads | Console output per packet |

## Setup

```powershell
git clone https://github.com/ALIHASSNAIN78/Network-Sniffer.git
cd Network-Sniffer
pip install -r requirements.txt
```

**Windows:** Install [Npcap](https://nmap.org/npcap/) (with WinPcap API-compatible mode). Run terminal **as Administrator**.

## Run

```powershell
# Demo mode — no Administrator / Npcap needed (for testing & screenshots)
python network_sniffer.py --demo

# Capture 10 packets (good for demo/submission)
python network_sniffer.py -c 10

# Only TCP traffic
python network_sniffer.py -c 20 -f tcp

# DNS queries
python network_sniffer.py -c 15 -f "udp port 53"

# List network interfaces
python network_sniffer.py --list-interfaces

# Specific interface
python network_sniffer.py -i "\Device\NPF_{...}" -c 10
```

Press **Ctrl+C** to stop when count is 0 (unlimited).

## Output

```
================================================================================
Packet #1  |  Time: 14:32:01.123  |  Length: 74 bytes
--------------------------------------------------------------------------------
Layer stack : Ether → IP → TCP → Raw
Protocol    : TCP (flags: S)
Source      : 192.168.1.5:52341
Destination : 142.250.185.78:443
IP details  : TTL=128, id=12345, len=60
Payload preview:
HEX: 16 03 01 00 ...
ASCII: .....
```


## Troubleshooting

| Problem | Fix |
|---------|-----|
| Permission denied | Run as Administrator |
| No modules named scapy | `pip install scapy` |
| Capture error on Windows | Install Npcap, reboot if needed |
| No packets | Generate traffic (open a website) or try `-f icmp` and `ping 8.8.8.8` |



## Contributors
ALIHUSSNAIN – Developer
