#!/usr/bin/env python3
"""
TASK 1: Basic Network Sniffer
Captures live network packets, analyzes layer structure, and prints
source/destination IPs, protocols, ports, and payload previews.
"""

from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime

try:
    from scapy.config import conf
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
    from scapy.sendrecv import sniff
except ImportError:
    print("Error: scapy is not installed. Run: pip install -r requirements.txt")
    print("Or run: .\\setup.ps1  (creates .venv and installs dependencies)")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def format_payload(packet, max_bytes: int = 64) -> str:
    """Extract and format payload as hex + printable ASCII preview."""
    if packet.haslayer(Raw):
        data = bytes(packet[Raw].load)
    elif packet.haslayer(ARP):
        data = bytes(packet[ARP])
    else:
        return "(no payload)"

    if not data:
        return "(empty)"

    chunk = data[:max_bytes]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    suffix = f" ... (+{len(data) - max_bytes} bytes)" if len(data) > max_bytes else ""
    return f"HEX: {hex_part}\nASCII: {ascii_part}{suffix}"


def get_protocol_name(packet) -> str:
    """Resolve highest relevant protocol label."""
    if packet.haslayer(TCP):
        flags = packet[TCP].sprintf("%TCP.flags%")
        return f"TCP (flags: {flags or '-'})"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        return f"ICMP (type={icmp.type}, code={icmp.code})"
    if packet.haslayer(ARP):
        op = "request" if packet[ARP].op == 1 else "reply"
        return f"ARP ({op})"
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(IP):
        return f"IP (proto={packet[IP].proto})"
    if packet.haslayer(Ether):
        return "Ethernet"
    return packet.summary()


def get_endpoints(packet) -> tuple[str, str, str, str]:
    """
    Return (src_ip, dst_ip, src_port, dst_port) as strings.
    Non-IP traffic uses MAC or ARP fields where applicable.
    """
    src_ip = dst_ip = src_port = dst_port = "-"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    if packet.haslayer(TCP):
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)

    if packet.haslayer(ARP) and not packet.haslayer(IP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    if packet.haslayer(Ether) and src_ip == "-":
        src_ip = packet[Ether].src
        dst_ip = packet[Ether].dst

    return src_ip, dst_ip, src_port, dst_port


def describe_layers(packet) -> str:
    """Build a human-readable layer stack (packet structure)."""
    layers = []
    current = packet
    while current:
        layers.append(current.__class__.__name__)
        current = current.payload if hasattr(current, "payload") and current.payload else None
    return " -> ".join(layers)


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

class PacketPrinter:
    def __init__(self, show_payload: bool = True, payload_bytes: int = 64):
        self.count = 0
        self.show_payload = show_payload
        self.payload_bytes = payload_bytes

    def __call__(self, packet) -> None:
        self.count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src_ip, dst_ip, src_port, dst_port = get_endpoints(packet)
        protocol = get_protocol_name(packet)
        layer_stack = describe_layers(packet)
        length = len(packet)

        print("=" * 72)
        print(f"Packet #{self.count}  |  Time: {timestamp}  |  Length: {length} bytes")
        print("-" * 72)
        print(f"Layer stack : {layer_stack}")
        print(f"Protocol    : {protocol}")
        print(f"Source      : {src_ip}" + (f":{src_port}" if src_port != "-" else ""))
        print(f"Destination : {dst_ip}" + (f":{dst_port}" if dst_port != "-" else ""))

        if packet.haslayer(IP):
            ip = packet[IP]
            print(f"IP details  : TTL={ip.ttl}, id={ip.id}, len={ip.len}")

        if self.show_payload:
            print("Payload preview:")
            print(format_payload(packet, self.payload_bytes))

        print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def list_interfaces() -> None:
    """Print available capture interfaces (useful on Windows with Npcap)."""
    print("Available interfaces:")
    for name, iface in conf.ifaces.items():
        desc = getattr(iface, "description", name) or name
        print(f"  - {name}: {desc}")


def run_demo(printer: PacketPrinter) -> None:
    """Analyze sample packets without live capture (no admin/Npcap needed)."""
    samples = [
        Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:01")
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / ICMP(type=8, code=0)
        / Raw(load=b"ping-demo-payload"),
        Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:03")
        / IP(src="192.168.1.10", dst="142.250.185.46")
        / TCP(sport=45123, dport=443, flags="S")
        / Raw(load=b"\x16\x03\x01\x00\x05hello"),
        Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:03")
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / UDP(sport=51234, dport=53)
        / Raw(load=b"\x12\x34query"),
        Ether(src="aa:bb:cc:dd:ee:04", dst="aa:bb:cc:dd:ee:05")
        / ARP(op=1, psrc="192.168.1.50", pdst="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:04"),
    ]
    print("DEMO MODE — analyzing sample packets (no live capture)\n")
    for pkt in samples:
        printer(pkt)
    print(f"Demo finished. Packets analyzed: {printer.count}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer (Task 1) — capture and analyze packets."
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Analyze sample packets without live capture (no admin required).",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Stop after N packets (0 = unlimited until Ctrl+C).",
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        help='BPF filter, e.g. "tcp", "udp port 53", "host 8.8.8.8".',
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Network interface name (default: scapy auto-select).",
    )
    parser.add_argument(
        "--no-payload",
        action="store_true",
        help="Hide payload preview.",
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=64,
        help="Max payload bytes to display (default: 64).",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List interfaces and exit.",
    )
    return parser.parse_args()


def check_environment() -> None:
    """Warn about common Windows / permission issues."""
    if platform.system() == "Windows":
        print(
            "Note (Windows): Install Npcap (https://nmap.org/npcap/) and run "
            "PowerShell/CMD as Administrator for live capture.\n"
        )


def main() -> None:
    args = parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    printer = PacketPrinter(
        show_payload=not args.no_payload,
        payload_bytes=args.payload_bytes,
    )

    if args.demo:
        run_demo(printer)
        return

    check_environment()

    count = args.count if args.count > 0 else 0
    filt = args.filter or None

    print("Starting packet capture... (Press Ctrl+C to stop)\n")
    if filt:
        print(f"Filter: {filt}")
    if args.interface:
        print(f"Interface: {args.interface}")
    print()

    try:
        sniff(
            prn=printer,
            filter=filt,
            iface=args.interface,
            count=count,
            store=False,
        )
    except PermissionError:
        print(
            "Permission denied. Run this program as Administrator (Windows) "
            "or with sudo (Linux/macOS)."
        )
        sys.exit(1)
    except OSError as exc:
        print(f"Capture error: {exc}")
        print("Ensure Npcap/WinPcap is installed on Windows, or check interface name.")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\nStopped. Total packets captured: {printer.count}")


if __name__ == "__main__":
    main()
