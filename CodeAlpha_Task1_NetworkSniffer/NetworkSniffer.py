import argparse
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS  # Imported DNS layer

DEFAULT_INTERFACE = "Intel(R) Wireless-AC 9560 160MHz"
DEFAULT_COUNT = 1000
REPORT_DIR = Path("reports")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Capture and summarize authorized IP network traffic."
    )
    parser.add_argument(
        "--protocol",
        choices=["ALL", "TCP", "UDP", "ICMP", "DNS"],
        default="ALL",
        help="Protocol to capture (default: ALL).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_COUNT,
        help="Maximum number of packets to capture (default: 1000).",
    )
    parser.add_argument(
        "--interface",
        default=DEFAULT_INTERFACE,
        help="Scapy interface name to capture on.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="CSV output path (optional).",
    )

    args = parser.parse_args()

    if not 1 <= args.count <= 10000:
        parser.error("--count must be between 1 and 10000")

    return args


def get_protocol(packet):
    sport, dport = "", ""
    
    # Saftey check, though analyze_packet already filters for IP
    if IP not in packet:
        return "UNKNOWN", sport, dport

    # Dynamically extract the underlying protocol name (TCP, UDP, IGMP, OSPF, etc.)
    protocol = packet[IP].sprintf("%IP.proto%").upper()

    # Extract ports if the transport layer exists
    if TCP in packet:
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        sport, dport = packet[UDP].sport, packet[UDP].dport

    # Explicitly label as DNS if it has a DNS layer (Application layer override)
    if DNS in packet:
        protocol = "DNS"

    return protocol, sport, dport


def analyze_packet(packet, rows, protocol_counts, totals):
    # Only analyze IP packets
    if IP not in packet:
        return

    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    ip_layer = packet[IP]
    protocol, source_port, destination_port = get_protocol(packet)
    packet_length = len(packet)

    payload_preview = ""
    if Raw in packet:
        payload_preview = bytes(packet[Raw].load)[:16].hex()

    row = {
        "timestamp": timestamp,
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size_bytes": packet_length,
        "payload_preview_hex": payload_preview,
    }
    
    rows.append(row)
    protocol_counts[protocol] += 1
    totals["packets"] += 1
    totals["bytes"] += packet_length

    print("-" * 60)
    print(f"Time:        {timestamp}")
    print(f"Source IP:   {ip_layer.src}")
    print(f"Destination: {ip_layer.dst}")
    print(f"Protocol:    {protocol}")
    print(f"Source port: {source_port or '-'}")
    print(f"Dest. port:  {destination_port or '-'}")
    print(f"Packet size: {packet_length} bytes")

    if payload_preview:
        print(f"Payload preview (first 16 bytes, hex): {payload_preview}")
    else:
        print("Payload preview: No raw payload available")


def write_report(rows, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "packet_size_bytes",
        "payload_preview_hex",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    args = parse_args()
    rows = []
    protocol_counts = Counter()
    totals = {"packets": 0, "bytes": 0}

    # Fixed DNS BPF filter ('dns' is invalid BPF syntax, use 'port 53')
    bpf_filters = {
        "ALL": "ip",
        "TCP": "ip and tcp",
        "UDP": "ip and udp",
        "DNS": "ip and port 53",
        "ICMP": "ip and icmp",
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = (
        Path(args.output)
        if args.output
        else REPORT_DIR / f"capture_{timestamp}.csv"
    )

    print("CodeAlpha Basic Network Sniffer")
    print(f"Interface: {args.interface}")
    print(f"Protocol filter: {args.protocol}")
    print(f"Packet limit: {args.count}")
    print(f"CSV report: {output_path}")
    print("Monitor only networks you own or are authorized to test.")
    print("Press Ctrl+C to stop early.\n")

    try:
        sniff(
            iface=args.interface,
            filter=bpf_filters[args.protocol],
            prn=lambda packet: analyze_packet(
                packet, rows, protocol_counts, totals
            ),
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("Permission denied. Try running PowerShell as Administrator.")
        return
    except OSError as error:
        print(f"Capture error: {error}")
        return
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    write_report(rows, output_path)

    print("\nCAPTURE SUMMARY")
    print("-" * 30)
    print(f"Total packets: {totals['packets']}")
    print(f"Total bytes:   {totals['bytes']}")
    print("Packets by protocol:")

    # This will now accurately display all observed protocols (TCP, UDP, IGMP, ICMP, DNS, etc.)
    if protocol_counts:
        for protocol, count in protocol_counts.most_common():
            print(f"  {protocol}: {count}")
    else:
        print("  No packets captured.")

    print(f"\nCSV report saved to: {output_path}")


if __name__ == "__main__":
    main()