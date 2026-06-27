# packet_capture.py
# Phase 1 + Day 2 upgrade — Packet capture with memory
# Run with: sudo python3 packet_capture.py

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import Counter   # We'll use this to count IPs easily

# ─── CONFIGURATION ────────────────────────────────────────────
INTERFACE  = "wlan0"   # Change to eth0 if needed
MAX_STORE  = 1000      # Keep only the last 1000 packets in memory
# ──────────────────────────────────────────────────────────────

# This is our "memory" — a list of dictionaries, one per packet
packet_store = []
packet_number = 0

def get_protocol(packet):
    if TCP  in packet: return "TCP"
    elif UDP  in packet: return "UDP"
    elif ICMP in packet: return "ICMP"
    else: return "OTHER"

def extract_packet_info(packet):
    """
    Pull every field we care about out of a raw Scapy packet
    and return it as a clean dictionary.
    Think of this like converting a messy raw egg into a
    labelled container — easy to read and store.
    """
    src_port = None
    dst_port = None
    protocol = get_protocol(packet)

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return {
        "timestamp" : datetime.now().strftime("%H:%M:%S"),
        "src_ip"    : packet[IP].src,
        "dst_ip"    : packet[IP].dst,
        "src_port"  : src_port,
        "dst_port"  : dst_port,
        "protocol"  : protocol,
        "size"      : len(packet),   # Packet size in bytes
    }

def print_packet(info, number):
    """Print one clean line per packet."""
    src = f"{info['src_ip']}:{info['src_port'] or '-'}"
    dst = f"{info['dst_ip']}:{info['dst_port'] or '-'}"
    print(
        f"[{info['timestamp']}] #{number:04d} | "
        f"{info['protocol']:<5} | {info['size']:>5}B | "
        f"{src:<26} -> {dst}"
    )

def print_summary():
    """
    Every 20 packets, print a quick summary.
    This is a preview of what the Phase 4 dashboard will show.
    Uses Counter — a special dictionary that counts things.
    Counter(["a","b","a"]) gives {"a":2, "b":1}
    """
    if len(packet_store) == 0:
        return

    print("\n" + "─" * 60)
    print(f"  SUMMARY  (last {len(packet_store)} packets in memory)")
    print("─" * 60)

    # Count how many times each protocol appeared
    protocols = Counter(p["protocol"] for p in packet_store)
    print(f"  Protocols : {dict(protocols)}")

    # Count packets per source IP, show top 3
    src_ips = Counter(p["src_ip"] for p in packet_store)
    print(f"  Top source IPs:")
    for ip, count in src_ips.most_common(3):
        print(f"    {ip:<20} {count} packets")

    # Count unique destination ports seen
    dst_ports = set(p["dst_port"] for p in packet_store if p["dst_port"])
    print(f"  Unique dst ports seen : {sorted(dst_ports)}")
    print("─" * 60 + "\n")

def process_packet(packet):
    """Called automatically by Scapy for every packet."""
    global packet_number

    if IP not in packet:
        return   # Skip non-IP traffic (ARP, etc.)

    packet_number += 1

    # 1. Extract fields into a dictionary
    info = extract_packet_info(packet)

    # 2. Store it in memory
    packet_store.append(info)

    # 3. If memory is getting big, drop the oldest packet
    #    This keeps RAM usage from growing forever
    if len(packet_store) > MAX_STORE:
        packet_store.pop(0)   # Remove item at index 0 (oldest)

    # 4. Print a live line
    print_packet(info, packet_number)

    # 5. Every 20 packets, show a summary
    if packet_number % 20 == 0:
        print_summary()

# ─── MAIN ─────────────────────────────────────────────────────
print("=" * 60)
print(f"  NIDS Day 2 — capturing on {INTERFACE}")
print(f"  Memory limit: {MAX_STORE} packets")
print("  Press Ctrl+C to stop and see final summary")
print("=" * 60)

try:
    sniff(
        iface=INTERFACE,
        prn=process_packet,
        count=0,
        store=False
    )
except KeyboardInterrupt:
    print("\nStopped by user.")
    print_summary()

    # Bonus: show the last 5 packets we stored
    print("\nLast 5 packets in memory:")
    for p in packet_store[-5:]:
        print(f"  {p}")
