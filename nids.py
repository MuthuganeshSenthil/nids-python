# nids.py
# Days 1-8 Complete — Threading + All Detectors + Logging + Enrichment
# Run with: sudo python3 nids.py

import threading
import queue
import sqlite3
import csv
import os
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ─── CONFIGURATION ────────────────────────────────────────────
INTERFACE             = "wlan0"
MAX_STORE             = 1000
FILTER_PROTO          = "ALL"      # "ALL", "TCP", "UDP", "ICMP"

PORT_SCAN_THRESHOLD   = 10
PING_FLOOD_THRESHOLD  = 10
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW_SECONDS   = 5

BLACKLISTED_IPS = {
    "10.0.0.99",
    "192.168.1.254",
    "1.2.3.4",
}

CSV_FILE = "alerts.csv"
DB_FILE  = "nids.db"
# ──────────────────────────────────────────────────────────────


# ─── SHARED STATE ─────────────────────────────────────────────
packet_queue = queue.Queue()
packet_store = []
alert_log    = []
packet_count = 0

port_history = defaultdict(list)
icmp_history = defaultdict(list)
conn_history = defaultdict(list)

store_lock   = threading.Lock()
# ──────────────────────────────────────────────────────────────


# ─── PORT → SERVICE MAP (Day 8) ───────────────────────────────
PORT_SERVICES = {
    20: "FTP-data", 21: "FTP",      22: "SSH",       23: "Telnet",
    25: "SMTP",     53: "DNS",      67: "DHCP",      68: "DHCP",
    80: "HTTP",    110: "POP3",    143: "IMAP",     443: "HTTPS",
   445: "SMB",    3306: "MySQL",  3389: "RDP",     5900: "VNC",
  8080: "HTTP-alt", 8443: "HTTPS-alt", 1900: "SSDP", 5353: "mDNS",
}
# ──────────────────────────────────────────────────────────────


# ─── DAY 6: LOGGER SETUP ──────────────────────────────────────
def setup_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "type", "src_ip",
                "detail", "severity", "ip_class"
            ])
        print(f"  Created {CSV_FILE}")

def setup_sqlite():
    conn   = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            type      TEXT,
            src_ip    TEXT,
            detail    TEXT,
            severity  TEXT DEFAULT 'LOW',
            ip_class  TEXT DEFAULT 'UNKNOWN'
        )
    """)
    conn.commit()
    conn.close()
    print(f"  Connected to {DB_FILE}")

def log_to_csv(alert):
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            alert["timestamp"],
            alert["type"],
            alert["src_ip"],
            alert["detail"],
            alert.get("severity", "LOW"),
            alert.get("ip_class", "UNKNOWN"),
        ])

def log_to_sqlite(alert):
    conn   = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts
            (timestamp, type, src_ip, detail, severity, ip_class)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["timestamp"],
        alert["type"],
        alert["src_ip"],
        alert["detail"],
        alert.get("severity", "LOW"),
        alert.get("ip_class", "UNKNOWN"),
    ))
    conn.commit()
    conn.close()
# ──────────────────────────────────────────────────────────────


# ─── HELPERS ──────────────────────────────────────────────────
def now_ts():
    return datetime.now().strftime("%H:%M:%S")

def now_sec():
    return datetime.now().timestamp()

def get_protocol(packet):
    if   TCP  in packet: return "TCP"
    elif UDP  in packet: return "UDP"
    elif ICMP in packet: return "ICMP"
    else:                return "OTHER"

def passes_filter(protocol):
    return FILTER_PROTO == "ALL" or FILTER_PROTO == protocol

def get_service(port):
    """Convert port number to service name."""
    if port is None:
        return "-"
    return PORT_SERVICES.get(port, str(port))

def classify_ip(ip):
    """
    Classify an IP as LOOPBACK, PRIVATE, MULTICAST, or PUBLIC.
    Based on RFC 1918 private address ranges.
    """
    if ip.startswith("127."):
        return "LOOPBACK"
    if ip.startswith("10."):
        return "PRIVATE"
    if ip.startswith("192.168."):
        return "PRIVATE"
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        if 16 <= second <= 31:
            return "PRIVATE"
    if ip.startswith("239.") or ip.startswith("224."):
        return "MULTICAST"
    return "PUBLIC"

def get_severity(alert_type):
    """
    Assign severity to each alert type.
    HIGH = act now, MEDIUM = investigate, LOW = informational.
    """
    severity_map = {
        "PORT_SCAN"      : "HIGH",
        "BRUTE_FORCE"    : "HIGH",
        "PING_FLOOD"     : "MEDIUM",
        "BLACKLISTED_IP" : "HIGH",
    }
    return severity_map.get(alert_type, "LOW")
# ──────────────────────────────────────────────────────────────


# ─── ALERT ENGINE ─────────────────────────────────────────────
def raise_alert(alert_type, src_ip, detail):
    severity = get_severity(alert_type)
    ip_class = classify_ip(src_ip)

    alert = {
        "timestamp" : now_ts(),
        "type"      : alert_type,
        "src_ip"    : src_ip,
        "detail"    : detail,
        "severity"  : severity,
        "ip_class"  : ip_class,
    }
    alert_log.append(alert)

    # ANSI terminal colors
    colors = {
        "HIGH"   : "\033[91m",   # Red
        "MEDIUM" : "\033[93m",   # Yellow
        "LOW"    : "\033[92m",   # Green
    }
    reset = "\033[0m"
    color = colors.get(severity, "")

    print(f"\n  {color}*** ALERT [{alert['timestamp']}]"
          f" [{severity}] ***{reset}")
    print(f"  Type     : {alert_type}")
    print(f"  Source   : {src_ip} ({ip_class})")
    print(f"  Detail   : {detail}")
    print(f"  Total alerts so far: {len(alert_log)}\n")

    log_to_csv(alert)
    log_to_sqlite(alert)
# ──────────────────────────────────────────────────────────────


# ─── DETECTORS ────────────────────────────────────────────────
def check_blacklist(src_ip, dst_ip):
    if src_ip in BLACKLISTED_IPS:
        raise_alert("BLACKLISTED_IP", src_ip,
                    f"{src_ip} is blacklisted (source)")
    if dst_ip in BLACKLISTED_IPS:
        raise_alert("BLACKLISTED_IP", dst_ip,
                    f"{dst_ip} is blacklisted (destination)")

def check_port_scan(src_ip, dst_port):
    if dst_port is None:
        return
    t = now_sec()
    port_history[src_ip].append((t, dst_port))
    port_history[src_ip] = [
        (ts, p) for ts, p in port_history[src_ip]
        if t - ts <= TIME_WINDOW_SECONDS
    ]
    unique = set(p for _, p in port_history[src_ip])
    if len(unique) >= PORT_SCAN_THRESHOLD:
        services = [get_service(p) for p in sorted(unique)]
        raise_alert(
            "PORT_SCAN", src_ip,
            f"{len(unique)} unique ports in {TIME_WINDOW_SECONDS}s"
            f": {services}"
        )
        port_history[src_ip] = []

def check_ping_flood(src_ip):
    t = now_sec()
    icmp_history[src_ip].append(t)
    icmp_history[src_ip] = [
        ts for ts in icmp_history[src_ip]
        if t - ts <= TIME_WINDOW_SECONDS
    ]
    count = len(icmp_history[src_ip])
    if count >= PING_FLOOD_THRESHOLD:
        raise_alert(
            "PING_FLOOD", src_ip,
            f"{count} ICMP packets in {TIME_WINDOW_SECONDS}s"
        )
        icmp_history[src_ip] = []

def check_brute_force(src_ip, dst_port):
    """
    Same IP hitting same port repeatedly.
    Port scan  = one IP, many DIFFERENT ports.
    Brute force = one IP, same port, many TIMES.
    """
    if dst_port is None:
        return
    key = (src_ip, dst_port)
    t   = now_sec()
    conn_history[key].append(t)
    conn_history[key] = [
        ts for ts in conn_history[key]
        if t - ts <= TIME_WINDOW_SECONDS
    ]
    count = len(conn_history[key])
    if count >= BRUTE_FORCE_THRESHOLD:
        service = get_service(dst_port)
        raise_alert(
            "BRUTE_FORCE", src_ip,
            f"{count} connections to port {dst_port}"
            f" ({service}) in {TIME_WINDOW_SECONDS}s"
        )
        conn_history[key] = []
# ──────────────────────────────────────────────────────────────


# ─── THREAD 1: CAPTURE ────────────────────────────────────────
def capture_packets():
    """
    Only job: grab packets off the wire and
    drop them into the queue. No detection here.
    """
    def handle(packet):
        if IP in packet:
            packet_queue.put(packet)

    print(f"  [Thread 1] Capture started on {INTERFACE}")
    sniff(iface=INTERFACE, prn=handle, store=False)
# ──────────────────────────────────────────────────────────────


# ─── THREAD 2: ANALYZE ────────────────────────────────────────
def analyze_packets():
    """
    Only job: pull packets from queue and
    run all detectors. Blocks when queue is empty.
    """
    global packet_count

    print("  [Thread 2] Analysis engine started")

    while True:
        try:
            packet = packet_queue.get(timeout=1)
        except queue.Empty:
            continue

        protocol = get_protocol(packet)
        if not passes_filter(protocol):
            continue

        packet_count += 1

        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        src_port = None
        dst_port = None

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Day 8 enrichment — service names + IP classification
        src_service = get_service(src_port)
        dst_service = get_service(dst_port)
        src_class   = classify_ip(src_ip)
        dst_class   = classify_ip(dst_ip)

        info = {
            "timestamp"   : now_ts(),
            "src_ip"      : src_ip,
            "dst_ip"      : dst_ip,
            "src_port"    : src_port,
            "dst_port"    : dst_port,
            "src_service" : src_service,
            "dst_service" : dst_service,
            "src_class"   : src_class,
            "dst_class"   : dst_class,
            "protocol"    : protocol,
            "size"        : len(packet),
        }

        with store_lock:
            packet_store.append(info)
            if len(packet_store) > MAX_STORE:
                packet_store.pop(0)

        # Enriched print line — shows service names now
        src_str = f"{src_ip}:{src_service}"
        dst_str = f"{dst_ip}:{dst_service}"
        print(
            f"[{info['timestamp']}] #{packet_count:04d} | "
            f"{protocol:<5} | {info['size']:>5}B | "
            f"{src_str:<32} -> {dst_str}"
        )

        # Run all 4 detectors
        check_blacklist(src_ip, dst_ip)
        check_port_scan(src_ip, dst_port)
        check_brute_force(src_ip, dst_port)
        if ICMP in packet:
            check_ping_flood(src_ip)

        packet_queue.task_done()
# ──────────────────────────────────────────────────────────────


# ─── END OF SESSION SUMMARY ───────────────────────────────────
def show_saved_alerts():
    print("\n" + "=" * 60)
    print("  ALERTS SAVED TO DATABASE THIS SESSION")
    print("=" * 60)
    conn   = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 20"
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("  No alerts saved yet.")
    else:
        for row in rows:
            # id | timestamp | type | src_ip | detail | severity | ip_class
            print(f"  [{row[1]}] {row[2]:<16} {row[5]:<8}"
                  f"| {row[3]:<18} | {row[4]}")
    print("=" * 60)
# ──────────────────────────────────────────────────────────────


# ─── MAIN ─────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  NIDS — Days 1-8 Complete")
    print(f"  Interface    : {INTERFACE}")
    print(f"  Filter       : {FILTER_PROTO}")
    print(f"  Port scan    : {PORT_SCAN_THRESHOLD} ports / {TIME_WINDOW_SECONDS}s")
    print(f"  Ping flood   : {PING_FLOOD_THRESHOLD} pings / {TIME_WINDOW_SECONDS}s")
    print(f"  Brute force  : {BRUTE_FORCE_THRESHOLD} conns / {TIME_WINDOW_SECONDS}s")
    print(f"  Blacklist    : {len(BLACKLISTED_IPS)} IPs")
    print(f"  CSV log      : {CSV_FILE}")
    print(f"  Database     : {DB_FILE}")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    setup_csv()
    setup_sqlite()

    t1 = threading.Thread(target=capture_packets, daemon=True)
    t2 = threading.Thread(target=analyze_packets, daemon=True)

    t1.start()
    t2.start()

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print(f"\n\nStopped.")
        print(f"  Packets captured : {packet_count}")
        print(f"  Alerts generated : {len(alert_log)}")
        show_saved_alerts()
        print(f"\n  Logs saved to: {CSV_FILE} and {DB_FILE}")
