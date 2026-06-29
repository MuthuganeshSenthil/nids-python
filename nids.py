# nids.py
# Days 5 + 6 — Threading + Brute Force + CSV + SQLite logging
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
INTERFACE             = "wlan0"   # Change to eth0 if needed
MAX_STORE             = 1000
FILTER_PROTO          = "ALL"

PORT_SCAN_THRESHOLD   = 10
PING_FLOOD_THRESHOLD  = 10        # Lowered from 20 — easier to trigger
BRUTE_FORCE_THRESHOLD = 5         # Same IP hits same port 5 times in window
TIME_WINDOW_SECONDS   = 5

BLACKLISTED_IPS = {"10.0.0.99", "192.168.1.254", "1.2.3.4"}

# Day 6 — log file paths
CSV_FILE = "alerts.csv"
DB_FILE  = "nids.db"
# ──────────────────────────────────────────────────────────────

# ─── SHARED STATE ─────────────────────────────────────────────
# queue.Queue is thread-safe — Thread 1 puts packets in,
# Thread 2 takes them out. No data corruption possible.
packet_queue  = queue.Queue()
packet_store  = []
alert_log     = []
packet_count  = 0

port_history  = defaultdict(list)   # ip -> [(time, port)]
icmp_history  = defaultdict(list)   # ip -> [time]
conn_history  = defaultdict(list)   # (ip, port) -> [time]

# Lock prevents two threads writing to the same list at once
store_lock    = threading.Lock()
# ──────────────────────────────────────────────────────────────


# ─── DAY 6: LOGGER SETUP ──────────────────────────────────────
def setup_csv():
    """
    Create the CSV file with headers if it doesn't exist yet.
    'a' mode = append, so we never overwrite old alerts.
    newline='' is required by Python's csv module on all platforms.
    """
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "type", "src_ip", "detail"])
        print(f"  Created {CSV_FILE}")

def setup_sqlite():
    """
    Create the SQLite database and alerts table if they don't exist.
    'CREATE TABLE IF NOT EXISTS' means safe to call every run —
    it won't overwrite existing data.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            type      TEXT,
            src_ip    TEXT,
            detail    TEXT
        )
    """)
    conn.commit()
    conn.close()
    print(f"  Connected to {DB_FILE}")

def log_to_csv(alert):
    """Append one alert row to the CSV file."""
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            alert["timestamp"],
            alert["type"],
            alert["src_ip"],
            alert["detail"]
        ])

def log_to_sqlite(alert):
    """
    Insert one alert into SQLite.
    Use '?' placeholders — NEVER format SQL strings directly,
    that causes SQL injection vulnerabilities.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (timestamp, type, src_ip, detail)
        VALUES (?, ?, ?, ?)
    """, (alert["timestamp"], alert["type"],
          alert["src_ip"], alert["detail"]))
    conn.commit()
    conn.close()
# ──────────────────────────────────────────────────────────────


# ─── HELPERS ──────────────────────────────────────────────────
def now_ts():
    return datetime.now().strftime("%H:%M:%S")

def now_sec():
    return datetime.now().timestamp()

def get_protocol(packet):
    if TCP  in packet: return "TCP"
    elif UDP  in packet: return "UDP"
    elif ICMP in packet: return "ICMP"
    else: return "OTHER"

def passes_filter(protocol):
    return FILTER_PROTO == "ALL" or FILTER_PROTO == protocol
# ──────────────────────────────────────────────────────────────


# ─── ALERT ENGINE ─────────────────────────────────────────────
def raise_alert(alert_type, src_ip, detail):
    """
    Creates alert, prints it, and now ALSO saves it to
    CSV and SQLite — that's the Day 6 upgrade.
    """
    alert = {
        "timestamp" : now_ts(),
        "type"      : alert_type,
        "src_ip"    : src_ip,
        "detail"    : detail,
    }
    alert_log.append(alert)

    # Print loud and clear
    print(f"\n  *** ALERT [{alert['timestamp']}] ***")
    print(f"  Type   : {alert_type}")
    print(f"  Source : {src_ip}")
    print(f"  Detail : {detail}")
    print(f"  Total alerts: {len(alert_log)}\n")

    # Day 6 — save to both files
    log_to_csv(alert)
    log_to_sqlite(alert)
# ──────────────────────────────────────────────────────────────


# ─── DETECTORS ────────────────────────────────────────────────
def check_blacklist(src_ip, dst_ip):
    if src_ip in BLACKLISTED_IPS:
        raise_alert("BLACKLISTED_IP", src_ip,
                    f"{src_ip} is blacklisted")
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
        raise_alert("PORT_SCAN", src_ip,
                    f"{len(unique)} unique ports in "
                    f"{TIME_WINDOW_SECONDS}s: {sorted(unique)}")
        port_history[src_ip] = []

def check_ping_flood(src_ip):
    t = now_sec()
    icmp_history[src_ip].append(t)
    icmp_history[src_ip] = [
        ts for ts in icmp_history[src_ip]
        if t - ts <= TIME_WINDOW_SECONDS
    ]
    if len(icmp_history[src_ip]) >= PING_FLOOD_THRESHOLD:
        raise_alert("PING_FLOOD", src_ip,
                    f"{len(icmp_history[src_ip])} ICMP packets "
                    f"in {TIME_WINDOW_SECONDS}s")
        icmp_history[src_ip] = []

def check_brute_force(src_ip, dst_port):
    """
    Brute force = same IP hammering the SAME port repeatedly.
    Different from port scan (which is many ports).
    Common targets: port 22 (SSH), 21 (FTP), 3389 (RDP).

    Key:   (src_ip, dst_port) pair
    Value: list of timestamps when this pair was seen
    If count exceeds threshold in window → brute force alert.
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
        raise_alert("BRUTE_FORCE", src_ip,
                    f"{count} connections to port {dst_port} "
                    f"in {TIME_WINDOW_SECONDS}s")
        conn_history[key] = []
# ──────────────────────────────────────────────────────────────


# ─── THREAD 1: CAPTURE ────────────────────────────────────────
def capture_packets():
    """
    This runs in Thread 1. Its ONLY job is to grab packets
    off the wire and drop them into the queue as fast as possible.
    No detection logic here — that's Thread 2's job.

    This is why threading fixes the ping flood problem:
    Thread 1 never slows down waiting for detection to finish.
    """
    def handle(packet):
        if IP in packet:
            packet_queue.put(packet)   # Hand off to Thread 2

    print(f"  [Thread 1] Capture started on {INTERFACE}")
    sniff(iface=INTERFACE, prn=handle, store=False)
# ──────────────────────────────────────────────────────────────


# ─── THREAD 2: ANALYZE ────────────────────────────────────────
def analyze_packets():
    """
    This runs in Thread 2. It pulls packets from the queue
    one at a time and runs all detectors on each one.

    packet_queue.get() BLOCKS (waits) until a packet arrives —
    so this thread uses zero CPU when the network is quiet.
    """
    global packet_count

    print("  [Thread 2] Analysis engine started")

    while True:
        try:
            # Wait up to 1 second for a packet
            # timeout=1 prevents this thread hanging forever
            # if the program is trying to shut down
            packet = packet_queue.get(timeout=1)
        except queue.Empty:
            continue   # No packet yet — loop and wait again

        protocol = get_protocol(packet)

        if not passes_filter(protocol):
            continue

        packet_count += 1

        # Extract fields
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

        info = {
            "timestamp" : now_ts(),
            "src_ip"    : src_ip,
            "dst_ip"    : dst_ip,
            "src_port"  : src_port,
            "dst_port"  : dst_port,
            "protocol"  : protocol,
            "size"      : len(packet),
        }

        # Store in memory (thread-safe with lock)
        with store_lock:
            packet_store.append(info)
            if len(packet_store) > MAX_STORE:
                packet_store.pop(0)

        # Print live line
        src = f"{src_ip}:{src_port or '-'}"
        dst = f"{dst_ip}:{dst_port or '-'}"
        print(f"[{info['timestamp']}] #{packet_count:04d} | "
              f"{protocol:<5} | {info['size']:>5}B | "
              f"{src:<26} -> {dst}")

        # Run all 4 detectors
        check_blacklist(src_ip, dst_ip)
        check_port_scan(src_ip, dst_port)
        check_brute_force(src_ip, dst_port)
        if ICMP in packet:
            check_ping_flood(src_ip)

        packet_queue.task_done()
# ──────────────────────────────────────────────────────────────


# ─── QUERY SAVED ALERTS (Day 6 bonus) ─────────────────────────
def show_saved_alerts():
    """
    At the end of the session, read back from SQLite
    and show all alerts ever saved — not just this session.
    This proves the database is persisting data correctly.
    """
    print("\n" + "=" * 60)
    print("  SAVED ALERTS FROM DATABASE")
    print("=" * 60)
    conn   = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 20")
    rows   = cursor.fetchall()
    conn.close()

    if not rows:
        print("  No alerts saved yet.")
    else:
        for row in rows:
            print(f"  [{row[1]}] {row[2]} | {row[3]} | {row[4]}")
    print("=" * 60)
# ──────────────────────────────────────────────────────────────


# ─── MAIN ─────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  NIDS — Days 5+6 | Threading + Logging")
    print(f"  Interface  : {INTERFACE}")
    print(f"  CSV log    : {CSV_FILE}")
    print(f"  Database   : {DB_FILE}")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    # Day 6 — set up log files before starting
    setup_csv()
    setup_sqlite()

    # Day 5 — start two threads
    # daemon=True means the thread dies automatically
    # when the main program exits (Ctrl+C)
    t1 = threading.Thread(target=capture_packets, daemon=True)
    t2 = threading.Thread(target=analyze_packets, daemon=True)

    t1.start()
    t2.start()

    try:
        # Keep main thread alive — just wait for both threads
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print(f"\n\nStopped. {packet_count} packets | "
              f"{len(alert_log)} alerts this session")
        show_saved_alerts()
        print(f"\nAlerts saved to: {CSV_FILE} and {DB_FILE}")
