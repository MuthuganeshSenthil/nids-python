# reporter.py

# Day 7 — Query and report from saved logs

# Run with: python3 reporter.py  (no sudo needed)



import sqlite3

import csv

from datetime import datetime

from collections import Counter



DB_FILE  = "nids.db"

CSV_FILE = "alerts.csv"



# ─── DATABASE QUERIES ─────────────────────────────────────────



def get_all_alerts():

    """Fetch every alert from SQLite, newest first."""

    conn   = sqlite3.connect(DB_FILE)

    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")

    rows   = cursor.fetchall()

    conn.close()

    return rows



def get_alerts_by_type(alert_type):

    """

    Fetch only alerts of a specific type.

    e.g. get_alerts_by_type("PORT_SCAN")

    The LIKE operator with % is SQL wildcard matching —

    so "PORT%" would match PORT_SCAN, PORT_ANYTHING etc.

    """

    conn   = sqlite3.connect(DB_FILE)

    cursor = conn.cursor()

    cursor.execute(

        "SELECT * FROM alerts WHERE type = ? ORDER BY id DESC",

        (alert_type,)

    )

    rows = cursor.fetchall()

    conn.close()

    return rows



def get_alerts_by_ip(ip_address):

    """Fetch all alerts where this IP was the source."""

    conn   = sqlite3.connect(DB_FILE)

    cursor = conn.cursor()

    cursor.execute(

        "SELECT * FROM alerts WHERE src_ip = ? ORDER BY id DESC",

        (ip_address,)

    )

    rows = cursor.fetchall()

    conn.close()

    return rows



def get_top_attackers(limit=5):

    """

    Use SQL COUNT + GROUP BY to find which IPs triggered

    the most alerts. This is a real SQL aggregation query —

    the same kind used in SIEM tools like Splunk.

    """

    conn   = sqlite3.connect(DB_FILE)

    cursor = conn.cursor()

    cursor.execute("""

        SELECT src_ip, COUNT(*) as alert_count

        FROM alerts

        GROUP BY src_ip

        ORDER BY alert_count DESC

        LIMIT ?

    """, (limit,))

    rows = cursor.fetchall()

    conn.close()

    return rows



def get_alert_type_counts():

    """Count how many of each alert type exist in the database."""

    conn   = sqlite3.connect(DB_FILE)

    cursor = conn.cursor()

    cursor.execute("""

        SELECT type, COUNT(*) as count

        FROM alerts

        GROUP BY type

        ORDER BY count DESC

    """)

    rows = cursor.fetchall()

    conn.close()

    return rows



# ─── DISPLAY FUNCTIONS ────────────────────────────────────────



def print_header(title):

    print("\n" + "=" * 60)

    print(f"  {title}")

    print("=" * 60)



def print_alerts(rows):

    if not rows:

        print("  No alerts found.")

        return

    for row in rows:

        # row = (id, timestamp, type, src_ip, detail)

        print(f"  [{row[1]}] {row[2]:<16} | {row[3]:<18} | {row[4]}")



def show_full_summary():

    """

    Master summary — shows everything useful at a glance.

    This is what you'd show in a demo or interview.

    """

    all_alerts = get_all_alerts()



    print_header("NIDS FULL REPORT")

    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print(f"  Database  : {DB_FILE}")

    print(f"  Total alerts in database: {len(all_alerts)}")



    # Alert type breakdown

    print_header("ALERT TYPE BREAKDOWN")

    type_counts = get_alert_type_counts()

    if not type_counts:

        print("  No alerts yet.")

    for row in type_counts:

        bar = "█" * min(row[1], 40)   # Visual bar, max 40 chars

        print(f"  {row[0]:<20} {row[1]:>4}  {bar}")



    # Top attackers

    print_header("TOP SOURCE IPs (most alerts)")

    attackers = get_top_attackers()

    if not attackers:

        print("  No data yet.")

    for ip, count in attackers:

        print(f"  {ip:<20} {count} alerts")



    # Recent alerts

    print_header("10 MOST RECENT ALERTS")

    recent = all_alerts[:10]

    print_alerts(recent)



def export_report():

    """

    Write a plain text report file — useful for attaching

    to emails or keeping as evidence.

    """

    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    all_alerts = get_all_alerts()

    type_counts = get_alert_type_counts()

    attackers = get_top_attackers()



    with open(filename, "w") as f:

        f.write("NIDS SECURITY REPORT\n")

        f.write(f"Generated: {datetime.now()}\n")

        f.write(f"Total alerts: {len(all_alerts)}\n\n")



        f.write("ALERT TYPES\n")

        f.write("-" * 40 + "\n")

        for row in type_counts:

            f.write(f"{row[0]:<20} {row[1]} alerts\n")



        f.write("\nTOP ATTACKERS\n")

        f.write("-" * 40 + "\n")

        for ip, count in attackers:

            f.write(f"{ip:<20} {count} alerts\n")



        f.write("\nALL ALERTS\n")

        f.write("-" * 40 + "\n")

        for row in all_alerts:

            f.write(f"[{row[1]}] {row[2]} | {row[3]} | {row[4]}\n")



    print(f"\n  Report saved to: {filename}")

    return filename



# ─── INTERACTIVE MENU ─────────────────────────────────────────



def main():

    print("=" * 60)

    print("  NIDS Reporter — Day 7")

    print("=" * 60)



    while True:

        print("\n  What do you want to do?")

        print("  1. Full summary")

        print("  2. Search by alert type")

        print("  3. Search by IP address")

        print("  4. Export report to file")

        print("  5. Show raw CSV contents")

        print("  0. Exit")



        choice = input("\n  Enter choice: ").strip()



        if choice == "1":

            show_full_summary()



        elif choice == "2":

            print("\n  Types: PORT_SCAN, PING_FLOOD, BRUTE_FORCE, BLACKLISTED_IP")

            alert_type = input("  Enter type: ").strip().upper()

            rows = get_alerts_by_type(alert_type)

            print_header(f"ALERTS: {alert_type}")

            print_alerts(rows)



        elif choice == "3":

            ip = input("  Enter IP address: ").strip()

            rows = get_alerts_by_ip(ip)

            print_header(f"ALERTS FROM: {ip}")

            print_alerts(rows)



        elif choice == "4":

            export_report()



        elif choice == "5":

            print_header("RAW CSV CONTENTS")

            try:

                with open(CSV_FILE, "r") as f:

                    reader = csv.reader(f)

                    for row in reader:

                        print(f"  {row}")

            except FileNotFoundError:

                print(f"  {CSV_FILE} not found — run nids.py first")



        elif choice == "0":

            print("  Bye.")

            break



        else:

            print("  Invalid choice.")



if __name__ == "__main__":

    main()
