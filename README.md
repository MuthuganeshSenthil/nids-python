# Python Network Intrusion Detection System (NIDS)

A lightweight NIDS built in Python using Scapy that captures
live network traffic and detects suspicious activity in real time.

Built on Kali Linux as a 10-day learning project.

## Features (in progress)

- [x] Live packet capture (TCP, UDP, ICMP)
- [x] Protocol filtering
- [x] Port scan detection (sliding time window)
- [x] Ping flood detection
- [x] Blacklisted IP alerting
- [x] Brute force detection
- [x] Alert logging to CSV and SQLite
- [ ] Tkinter live dashboard

## Tech Stack

- Python 3
- Scapy (packet capture)
- SQLite (logging, coming Day 6)
- Tkinter (dashboard, coming Day 9)

## How to run

```bash
# Requires root for raw packet capture
sudo python3 nids.py
```

## How it works

Each packet passes through a filter, then three detectors.
Detection uses a sliding time window — only events in the
last N seconds are counted, which avoids false positives
from slow background traffic.

## Project status

Day 4 of 10 complete. Actively being built.

## What I learned

- How TCP/UDP/ICMP packets are structured
- How Scapy captures raw network traffic
- Sliding window algorithm for rate-based detection
- Real network traffic: DHCP, DNS, SSDP, mDNS
- Why real NIDS tools like Snort use C (performance ceiling of Python)

## Author

MUTHUGANESH S — built while learning networking and cybersecurity
