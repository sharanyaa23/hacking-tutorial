
"""
ids_probe.py — tiny IDS probe (single-file, educational)

Purpose:
--------
A simple Intrusion Detection System (IDS) probe built using Scapy.  
It monitors live network traffic and raises alerts for:
  1. Port scans (many SYN packets to different ports in a short time).
  2. Suspicious plain HTTP requests (based on User-Agent keywords).

Output:
--------
Alerts are written as newline-separated JSON objects into 'alerts.json'.  
Optionally, alerts can also be POSTed to a webhook URL.

⚠️ Run this only on systems/networks you own or have permission to monitor.
"""



from __future__ import annotations
import os
import time
import json
import argparse
from collections import defaultdict, deque
from datetime import datetime
import threading
from scapy.layers.inet6 import IPv6


# Try importing Scapy (used for packet sniffing)
try:
    from scapy.all import sniff, IP, TCP, Raw
except Exception as exc:
    raise SystemExit(
        "Scapy is required. Install it with: pip install scapy\n"
        f"Import error: {exc}"
    )

# Optional dependency for webhook support
try:
    import requests
except Exception:
    requests = None

# ---------------------- CONFIGURATION ----------------------

# File where alerts will be saved
ALERT_FILE = os.path.join(os.path.dirname(__file__), "alerts.json")

# Port scan detection parameters
PORT_SCAN_WINDOW = 10          # seconds of observation
PORT_SCAN_PORT_THRESHOLD = 12  # unique ports within window to trigger alert

# Suspicious keywords to flag in HTTP User-Agent strings
SUSPICIOUS_UA_KEYWORDS = ["sqlmap", "nikto", "acunetix", "curl", "wget", "fuzzer", "scanner"]

# Optional webhook URL (set from CLI)
WEBHOOK: str | None = None

# Runtime data structures
# Stores for each source IP → list of (timestamp, dst_port)
syn_history = defaultdict(lambda: deque())
file_lock = threading.Lock()  # prevents concurrent writes to alerts.json

# ------------------------------------------------------------

def now_iso() -> str:
    """Return current UTC time in ISO 8601 format (used for timestamps)."""
    return datetime.utcnow().isoformat() + "Z"


def write_alert(alert: dict) -> None:
    """
    Save an alert to the 'alerts.json' file and optionally send it to a webhook.

    Each alert is a single JSON object on its own line.
    The file is appended (not overwritten), so old alerts are preserved.
    """
    alert["detected_at"] = now_iso()
    line = json.dumps(alert, ensure_ascii=False)
    
    # Thread-safe file writing
    with file_lock:
        os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
        with open(ALERT_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    # Print a short console summary
    print("[ALERT]", alert.get("type"), "-", alert.get("summary", ""))

    # If webhook configured, try to send alert
    if WEBHOOK and requests:
        try:
            requests.post(WEBHOOK, json=alert, timeout=3)
        except Exception:
            pass


def check_port_scan(pkt_time: float, src_ip: str, dst_port: int) -> None:
    """
    Detect potential port scans.

    - Keeps a deque of recent SYN packets per source IP.
    - If the number of distinct destination ports exceeds a threshold
      within a time window, it raises a 'port_scan' alert.
    """
    dq = syn_history[src_ip]
    dq.append((pkt_time, dst_port))

    # Remove old entries outside the time window
    cutoff = pkt_time - PORT_SCAN_WINDOW
    while dq and dq[0][0] < cutoff:
        dq.popleft()

    # Count unique destination ports in the current window
    distinct_ports = {p for _, p in dq}

    # If threshold exceeded, trigger alert
    if len(distinct_ports) >= PORT_SCAN_PORT_THRESHOLD:
        alert = {
            "type": "port_scan",
            "summary": f"Possible port scan from {src_ip} to {len(distinct_ports)} ports",
            "src_ip": src_ip,
            "unique_ports": sorted(distinct_ports),
            "count": len(distinct_ports),
            "window_seconds": PORT_SCAN_WINDOW,
        }
        dq.clear()  # Reset history to avoid duplicate alerts
        write_alert(alert)


def extract_user_agent(payload_bytes: bytes) -> str | None:
    """
    Extract the 'User-Agent' value from an HTTP request payload, if present.

    - Only works for unencrypted (plain HTTP) traffic.
    - Scans the decoded payload for a line starting with 'User-Agent:'.
    """
    try:
        txt = payload_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None

    for line in txt.splitlines():
        if line.lower().startswith("user-agent:"):
            return line.split(":", 1)[1].strip()
    return None


def check_http_user_agent(payload: bytes, src_ip: str, dst_ip: str, dst_port: int) -> None:
    """
    Check if the HTTP payload contains a suspicious User-Agent header.

    If any keyword from SUSPICIOUS_UA_KEYWORDS is found inside the
    'User-Agent' value, a 'suspicious_user_agent' alert is written.
    """
    ua = extract_user_agent(payload)
    if not ua:
        return

    ua_lower = ua.lower()
    for key in SUSPICIOUS_UA_KEYWORDS:
        if key in ua_lower:
            alert = {
                "type": "suspicious_user_agent",
                "summary": f"Suspicious User-Agent '{ua[:80]}' from {src_ip}",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "user_agent": ua,
            }
            write_alert(alert)
            return


def packet_handler(pkt) -> None:
    """Callback invoked by scapy.sniff for each captured packet.

    Support both IPv4 and IPv6. For IPv6, use IPv6 layer instead of IP.
    For both families, extract TCP, detect SYN (client->server SYN w/o ACK),
    and inspect Raw payloads for HTTP User-Agent.
    """
    ts = time.time()

    def _process(ip_layer, tcp_layer, src_ip, dst_ip):
        # SYN without ACK -> client initial SYN (avoid counting SYN-ACK responses)
        try:
            flags = int(tcp_layer.flags)
        except Exception:
            flags = 0
        syn_only = (flags & 0x02) and not (flags & 0x10)
        if syn_only:
            try:
                dst_port = int(tcp_layer.dport)
            except Exception:
                return
            check_port_scan(ts, src_ip, dst_port)

        # If there is application payload, check for HTTP User-Agent header
        if Raw in pkt:
            try:
                payload_bytes = bytes(pkt[Raw].load)
            except Exception:
                payload_bytes = b""
            try:
                dst_port = int(tcp_layer.dport)
            except Exception:
                dst_port = None
            check_http_user_agent(payload_bytes, src_ip, dst_ip, dst_port)

    # IPv4 case
    if IP in pkt and TCP in pkt:
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        _process(ip_layer, tcp_layer, src_ip, dst_ip)
        return

    # IPv6 case (this also catches IPv6-mapped IPv4 addresses)
    if IPv6 in pkt and TCP in pkt:
        ip6 = pkt[IPv6]
        tcp_layer = pkt[TCP]
        src_ip = ip6.src
        dst_ip = ip6.dst
        # If dst/src are IPv4-mapped (::ffff:1.2.3.4), normalize to plain IPv4 string
        if src_ip.startswith("::ffff:"):
            src_ip = src_ip.split("::ffff:")[-1]
        if dst_ip.startswith("::ffff:"):
            dst_ip = dst_ip.split("::ffff:")[-1]
        _process(ip6, tcp_layer, src_ip, dst_ip)
        return

    # otherwise ignore non-TCP or non-IP packets
    return


def parse_args():
    """
    Parse command-line arguments for interface selection and thresholds.
    """
    p = argparse.ArgumentParser(description="Tiny IDS probe - sniff packets and emit simple alerts")
    p.add_argument("-i", "--iface", default=None, help="Interface to sniff (e.g., eth0, wlan0, etc.)")
    p.add_argument("--webhook", default=None, help="Optional: webhook URL to POST alerts")
    p.add_argument("--port-threshold", type=int, default=PORT_SCAN_PORT_THRESHOLD,
                   help="Number of unique ports to trigger port-scan alert")
    p.add_argument("--window", type=int, default=PORT_SCAN_WINDOW,
                   help="Time window (in seconds) for port-scan detection")
    return p.parse_args()


def main() -> None:
    """
    Entry point of the program.

    - Parses CLI arguments.
    - Configures thresholds and webhook.
    - Starts live packet sniffing.
    """
    global WEBHOOK, PORT_SCAN_PORT_THRESHOLD, PORT_SCAN_WINDOW

    args = parse_args()
    WEBHOOK = args.webhook
    PORT_SCAN_PORT_THRESHOLD = args.port_threshold
    PORT_SCAN_WINDOW = args.window

    print(f"Starting tiny IDS probe. Alerts will be written to: {ALERT_FILE}")
    print("Press Ctrl+C to stop. Run only on networks you own or are authorized to monitor.")

    try:
        sniff(iface=args.iface, prn=packet_handler, store=False)
    except PermissionError:
        print("Permission denied: run as root / Administrator.")
    except Exception as e:
        print("Error while sniffing:", e)


if __name__ == "__main__":
    main()
