from flask import Flask, jsonify
import os
import re

LOG_DIR = "/logs"

app = Flask(__name__)


def load_logs():
    """
    Read all log files from LOG_DIR and return a list of lines.
    """
    entries = []
    for root, _, files in os.walk(LOG_DIR):
        for f in files:
            path = os.path.join(root, f)
            try:
                with open(path, "r", errors="ignore") as fh:
                    for line in fh:
                        entries.append(line.strip())
            except Exception:
                # Ignore files we can't read
                continue
    return entries


def detect_nmap_scans(log_lines):
    """
    Detect IPs with a very high number of log entries.
    This is a simple heuristic for scanning or noisy enumeration.
    """
    alerts = []
    ip_counts = {}
    ip_regex = re.compile(r"(\d{1,3}\.){3}\d{1,3}")

    for line in log_lines:
        m = ip_regex.search(line)
        if m:
            ip = m.group(0)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for ip, count in ip_counts.items():
        if count > 50:  # Threshold for "suspicious" volume
            alerts.append({
                "type": "POTENTIAL_PORT_OR_WEB_SCAN",
                "source_ip": ip,
                "event_count": count,
                "description": f"High number of hits from {ip}, possible scan or enumeration."
            })

    return alerts


def detect_repeated_404s(log_lines):
    """
    Detect repeated 404 errors from the same IP.
    Indicates scanning, directory busting, or probing for hidden files.
    """
    alerts = []
    ip_counts = {}
    ip_regex = re.compile(r"(\d{1,3}\.){3}\d{1,3}")

    for line in log_lines:
        if " 404 " in line:  # Nginx logs include status code
            m = ip_regex.search(line)
            if m:
                ip = m.group(0)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for ip, count in ip_counts.items():
        if count > 20:  # Threshold for repeated 404s
            alerts.append({
                "type": "REPEATED_404_ERRORS",
                "source_ip": ip,
                "event_count": count,
                "description": f"{count} repeated 404 errors from {ip}. Possible scanning or directory brute force."
            })

    return alerts


@app.route("/")
def index():
    return jsonify({
        "message": "Log Analyzer API running. Go to /alerts to see detections."
    })


@app.route("/alerts")
def alerts():
    logs = load_logs()
    detections = []
    detections.extend(detect_nmap_scans(logs))
    detections.extend(detect_repeated_404s(logs))
    return jsonify(detections)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4100)


