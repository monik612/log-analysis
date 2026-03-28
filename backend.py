"""
Log Analyzer — Flask Backend
Run:  python backend.py
Open: http://localhost:5000
"""

import re
import json
from collections import defaultdict
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
import os

app = Flask(__name__, static_folder="static")

# ── Trusted subnets ────────────────────────────────────────────────────────────
TRUSTED_SUBNETS = ["10.0.0.", "192.168.1.", "127.0.0."]
BRUTE_THRESHOLD = 5

# ── Sample log (used when no file is uploaded) ─────────────────────────────────
SAMPLE_LOG = """\
Jan 10 08:12:01 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:12:04 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:12:07 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:12:10 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:12:13 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:12:16 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:15:00 server sshd[1235]: Accepted password for alice from 10.0.0.5 port 52341 ssh2
Jan 10 08:20:01 server sshd[1236]: Failed password for admin from 203.0.113.42 port 22 ssh2
Jan 10 08:20:04 server sshd[1236]: Failed password for admin from 203.0.113.42 port 22 ssh2
Jan 10 08:20:07 server sshd[1236]: Failed password for admin from 203.0.113.42 port 22 ssh2
Jan 10 08:22:00 server sshd[1237]: Accepted password for bob from 10.0.0.8 port 52400 ssh2
Jan 10 09:00:01 server sshd[1238]: Failed password for root from 45.33.32.156 port 22 ssh2
Jan 10 09:00:04 server sshd[1238]: Failed password for root from 45.33.32.156 port 22 ssh2
Jan 10 09:00:07 server sshd[1238]: Failed password for root from 45.33.32.156 port 22 ssh2
Jan 10 09:00:10 server sshd[1238]: Failed password for root from 45.33.32.156 port 22 ssh2
Jan 10 09:00:13 server sshd[1238]: Failed password for root from 45.33.32.156 port 22 ssh2
Jan 10 09:05:00 server sshd[1239]: Accepted password for charlie from 192.168.1.20 port 53000 ssh2
Jan 10 10:01:00 server sshd[1240]: Failed password for nobody from 198.51.100.77 port 22 ssh2
Jan 10 10:01:03 server sshd[1240]: Failed password for nobody from 198.51.100.77 port 22 ssh2
Jan 10 10:01:06 server sshd[1240]: Failed password for nobody from 198.51.100.77 port 22 ssh2
Jan 10 10:01:09 server sshd[1240]: Failed password for nobody from 198.51.100.77 port 22 ssh2
Jan 10 10:01:12 server sshd[1240]: Failed password for nobody from 198.51.100.77 port 22 ssh2
Jan 10 10:01:15 server sshd[1240]: Failed password for nobody from 198.51.100.77 port 22 ssh2
Jan 10 10:01:18 server sshd[1240]: Failed password for nobody from 198.51.100.77 port 22 ssh2
Jan 10 10:01:21 server sshd[1240]: Failed password for nobody from 198.51.100.77 port 22 ssh2
Jan 10 10:30:00 server sshd[1241]: Accepted password for dave from 10.0.0.15 port 54000 ssh2
Jan 10 11:00:01 server sshd[1242]: Failed password for root from 172.16.0.99 port 22 ssh2
Jan 10 11:00:04 server sshd[1242]: Failed password for root from 172.16.0.99 port 22 ssh2
"""

# ── Core analysis functions ───────────────────────────────────────────────────

def is_external(ip):
    return not any(ip.startswith(p) for p in TRUSTED_SUBNETS)


def parse_logs(text):
    pattern = re.compile(
        r"(\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"(Failed password|Accepted password) for (\S+) from ([\d.]+)"
    )
    records = []
    for line in text.strip().splitlines():
        m = pattern.search(line)
        if m:
            records.append({
                "timestamp": m.group(1),
                "status":    "failed" if "Failed" in m.group(2) else "success",
                "user":      m.group(3),
                "ip":        m.group(4),
                "external":  is_external(m.group(4)),
            })
    return records


def detect_brute_force(records):
    counter = defaultdict(lambda: {"count": 0, "users": set()})
    for r in records:
        if r["status"] == "failed":
            counter[r["ip"]]["count"] += 1
            counter[r["ip"]]["users"].add(r["user"])

    alerts = []
    for ip, d in counter.items():
        if d["count"] >= BRUTE_THRESHOLD:
            count = d["count"]
            sev = "CRITICAL" if count >= 8 else "HIGH" if count >= 5 else "MEDIUM"
            alerts.append({
                "type": "BRUTE_FORCE",
                "ip": ip,
                "count": count,
                "users": sorted(d["users"]),
                "external": is_external(ip),
                "severity": sev,
            })
    return sorted(alerts, key=lambda x: x["count"], reverse=True)


def detect_unusual_ips(records):
    seen = {}
    for r in records:
        ip = r["ip"]
        if not is_external(ip):
            continue
        if ip not in seen:
            seen[ip] = {"ip": ip, "failed": 0, "success": 0, "users": set()}
        if r["status"] == "failed":
            seen[ip]["failed"] += 1
        else:
            seen[ip]["success"] += 1
        seen[ip]["users"].add(r["user"])

    result = []
    for ip, d in seen.items():
        result.append(
            "type": "UNUSUAL_IP",
            "ip": ip,
            "failed": d["failed"],
            "success": d["success"],
            "users": sorted(d["users"]),
            "warning": d["success"] > 0,
        })
    return sorted(result, key=lambda x: x["failed"], reverse=True)


def analyze(text):
    records     = parse_logs(text)
    brute       = detect_brute_force(records)
    unusual     = detect_unusual_ips(records)
    total_f     = sum(1 for r in records if r["status"] == "failed")
    total_s     = sum(1 for r in records if r["status"] == "success")
    unique_ips  = len({r["ip"] for r in records})
    return {
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_lines":        len(records),
            "total_failed":       total_f,
            "total_success":      total_s,
            "unique_ips":         unique_ips,
            "brute_force_count":  len(brute),
            "unusual_ip_count":   len(unusual),
        },
        "logs":                   records,
        "brute_force_alerts":     brute,
        "unusual_ip_alerts":      unusual,
    }

# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/api/analyze/sample", methods=["GET"])
def analyze_sample():
    return jsonify(analyze(SAMPLE_LOG))


@app.route("/api/analyze/upload", methods=["POST"])
def analyze_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    text = f.read().decode("utf-8", errors="ignore")
    if not text.strip():
        return jsonify({"error": "File is empty"}), 400
    return jsonify(analyze(text))


@app.route("/api/analyze/text", methods=["POST"])
def analyze_text():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "No log text provided"}), 400
    return jsonify(analyze(text))

# ── Serve frontend ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    os.makedirs("static", exist_ok=True)
    print("\n  Log Analyzer running → http://localhost:5000\n")
    app.run(debug=True, port=5000)
