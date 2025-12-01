# SOC Detection Lab (Docker-Based)

## Overview
This lab simulates a small SOC environment using Docker:

- `target-web`: Nginx web server acting as a victim
- `attacker`: Kali-based attacker container used to generate malicious traffic (nmap scans, repeated requests)
- `log-analyzer-api`: Python/Flask mini-SIEM that ingests Nginx logs from a shared volume and exposes detections via a JSON API

## Objectives
- Practice log collection and centralized analysis
- Build basic detection logic for web/port scans
- Understand how attacker behavior shows up in logs
- Document detections and map them to MITRE ATT&CK techniques

## Architecture
Attacker → Target → Logs → Detection:

- The `attacker` container sends nmap and curl traffic to `target-web`
- `target-web` writes access logs to `/var/log/nginx`
- Logs are shared via a Docker volume (`./nginx_logs`)
- `log-analyzer-api` reads the shared logs from `/logs`
- Detection logic identifies IPs with noisy activity and raises alerts on `/alerts`

## How to Run

```bash
# from the soc-detection-lab folder
docker compose up -d

# open the mini-SIEM API
http://localhost:4100/

# generate attack traffic
docker exec -it attacker /bin/bash
apt update && apt install -y nmap curl
nmap -sS target-web
for i in {1..200}; do curl http://target-web >/dev/null 2>&1; done
exit


