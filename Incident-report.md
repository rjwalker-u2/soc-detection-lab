🛑 INCIDENT REPORT — Web Server Scan & Enumeration

Environment: Docker-Based SOC Detection Lab
Analyst: RJ Walker
Date: 12/1/2025

🔎 1. Executive Summary

On DATE, the detection engine identified a large volume of HTTP requests and a port scan originating from the internal IP address 172.23.0.2, associated with the attacker container in the SOC lab environment.

The activity included:

A stealth SYN scan (nmap -sS)

High-volume HTTP enumeration (200+ requests)

This behavior is consistent with Active Scanning and Web/Port Enumeration, categorized under MITRE ATT&CK T1046 and T1595.

The activity was detected by the custom Python/Flask SIEM service, which raised a “POTENTIAL_PORT_OR_WEB_SCAN” alert.

📁 2. Indicators of Compromise (IOCs)
Type	Value	Notes
Source IP	172.23.0.2	Attacker container
Target Service	Nginx Web Server (target-web)	Victim
Event Count	200+ HTTP hits	Excessive enumeration
Scan Type	SYN scan (-sS)	Likely reconnaissance
🧠 3. MITRE ATT&CK Mapping
Technique	ID	Description
Network Service Scanning	T1046	Port scanning to identify open services
Active Scanning	T1595	Probing infrastructure for weaknesses
Web Service Enumeration	T1046 / T1589	High-volume HTTP requests for information discovery
📝 4. Timeline of Events
Timestamp (approx.)	Event
T0	Attacker container launched
T1	Port scan executed using nmap -sS target-web
T2	~200 HTTP requests sent using automated curl loop
T3	Log-analyzer API identifies excessive hits
T4	Alert created and exposed at /alerts endpoint
🧪 5. Log Evidence (Sample Nginx Log Entries)
172.23.0.2 - - [XX/XXX/2025:HH:MM:SS] "GET / HTTP/1.1" 200 612 "-" "curl/7.74.0"
172.23.0.2 - - [XX/XXX/2025:HH:MM:SS] "GET / HTTP/1.1" 200 612 "-" "curl/7.74.0"
...
(Repeated over 200 times)


Analysis:
Repeated identical requests from the same IP within a short window strongly suggest automated enumeration or scanning.

🚨 6. Detection Details

Alert generated:

{
  "type": "POTENTIAL_PORT_OR_WEB_SCAN",
  "source_ip": "172.23.0.2",
  "event_count": 200,
  "description": "High number of hits from 172.23.0.2, possible scan or enumeration."
}


The detection logic is based on:

Counting repeated IP appearances

Threshold > 50 events triggers alert

🛠️ 7. Recommended Mitigations

Short-Term:

Apply rate limiting on web endpoints

Block or throttle suspicious IP addresses

Review Nginx access logs for anomalies

Long-Term:

Enable Web Application Firewall (WAF) rules

Implement IDS/IPS signatures for scan detection

Add user-agent anomaly detection

Introduce authentication / MFA for sensitive endpoints

📚 8. Conclusion

This simulated incident demonstrates the effectiveness of basic log analysis and detection engineering techniques. The environment successfully detected high-volume scanning and enumeration attempts, mapping them to industry frameworks and logging them centrally.

This report showcases SOC analysis skills including:

Detection interpretation

IoC extraction

MITRE mapping

Timeline reconstruction

Log analysis

Mitigation recommendations

✔️ END OF REPORT
