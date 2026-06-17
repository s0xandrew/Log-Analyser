# 🛡️ Log Analyzer & Intrusion Detection System

A Python-based IDS that parses web server logs and automatically 
detects brute force attacks, directory scanning, suspicious paths, 
and known malicious IPs.

Built as part of my self-taught cybersecurity sprint for
IIT Kanpur B.Cyber application (Wadhwani School of AI and Intelligent Systems).

---

## ⚡ Features

- **Brute Force Detection** — Flags IPs exceeding failed login threshold
- **Path Scanning Detection** — Detects directory enumeration attempts
- **Suspicious Path Alerts** — Monitors for admin panels, config files, shells
- **Threat Intelligence** — Cross-references IPs against known bad IP list
- **IP Activity Summary** — Full table of all IPs with request counts and status
- **Threat Report** — Saves complete analysis to `threat_report.txt`

---

## 🛠️ Setup & Installation

**Requirements:** Python 3.x (zero external libraries)

```bash
# Clone the repository
git clone https://github.com/s0xandrew/log-analyzer.git
cd log-analyzer

# Run the analyzer
python log_analyzer.py
```

---

## 📸 Sample Output
LOG ANALYZER & INTRUSION DETECTION SYSTEM

By Sourabh (s0xandrew) | Ethical Use Only
[LOAD] Read 35 log lines from sample_logs.txt

[LOAD] Successfully parsed 35 entries
[MODULE 1] Brute Force Detection

🚨 ALERT: BRUTE FORCE detected from 45.33.32.156 — 7 failed logins

🚨 ALERT: BRUTE FORCE detected from 172.16.0.99 — 8 failed logins
[MODULE 2] Path Scanning Detection

🚨 ALERT: PATH SCANNING from 45.33.32.156 — probed 7 restricted paths

→ /admin

→ /wp-admin

→ /phpmyadmin

→ /shell.php

→ /.env
[MODULE 4] Threat Intelligence

🚨 ALERT: KNOWN MALICIOUS IP active: 45.33.32.156
IP ADDRESS           REQUESTS   FAILED LOGINS   STATUS

45.33.32.156         14         7               ⚠ SUSPICIOUS

172.16.0.99          8          8               ⚠ SUSPICIOUS

192.168.1.1          4          0               Normal
[THREAT SUMMARY]

Total unique IPs seen:  8

Total alerts raised:    13

---

## 🧠 How It Works

### Brute Force Detection
Counts HTTP 401 (Unauthorized) responses per IP address.
If an IP exceeds the threshold (default: 5 failed logins),
it triggers a brute force alert. Real attackers use tools
like Hydra and Medusa to attempt thousands of passwords/second.

### Path Scanning Detection
Tracks HTTP 403 (Forbidden) responses per IP. Multiple 403s
from the same IP indicate automated directory enumeration —
a recon technique used to find exposed admin panels,
backup files, and configuration files before exploiting them.

### Suspicious Path Monitoring
All requests are checked against a list of known sensitive paths
(/admin, /.env, /shell.php, /etc/passwd). Any access attempt
triggers an immediate alert regardless of response code.

### Threat Intelligence
IP addresses are cross-referenced against a known bad IP list.
Production IDS systems use live feeds from AbuseIPDB, Shodan,
and government threat intelligence platforms for this purpose.

---

## 🎯 Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute Force | 5+ failed logins from same IP | HIGH |
| Path Scanning | 3+ forbidden responses from same IP | HIGH |
| Suspicious Path | Request to known attack path | MEDIUM |
| Known Bad IP | IP matches threat intel list | CRITICAL |

---

## 📁 Project Structure
log-analyzer/

│

├── log_analyzer.py      # Main IDS engine

├── sample_logs.txt      # Sample web server logs for testing

├── threat_report.txt    # Auto-generated threat report

└── README.md            # This file
---

## ⚖️ Ethical Use Disclaimer

This tool is designed for:
- Analyzing logs from systems you own or administer
- Learning how intrusion detection systems work
- Educational cybersecurity demonstrations

Never use log analysis techniques to access or analyze
systems without authorization.

---

## 🔗 B.Cyber Relevance

| Concept | Maps To |
|---------|---------|
| Log parsing & analysis | SIEM fundamentals |
| Brute force detection | Authentication attack patterns |
| Path scanning detection | Web application recon techniques |
| Threat intelligence | IOC matching and threat hunting |
| Incident alerting | Blue team / SOC analyst workflow |
| Regex pattern matching | Log forensics and analysis |

---

## 👨‍💻 Author

**Sourabh (s0xandrew)**
Self-taught cybersecurity enthusiast | JEE Main 2026
Building towards IIT Kanpur B.Cyber (Wadhwani School of AI)

---

## 📚 What I Learned

- How web server logs are structured and parsed
- Brute force and directory scanning attack patterns
- Building detection rules from threat signatures
- Threat intelligence concepts and IP reputation
- Python: regex, defaultdict, file I/O, pattern matching
- Blue team mindset — detecting attacks from defender's view