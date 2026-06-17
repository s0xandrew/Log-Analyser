# ============================================================
# Log Analyzer & Intrusion Detection System (IDS)
# Author: Sourabh (s0xandrew)
# Detects: Brute force, directory traversal, suspicious scanning
# Ethical Use: Analyze logs from systems you own/administer
# ============================================================

import re                  # Pattern matching in log lines
import datetime            # Timestamps
from collections import defaultdict  # Auto-initializing dictionaries


# ── CONFIGURATION ────────────────────────────────────────────
LOG_FILE = "sample_logs.txt"
REPORT_FILE = "threat_report.txt"

# Thresholds for detection
BRUTE_FORCE_THRESHOLD = 5    # Failed logins from same IP = brute force
SCAN_THRESHOLD = 3           # 403 errors from same IP = directory scanning

# Suspicious paths attackers commonly probe
SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/shell.php",
    "/.env", "/config.php", "/etc/passwd", "/passwd",
    "/.git", "/backup", "/db.sql", "/login.php",
    "/manager", "/administrator", "/.htaccess",
]

# Known malicious IP ranges (simplified for demo)
KNOWN_BAD_IPS = [
    "45.33.32.156",   # Example — scanme.nmap.org (used in our scanner demo)
    "203.0.113.42",   # TEST-NET — RFC 5737 documentation range
]

# ── DATA STORAGE ─────────────────────────────────────────────
failed_logins = defaultdict(int)      # IP → count of failed logins
path_probes = defaultdict(list)       # IP → list of probed paths
ip_activity = defaultdict(list)       # IP → all log entries
error_counts = defaultdict(int)       # IP → count of errors
all_ips = set()                       # All unique IPs seen
findings = []                         # Report lines
alerts = []                           # High priority alerts


def log(message):
    """Print and store output."""
    print(message)
    findings.append(message)


def alert(message):
    """Print, store, and flag as high priority alert."""
    msg = f"🚨 ALERT: {message}"
    print(msg)
    findings.append(msg)
    alerts.append(msg)


# ── LOG PARSER ───────────────────────────────────────────────
def parse_log_line(line):
    """
    Parse a single log line into structured data.
    Log format: DATE TIME LEVEL IP METHOD PATH STATUS
    Example: 2026-06-17 08:02:01 WARNING 45.33.32.156 POST /login 401
    """
    # Regex pattern to extract each field
    pattern = r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+) ([\d.]+) (\w+) (\S+) (\d{3})'
    match = re.match(pattern, line.strip())

    if match:
        return {
            'date':    match.group(1),
            'time':    match.group(2),
            'level':   match.group(3),
            'ip':      match.group(4),
            'method':  match.group(5),
            'path':    match.group(6),
            'status':  int(match.group(7)),
        }
    return None


def load_logs(filepath):
    """
    Read and parse all log lines from file.
    Returns list of parsed log dictionaries.
    """
    parsed = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        log(f"[LOAD] Read {len(lines)} log lines from {filepath}")

        for line in lines:
            entry = parse_log_line(line)
            if entry:
                parsed.append(entry)

        log(f"[LOAD] Successfully parsed {len(parsed)} entries")
        return parsed

    except FileNotFoundError:
        log(f"[ERROR] Log file not found: {filepath}")
        return []


# ── ANALYSIS MODULES ─────────────────────────────────────────
def analyze_failed_logins(logs):
    """
    Brute Force Detection:
    Count failed login attempts (HTTP 401) per IP.
    If an IP fails login more than threshold times → brute force attack.
    
    Real attackers use tools like Hydra, Medusa to try
    thousands of passwords per second automatically.
    """
    log("\n[MODULE 1] Brute Force Detection")
    log("-" * 45)

    for entry in logs:
        # 401 = Unauthorized (wrong password)
        if entry['status'] == 401 and '/login' in entry['path']:
            failed_logins[entry['ip']] += 1

    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alert(f"BRUTE FORCE detected from {ip} — {count} failed logins")
        else:
            log(f"[INFO] {ip} had {count} failed login(s) — below threshold")


def analyze_path_scanning(logs):
    """
    Directory/Path Scanning Detection:
    Attackers probe common sensitive paths looking for
    exposed admin panels, config files, backup files.
    Multiple 403 (Forbidden) errors from same IP = scanning.
    """
    log("\n[MODULE 2] Path Scanning Detection")
    log("-" * 45)

    for entry in logs:
        # 403 = Forbidden (path exists but access denied)
        if entry['status'] == 403:
            error_counts[entry['ip']] += 1
            path_probes[entry['ip']].append(entry['path'])

    for ip, paths in path_probes.items():
        if len(paths) >= SCAN_THRESHOLD:
            alert(f"PATH SCANNING from {ip} — probed {len(paths)} restricted paths")
            for path in paths:
                log(f"    → {path}")


def analyze_suspicious_paths(logs):
    """
    Suspicious Path Detection:
    Check if any requests targeted known attack paths
    regardless of response code.
    """
    log("\n[MODULE 3] Suspicious Path Detection")
    log("-" * 45)

    found = False
    for entry in logs:
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in entry['path']:
                alert(f"SUSPICIOUS PATH: {entry['ip']} → {entry['path']} ({entry['status']})")
                found = True

    if not found:
        log("[INFO] No suspicious paths detected.")


def analyze_known_bad_ips(logs):
    """
    Known Bad IP Detection:
    Cross-reference IPs against threat intelligence list.
    Real IDS systems use feeds like AbuseIPDB, VirusTotal,
    Shodan, and government threat intel for this.
    """
    log("\n[MODULE 4] Threat Intelligence — Known Bad IPs")
    log("-" * 45)

    seen_bad = set()
    for entry in logs:
        if entry['ip'] in KNOWN_BAD_IPS and entry['ip'] not in seen_bad:
            alert(f"KNOWN MALICIOUS IP active: {entry['ip']}")
            seen_bad.add(entry['ip'])

    if not seen_bad:
        log("[INFO] No known malicious IPs detected in logs.")


def generate_ip_summary(logs):
    """
    IP Activity Summary:
    Show all unique IPs and their request counts.
    Useful for spotting unusually active IPs.
    """
    log("\n[MODULE 5] IP Activity Summary")
    log("-" * 45)

    ip_counts = defaultdict(int)
    for entry in logs:
        ip_counts[entry['ip']] += 1
        all_ips.add(entry['ip'])

    log(f"{'IP ADDRESS':<20} {'REQUESTS':<10} {'FAILED LOGINS':<15} {'STATUS'}")
    log(f"{'-'*20} {'-'*10} {'-'*15} {'-'*10}")

    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        fails = failed_logins.get(ip, 0)
        status = "⚠ SUSPICIOUS" if ip in KNOWN_BAD_IPS or fails >= BRUTE_FORCE_THRESHOLD else "Normal"
        log(f"{ip:<20} {count:<10} {fails:<15} {status}")


def generate_threat_summary():
    """Print final threat summary."""
    log(f"\n{'='*60}")
    log(f"[THREAT SUMMARY]")
    log(f"{'='*60}")
    log(f"  Total unique IPs seen:  {len(all_ips)}")
    log(f"  Total alerts raised:    {len(alerts)}")
    log(f"\n  High Priority Alerts:")

    if alerts:
        for a in alerts:
            log(f"    {a}")
    else:
        log("    None — logs appear clean.")


def save_report():
    """Save full report to file."""
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write("\n".join(findings))
    print(f"\n[REPORT] Saved to {REPORT_FILE}")


# ── MAIN ─────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("   LOG ANALYZER & INTRUSION DETECTION SYSTEM")
    print("   By Sourabh (s0xandrew) | Ethical Use Only")
    print(f"   Analyzing: {LOG_FILE}")
    print("=" * 60)

    log(f"\n[INFO] Analysis started: {datetime.datetime.now()}")

    # Load and parse logs
    logs = load_logs(LOG_FILE)
    if not logs:
        print("[ERROR] No logs to analyze.")
        return

    # Run all detection modules
    analyze_failed_logins(logs)
    analyze_path_scanning(logs)
    analyze_suspicious_paths(logs)
    analyze_known_bad_ips(logs)
    generate_ip_summary(logs)
    generate_threat_summary()

    log(f"\n[INFO] Analysis completed: {datetime.datetime.now()}")

    # Save report
    save_report()


if __name__ == "__main__":
    main()