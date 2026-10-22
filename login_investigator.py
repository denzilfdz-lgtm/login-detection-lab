
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta

LOG_FILE = "sample_investigation.csv"
REPORT_FILE = "investigation_report.txt"
WINDOW = timedelta(minutes=10)
RISK_THRESHOLD = 3
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def investigate(lines):
    events = []
    alerts = []
    reader = csv.DictReader(lines)

    required = {"timestamp", "username", "ip", "status"}
    if not reader.fieldnames or not required.issubset(
        set(reader.fieldnames)
    ):
        return alerts

    for row in reader:
        try:
            timestamp = datetime.strptime(
                row["timestamp"].strip(), TIME_FORMAT
            )
            username = row["username"].strip()
            ip = row["ip"].strip()
            status = row["status"].strip().upper()
        except (ValueError, AttributeError, KeyError):
            continue

        if not username or not ip:
            continue
        if status not in {"FAIL", "SUCCESS"}:
            continue

        events.append((timestamp, username, ip, status))

    events.sort(key=lambda event: event[0])
    failures_by_ip = defaultdict(deque)

    for timestamp, username, ip, status in events:
        recent = failures_by_ip[ip]

        while recent and timestamp - recent[0] > WINDOW:
            recent.popleft()

        if status == "FAIL":
            recent.append(timestamp)
            continue

        failure_count = len(recent)
        risk = 0
        reasons = []

        if failure_count >= 2:
            risk += 2
            reasons.append(f"{failure_count} recent failed logins")

        if failure_count >= 1:
            risk += 2
            reasons.append("success after failed login")

        if timestamp.hour >= 22 or timestamp.hour < 6:
            risk += 1
            reasons.append("outside configured working hours")

        if risk >= RISK_THRESHOLD:
            alerts.append({
                "time": timestamp,
                "username": username,
                "ip": ip,
                "risk": risk,
                "reasons": reasons,
            })

    return alerts


def main():
    with open(LOG_FILE, newline="", encoding="utf-8") as file:
        alerts = investigate(file)

    report = ["--- Login Investigation Report ---", ""]

    if not alerts:
        report.append("No events met the risk threshold.")
    else:
        for alert in alerts:
            report.extend([
                f"ALERT | Risk: {alert['risk']} | "
                f"User: {alert['username']} | IP: {alert['ip']}",
                f"Time: {alert['time']}",
                "Reasons: " + "; ".join(alert["reasons"]),
                "",
            ])

    output = "\n".join(report)

    print(output)
    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write(output + "\n")

    print(f"\nReport saved to {REPORT_FILE}")


if __name__ == "__main__":
    main()
