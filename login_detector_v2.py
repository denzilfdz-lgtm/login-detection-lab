
from collections import defaultdict, deque
from datetime import datetime, timedelta

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def detect_alerts(lines, threshold=3, window_seconds=120):
    events_by_ip = defaultdict(list)

    # Parse records and group failed logins by source IP.
    for line in lines:
        parts = line.strip().split(",")

        if len(parts) != 4:
            continue

        timestamp_text, username, ip, status = [
            part.strip() for part in parts
        ]

        try:
            timestamp = datetime.strptime(
                timestamp_text, TIME_FORMAT
            )
        except ValueError:
            continue

        if not username or not ip:
            continue

        if status.upper() == "FAIL":
            events_by_ip[ip].append((timestamp, username))

    alerts = []
    window_duration = timedelta(seconds=window_seconds)

    for ip, events in events_by_ip.items():
        # Sort chronologically, even if input records were out of order.
        events.sort(key=lambda event: event[0])
        recent = deque()

        for timestamp, username in events:
            # Keep events inside the rolling time window.
            while (
                recent
                and timestamp - recent[0][0] > window_duration
            ):
                recent.popleft()

            recent.append((timestamp, username))

            if len(recent) >= threshold:
                alerts.append({
                    "ip": ip,
                    "count": len(recent),
                    "start": recent[0][0],
                    "end": timestamp,
                })

                # One alert per IP for this detection run.
                break

    return sorted(alerts, key=lambda alert: alert["end"])


def main():
    with open("sample_auth_v3.log", encoding="utf-8") as file:
        alerts = detect_alerts(file)

    print("--- Login Security Report ---")

    if not alerts:
        print("No threshold breaches detected.")
        return

    for alert in alerts:
        print(
            f"ALERT: {alert['ip']} | "
            f"Failures: {alert['count']} | "
            f"From: {alert['start']} | "
            f"To: {alert['end']}"
        )


if __name__ == "__main__":
    main()
