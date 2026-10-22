from datetime import datetime, timedelta
from collections import defaultdict, deque

LOG_FILE = "sample_auth_v3.log"
WINDOW = timedelta(minutes=2)
THRESHOLD = 3
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Store failed events separately for each source IP.
failed_by_ip = defaultdict(deque)

with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):
        line = line.strip()

        if not line:
            continue

        parts = line.split(",")

        if len(parts) != 4:
            print(f"Skipping malformed line {line_number}")
            continue

        timestamp_text, username, ip, status = [
            part.strip() for part in parts
        ]

        try:
            timestamp = datetime.strptime(
                timestamp_text, TIME_FORMAT
            )
        except ValueError:
            print(f"Skipping invalid timestamp on line {line_number}")
            continue

        if not username or not ip:
            print(f"Skipping missing field on line {line_number}")
            continue

        status = status.upper()

        if status != "FAIL":
            continue

        events = failed_by_ip[ip]

        # Remove failures outside the rolling window.
        while events and timestamp - events[0] > WINDOW:
            events.popleft()

        # Record the current failure.
        events.append(timestamp)

        # Alert when the rolling count reaches the threshold.
        if len(events) == THRESHOLD:
            start = events[0].strftime(TIME_FORMAT)
            end = timestamp.strftime(TIME_FORMAT)

            print(
                f"ALERT: IP={ip} | "
                f"Failures={len(events)} | "
                f"Window={start} to {end}"
            )
