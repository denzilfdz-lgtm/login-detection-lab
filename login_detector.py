threshold = 3
failed_counts = {}

with open("sample_auth.log", "r") as file:
    for line in file:
        line = line.strip()

        if not line:
            continue

        parts = line.split(",")

        if len(parts) != 2:
            print("Skipping invalid record:", line)
            continue

        username, status = parts
        username = username.strip()
        status = status.strip().upper()

        if status == "FAIL":
            failed_counts[username] = (
                failed_counts.get(username, 0) + 1
            )

print("\n--- Login Security Report ---")

for username, count in failed_counts.items():
    if count >= threshold:
        print(f"ALERT: {username} had {count} failed logins")
    else:
        print(f"INFO: {username} had {count} failed logins")
