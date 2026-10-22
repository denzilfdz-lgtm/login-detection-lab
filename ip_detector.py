threshold = 3
failed_by_ip = {}
success_by_ip = {}

with open("sample_auth_v2.log", "r") as file:
    for line in file:
        line = line.strip()

        if not line:
            continue

        parts = line.split(",")

        if len(parts) != 3:
            print("Skipping invalid record:", line)
            continue

        username, ip, status = [
            part.strip() for part in parts
        ]

        status = status.upper()

        if not username or not ip:
            print("Skipping invalid record:", line)
            continue

        if status == "FAIL":
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
        elif status == "SUCCESS":
            success_by_ip[ip] = success_by_ip.get(ip, 0) + 1
        else:
            print("Skipping unknown status:", line)

print("\n--- IP Login Security Report ---")

for ip, count in failed_by_ip.items():
    successes = success_by_ip.get(ip, 0)

    if count >= threshold:
        print(
            f"ALERT: {ip} | Failed: {count} "
            f"| Successful: {successes}"
        )
    else:
        print(
            f"INFO: {ip} | Failed: {count} "
            f"| Successful: {successes}"
        )
