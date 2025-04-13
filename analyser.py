import os.path
import re
from collections import Counter
from datetime import datetime
from logger import LOG_FILE


def analyze_logs():
    if not os.path.exists(LOG_FILE):
        print("No logs yet. Run logger.py first.")
        return

    with open(LOG_FILE, "r") as f:
        logs = f.readlines()

    if not logs:
        print("No events to analyse.")
        return

    failed_attempts = [log for log in logs if "Failed Login" in log]
    successful_logins = [log for log in logs if "Successful login" in log]
    sudo_commands = [log for log in logs if "Sudo command" in log]

    print(f"Total failed attempts: {len(failed_attempts)}")
    print(f"Total successful logins: {len(successful_logins)}")
    print(f"Total sudo commands: {len(sudo_commands)}")

    # Extract usernames from failed login attempts
    usernames_failed = []
    ip_addresses = []
    for log in failed_attempts:
        parts = log.split()
        if "for" in parts:
            user_index = parts.index("for") + 1
            usernames_failed.append(parts[user_index])

        # Extract IP addresses
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", log)
        if ip_match:
            ip_addresses.append(ip_match.group(1))

    failed_counts = Counter(usernames_failed)
    ip_counts = Counter(ip_addresses)

    print("\nFailed attempts by user:")
    for user, count in failed_counts.items():
        print(f"{user}: {count}")
        if count > 3:
            print(f"ALERT!! Possible brute-force on {user}")

    print("\nFailed attempts by IP address:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")
        if count > 5:
            print(f"ALERT!! Possible network attack from {ip}")

    usernames_success = []
    for log in successful_logins:
        parts = log.split()
        if "for" in parts:
            user_index = parts.index("for") + 1
            usernames_success.append(parts[user_index])

    print("\nSuccessful logins by user:")
    for user in usernames_success:
        if user in failed_counts and failed_counts[user] > 3:
            print(
                f"ALERT!! {user} succeeded after {failed_counts[user]} fails - possible breach!"
            )

    # Analyze sudo commands
    if sudo_commands:
        print("\nSudo commands analysis:")
        for log in sudo_commands:
            timestamp = log.split(" - ")[0]
            cmd_match = re.search(r"COMMAND=(.+?)$", log)
            if cmd_match:
                command = cmd_match.group(1)
                print(f"{timestamp}: {command}")

    # Generate a summary report
    generate_report(
        failed_attempts, successful_logins, sudo_commands, failed_counts, ip_counts
    )


def generate_report(
    failed_attempts, successful_logins, sudo_commands, failed_counts, ip_counts
):
    """Generate a comprehensive security report."""
    report = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report.append(f"SECURITY ANALYSIS REPORT - {timestamp}")
    report.append("=" * 50)
    report.append(
        f"Total events analyzed: {len(failed_attempts) + len(successful_logins) + len(sudo_commands)}"
    )
    report.append(f"Failed logins: {len(failed_attempts)}")
    report.append(f"Successful logins: {len(successful_logins)}")
    report.append(f"Sudo commands: {len(sudo_commands)}")
    report.append("=" * 50)

    # High-risk users (multiple failed attempts)
    high_risk = {user: count for user, count in failed_counts.items() if count > 3}
    if high_risk:
        report.append("\nHIGH RISK ACCOUNTS:")
        for user, count in high_risk.items():
            report.append(f"- {user}: {count} failed attempts")

    # Suspicious IPs
    suspicious_ips = {ip: count for ip, count in ip_counts.items() if count > 5}
    if suspicious_ips:
        report.append("\nSUSPICIOUS IP ADDRESSES:")
        for ip, count in suspicious_ips.items():
            report.append(f"- {ip}: {count} failed attempts")

    # Potential breaches
    breaches = []
    for log in successful_logins:
        parts = log.split()
        if "for" in parts:
            user_index = parts.index("for") + 1
            username = parts[user_index]
            if username in failed_counts and failed_counts[username] > 3:
                breaches.append((username, failed_counts[username]))

    if breaches:
        report.append("\nPOTENTIAL SECURITY BREACHES:")
        for user, fails in breaches:
            report.append(f"- {user}: Successful login after {fails} failed attempts")

    # Write report to file
    with open("security_report.txt", "w") as f:
        f.write("\n".join(report))

    print("\nReport saved to security_report.txt")


if __name__ == "__main__":
    analyze_logs()
