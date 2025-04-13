import os.path
from collections import Counter
from base64 import b64decode
from logger import LOG_FILE, KEY

def analyze_logs():
    if not os.path.exists(LOG_FILE):
        print("No logs yet. Run logger.py first.")
        return

    with open(LOG_FILE, "r") as f:
        encrypted_logs = f.readlines()

    logs = [b64decode(log.strip()).decode()[:-len(KEY)] for log in encrypted_logs]

    if not logs:
        print("No events to analyse.")
        return

    failed_attempts = [log for log in logs if "Failed Login" in log]
    successful_logins = [log for log in logs if "Successful login" in log]
    sudo_commands = [log for log in logs if "Sudo command" in log]

    print(f"Total failed attempts: {len(failed_attempts)}")
    print(f"Total successful logins: {len(successful_logins)}")
    print(f"Total sudo commands: {len(sudo_commands)}")

    usernames_failed = []
    for log in failed_attempts:
        parts = log.split()
        if "for" in parts:
            user_index = parts.index("for") + 1
            usernames_failed.append(parts[user_index])

    failed_counts = Counter(usernames_failed)
    print("\nFailed attempts by user:")
    for user, count in failed_counts.items():
        print(f"{user}: {count}")
        if count > 3:
            print(f"ALERT!! Possible brute-force on {user}")

    usernames_success = []
    for log in successful_logins:
        parts = log.split()
        if "for" in parts:
            user_index = parts.index("for") + 1
            usernames_success.append(parts[user_index])

    print("\nSuccessful logins by user:")
    for user in usernames_success:
        if user in failed_counts and failed_counts[user] > 3:
            print(f"ALERT!! {user} succeeded after {failed_counts[user]} fails - possible breach!")

if __name__ == "__main__":
    analyze_logs()

