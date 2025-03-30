import time
import os
from base64 import b64encode

LOG_FILE = "security_log.txt"
KEY = b"simplekey"

def monitor_auth_log():
    auth_log_path = "/var/log/auth.log"
    if not os.path.exists(auth_log_path):
        print("Error: auth.log not found. Aren't you on Linux?")
        return

    print("Monitoring started... Press Ctrl+C to stop.")
    with open(auth_log_path, "r") as auth_file:
        auth_file.seek(0, os.SEEK_END)
        while True:
            line = auth_file.readline()
            if line:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                if "Failed password" in line:
                    event = f"{timestamp} - Suspicious: Failed Login - {line.strip()}"
                elif "Accepted password" in line:
                    event = f"{timestamp} - Notice: Successful login - {line.strip()}"
                elif "sudo: " in line and "COMMAND" in line:
                    event = f"{timestamp} - Warning: Sudo command executed - {line.strip()}"
                else:
                    continue
                print(event)
                save_event(event)
            time.sleep(0.1)

def save_event(event):
    encrypted = b64encode(event.encode() + KEY).decode()
    with open(LOG_FILE, "a") as log_file:
        log_file.write(encrypted + "\n")

if __name__ == "__main__":
    try:
        monitor_auth_log()
    except KeyboardInterrupt:
        print("\nStopped.")
