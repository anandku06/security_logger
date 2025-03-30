import time
import os

LOG_FILE = "security_log.txt"
KEY = b"simplekey"

def monitor_auth_log():
    auth_log_path = "/var/log/auth.log"
    if not os.path.exists(auth_log_path):
        print("Error: auth.log not found. Are you on Linux?")
        return

    print("Monitoring started... Press Ctrl+C to stop.")
    with open(auth_log_path, "r") as auth_file:
        auth_file.seek(0, os.SEEK_END)
        while True:
            line = auth_file.readline()
            if line and "Failed password" in line:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                event = f"{timestamp} - Suspicious: {line.strip()}"
                print(event)
                save_event(event)
            time.sleep(0.1)

def save_event(event):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(event + "\n")

if __name__ == "main":
    try:
        monitor_auth_log()
    except KeyboardInterrupt:
        print("\nStopped.")
