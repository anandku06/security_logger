import time
import os
from config import LOG_MAX_SIZE

LOG_FILE = "security_log.txt"

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
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_SIZE:
        rotate_log_file()
    with open(LOG_FILE, "a") as log_file:
        log_file.write(event + "\n")

def rotate_log_file():
    rotatedFile = f"{LOG_FILE}.1"
    if os.path.exists(rotatedFile):
        os.remove(rotatedFile)
    os.rename(LOG_FILE, rotatedFile)
    print(f"Log file rotated: {rotatedFile}")

if __name__ == "__main__":
    try:
        monitor_auth_log()
    except KeyboardInterrupt:
        print("\nStopped.")
