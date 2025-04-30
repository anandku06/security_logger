import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox, simpledialog
import os
import datetime
from logger import LOG_FILE
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

window = tk.Tk()
window.title("Security Logger")
window.geometry("700x500")

notebook = ttk.Notebook(window)
notebook.pack(fill="both", expand=True, pady=5, padx=5)

log_frame = ttk.Frame(notebook)
notebook.add(log_frame, text="Security Logs")

filter_frame = ttk.Frame(log_frame)
filter_frame.pack(fill="x", pady=5)

filter_label = ttk.Label(filter_frame, text="Filter:")
filter_label.pack(side="left", padx=5)

filter_var = tk.StringVar()
filter_combo = ttk.Combobox(filter_frame, textvariable=filter_var)
filter_combo["values"] = (
    "All logs",
    "Failed Logins",
    "Successful Logins",
    "Sudo Commands",
)
filter_combo.current(0)
filter_combo.pack(side="left", padx=5)

date_label = ttk.Label(filter_frame, text="Date:")
date_label.pack(side="left", padx=(15, 5))

date_var = tk.StringVar()
date_var.set(datetime.datetime.now().strftime("%Y-%m-%d"))
date_entry = ttk.Entry(filter_frame, textvariable=date_var, width=10)
date_entry.pack(side="left")

search_label = ttk.Label(filter_frame, text="Search:")
search_label.pack(side="left", padx=(15, 5))

search_var = tk.StringVar()
search_entry = ttk.Entry(filter_frame, textvariable=search_var, width=15)
search_entry.pack(side="left")

apply_btn = ttk.Button(
    filter_frame, text="Apply Filter", command=lambda: update_display()
)
apply_btn.pack(side="right", padx=5)

log_display = scrolledtext.ScrolledText(log_frame, width=80, height=25)
log_display.pack(pady=5, padx=5, fill="both", expand=True)

alert_label = tk.Label(log_frame, text="", fg="red")
alert_label.pack()

stats_frame = ttk.Frame(notebook)
notebook.add(stats_frame, text="Statistics")

stats_text = scrolledtext.ScrolledText(stats_frame, width=80, height=25)
stats_text.pack(pady=5, padx=5, fill="both", expand=True)

analysis_frame = ttk.Frame(notebook)
notebook.add(analysis_frame, text="Analysis")

analysis_text = scrolledtext.ScrolledText(analysis_frame, width=80, height=25)
analysis_text.pack(pady=5, padx=5, fill="both", expand=True)


def update_display():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()

        if date_var.get():
            try:
                filter_date = date_var.get()
                logs = [log for log in logs if filter_date in log]
            except Exception:
                pass

        if search_var.get():
            search_term = search_var.get().lower()
            logs = [log for log in logs if search_term in log.lower()]

        filter_type = filter_var.get()
        if filter_type == "Failed Logins":
            logs = [log for log in logs if "Failed Login" in log]
        elif filter_type == "Successful Logins":
            logs = [log for log in logs if "Successful login" in log]
        elif filter_type == "Sudo Commands":
            logs = [log for log in logs if "Sudo command" in log]

        log_display.delete(1.0, tk.END)
        log_display.insert(tk.END, "".join(logs))

        failed_count = sum(1 for log in logs if "Failed Login" in log)
        success_count = sum(1 for log in logs if "Successful login" in log)
        sudo_count = sum(1 for log in logs if "Sudo command" in log)

        stats_text.delete(1.0, tk.END)
        stats_text.insert(tk.END, "Security Event Statistics:\n\n")
        stats_text.insert(tk.END, f"• Failed login attempts: {failed_count}\n")
        stats_text.insert(tk.END, f"• Successful logins: {success_count}\n")
        stats_text.insert(tk.END, f"• Sudo commands executed: {sudo_count}\n\n")

        if failed_count > 0:
            stats_text.insert(tk.END, "Most recent failed login:\n")
            for log in reversed(logs):
                if "Failed Login" in log:
                    stats_text.insert(tk.END, f"  {log}\n\n")
                    break

        update_analysis(logs)

        if failed_count > 3:
            alert_label.config(
                text=f"ALERT: {failed_count} failed login attempts!", fg="red"
            )
        elif success_count > 0 and failed_count > 3:
            alert_label.config(
                text="ALERT: Successful login after multiple failures - please verify!",
                fg="orange",
            )
        elif sudo_count > 1:
            alert_label.config(
                text="NOTICE: Multiple sudo commands detected", fg="yellow"
            )
        else:
            alert_label.config(text="", fg="red")

    window.after(2000, update_display)


def update_analysis(logs):
    """Update the analysis tab with security insights."""
    from collections import Counter
    import re

    analysis_text.delete(1.0, tk.END)
    analysis_text.insert(tk.END, "Security Analysis Report\n")
    analysis_text.insert(tk.END, "=======================\n\n")

    usernames = []
    ip_addresses = []

    for log in logs:
        if "Failed Login" in log or "Successful login" in log:
            parts = log.split()
            if "for" in parts:
                idx = parts.index("for")
                if idx + 1 < len(parts):
                    usernames.append(parts[idx + 1])

            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", log)
            if ip_match:
                ip_addresses.append(ip_match.group(1))

    username_counts = Counter(usernames)
    ip_counts = Counter(ip_addresses)

    analysis_text.insert(tk.END, "Top Users with Login Attempts:\n")
    for user, count in username_counts.most_common(5):
        analysis_text.insert(tk.END, f"• {user}: {count} attempts\n")

    analysis_text.insert(tk.END, "\nTop Source IP Addresses:\n")
    for ip, count in ip_counts.most_common(5):
        analysis_text.insert(tk.END, f"• {ip}: {count} attempts\n")

    analysis_text.insert(tk.END, "\nSuspicious Activity:\n")

    suspicious_found = False
    for user, count in username_counts.items():
        if count >= 3:
            analysis_text.insert(
                tk.END, f"• Multiple attempts ({count}) for user: {user}\n"
            )
            suspicious_found = True

    for ip, count in ip_counts.items():
        if count >= 5:
            analysis_text.insert(
                tk.END, f"• High number of attempts ({count}) from IP: {ip}\n"
            )
            suspicious_found = True

    if not suspicious_found:
        analysis_text.insert(tk.END, "• No suspicious patterns detected\n")


def start_monitoring():
    import subprocess
    import threading

    def run_monitor():
        subprocess.call(["python3", "logger.py"])

    thread = threading.Thread(target=run_monitor)
    thread.daemon = True
    thread.start()
    monitor_btn.config(state="disabled")
    status_label.config(text="Monitoring active", fg="green")


def run_analysis():
    """Run the external analysis script and show results."""
    import subprocess

    try:
        subprocess.call(["python3", "analyser.py"])

        if os.path.exists("security_report.txt"):
            with open("security_report.txt", "r") as f:
                report = f.read()

            analysis_text.delete(1.0, tk.END)
            analysis_text.insert(tk.END, report)
            messagebox.showinfo("Analysis Complete", "Security analysis complete!")
        else:
            messagebox.showinfo(
                "Analysis", "Analysis completed, but no report was generated."
            )
    except Exception as e:
        messagebox.showerror("Error", f"Analysis failed: {str(e)}")

def send_logs_via_email():
    """Send the log file via email."""
    if not os.path.exists(LOG_FILE):
        messagebox.showerror("Error", "Log file not found!")
        return

    # Prompt for email details
    sender_email = "anandkr1704@gmail.com"
    recipient_email = simpledialog.askstring("Recipient Email", "Enter recipient's email address:")
    password = "zhgt euli iswq dnnv"

    if not sender_email or not recipient_email or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    try:
        # Create the email
        subject = "Security Logs"
        body = "Please find the attached security logs."

        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = recipient_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        # Attach the log file
        with open(LOG_FILE, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename={os.path.basename(LOG_FILE)}",
        )
        msg.attach(part)

        # Send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, recipient_email, msg.as_string())

        messagebox.showinfo("Success", "Logs sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {str(e)}")

def export_logs():
    """Export logs to a user-specified file."""
    export_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Export Logs",
    )

    if export_path:
        try:
            with open(LOG_FILE, "r") as f:
                logs = f.read()

            with open(export_path, "w") as out:
                out.write(logs)

            messagebox.showinfo("Export Successful", f"Logs exported to {export_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Error: {str(e)}")


control_frame = ttk.Frame(window)
control_frame.pack(fill="x", pady=10)

monitor_btn = ttk.Button(
    control_frame, text="Start Monitoring", command=start_monitoring
)
monitor_btn.pack(side="left", padx=10)

clear_btn = ttk.Button(
    control_frame,
    text="Clear Logs",
    command=lambda: open(LOG_FILE, "w").close() if os.path.exists(LOG_FILE) else None,
)
clear_btn.pack(side="left", padx=10)

analyse_btn = ttk.Button(control_frame, text="Run Analysis", command=run_analysis)
analyse_btn.pack(side="left", padx=10)

export_btn = ttk.Button(control_frame, text="Export Logs", command=export_logs)
export_btn.pack(side="left", padx=10)

send_email_btn = ttk.Button(
    control_frame, text="Send Logs via Email", command=lambda: send_logs_via_email()
)
send_email_btn.pack(side="left", padx=10)

inactive_style = ttk.Style()
inactive_style.configure("Inactive.TLabel", foreground="gray")

status_label = ttk.Label(control_frame, text="Monitoring inactive", foreground="gray")
status_label.pack(side="right", padx=10)

if __name__ == "__main__":
    update_display()
    window.mainloop()
