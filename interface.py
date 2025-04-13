import tkinter as tk  
from tkinter import scrolledtext  
import os  
from base64 import b64decode  
from logger import LOG_FILE, KEY

window = tk.Tk()
window.title("Security Logger")
window.geometry("600x400")  

log_display = scrolledtext.ScrolledText(window, width=70, height=20)
log_display.pack(pady=10)  

alert_label = tk.Label(window, text="", fg="red")
alert_label.pack()


def update_display():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            encrypted_logs = f.readlines() 
        
        logs = []
        for line in encrypted_logs:
            try:
                decrypted_line = b64decode(line.strip()).decode()[:-len(KEY)]
                logs.append(decrypted_line)
            except Exception as e:
                print(f"Error decoding line: {str(e)}")  

        log_display.delete(1.0, tk.END)  
        log_display.insert(tk.END, "\n".join(logs))  

        failed_count = logs.count("Failed login")
        success_count = logs.count("Successful login")
        sudo_count = logs.count("Sudo command")

        if failed_count > 3:
            alert_label.config(text=f"ALERT: {failed_count} failed attempts!", fg="red")
        elif success_count > 0 and failed_count > 3:
            alert_label.config(
                text="ALERT: Success after many fails - check it!", fg="orange"
            )
        elif sudo_count > 1:
            alert_label.config(
                text="NOTICE: Multiple sudo commands detected", fg="yellow"
            )
        else:
            alert_label.config(text="", fg="red")

    window.after(2000, update_display)  


if __name__ == "__main__":
    update_display()
    window.mainloop()  
