
import tkinter as tk
from tkinter import ttk, scrolledtext
import queue
from pathlib import Path
import threading

STATE_COLORS = {
    "VERIFYING_SIGNATURE": "#007bff",
    "DECRYPTING": "#007bff",
    "COMPLETE": "#28a745",
    "FAILED": "#dc3545"
}

STATE_PROGRESS = {
    "VERIFYING_SIGNATURE": 25,
    "DECRYPTING": 50,
    "COMPLETE": 100,
    "FAILED": 100
}

class AgentGUI(tk.Toplevel):
    """A Toplevel window that displays the status of the decryption process."""

    def __init__(self, parent, job_path: str, drive_letter: str):
        super().__init__(parent)
        self.job_path = job_path
        self.drive_letter = drive_letter

        self.title(f"Agent - {drive_letter}")
        self.geometry("600x350")

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=f"Processing: {job_path}").pack(fill=tk.X, pady=5)

        self.status_var = tk.StringVar(value="VERIFYING_SIGNATURE")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, font=("Segoe UI", 12, "bold"))
        self.status_label.pack(fill=tk.X, pady=10)

        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state=tk.DISABLED, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def update_log(self, message: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def update_status(self, new_state: str):
        self.status_var.set(new_state)
        color = STATE_COLORS.get(new_state, "#000000")
        self.status_label.configure(foreground=color)
        progress = STATE_PROGRESS.get(new_state, 0)
        self.progress_var.set(progress)

class GuiManager:
    """Manages the agent GUI windows."""

    def __init__(self, msg_queue: queue.Queue, file_processor):
        self.msg_queue = msg_queue
        self.root = tk.Tk()
        self.root.withdraw()
        self.job_windows = {}
        self.file_processor = file_processor

        self.process_queue()

    def process_queue(self):
        try:
            while not self.msg_queue.empty():
                msg = self.msg_queue.get_nowait()
                event_type = msg.get("event")
                job_path = msg.get("job_path")

                if event_type == "NEW_JOB":
                    drive_letter = msg.get("drive_letter")
                    if job_path not in self.job_windows:
                        window = AgentGUI(self.root, job_path, drive_letter)
                        self.job_windows[job_path] = window
                        # Automatically start decryption in a new thread
                        # Create output folder on the USB drive
                        usb_output_path = Path(f"{drive_letter}\\agent_output")
                        threading.Thread(target=self.file_processor.process_encrypted_job, 
                                         args=(Path(job_path), usb_output_path, self.msg_queue, job_path)).start()

                elif event_type == "LOG_EVENT":
                    if job_path in self.job_windows:
                        self.job_windows[job_path].update_log(msg.get("log_message"))
                
                elif event_type == "STATUS_UPDATE":
                    if job_path in self.job_windows:
                        self.job_windows[job_path].update_status(msg.get("status"))

                elif event_type == "DEVICE_REMOVED":
                    if job_path in self.job_windows:
                        self.job_windows[job_path].destroy()
                        del self.job_windows[job_path]

        finally:
            self.root.after(100, self.process_queue)

    def start(self):
        self.root.mainloop()

