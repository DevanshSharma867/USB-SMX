# Handles the GUI for job status notifications.
import tkinter as tk
from tkinter import ttk, scrolledtext
import queue
import os
import subprocess
import sys

# --- UI Configuration ---
STATE_COLORS = {
    "INITIALIZED": "#007bff",  # Blue
    "ENUMERATING": "#007bff",
    "POLICY_CHECK": "#007bff",
    "SCANNING": "#007bff",
    "PACKAGING": "#007bff",
    "SUCCESS": "#28a745",      # Green
    "FAILED_POLICY": "#dc3545", # Red
    "QUARANTINED": "#dc3545",
    "FAILED": "#dc3545"
}

STATE_PROGRESS = {
    "INITIALIZED": 5,
    "ENUMERATING": 20,
    "POLICY_CHECK": 40,
    "SCANNING": 60,
    "PACKAGING": 80,
    "SUCCESS": 100,
    "FAILED_POLICY": 100,
    "QUARANTINED": 100,
    "FAILED": 100
}

class JobInfoWindow(tk.Toplevel):
    """A Toplevel window that displays the status and logs for a single job."""
    def __init__(self, parent, job_id: str, drive_letter: str, job_path: str):
        super().__init__(parent)
        self.job_id = job_id
        self.job_path = job_path

        self.title(f"Gateway Job: {job_id[:8]}...")
        self.geometry("650x450")
        self.resizable(False, False)

        # --- Style ---
        style = ttk.Style(self)
        style.theme_use('vista') # Use a modern theme
        style.configure('TLabel', font=('Segoe UI', 9))
        style.configure('Bold.TLabel', font=('Segoe UI', 10, 'bold'))
        style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('TButton', font=('Segoe UI', 9))
        style.configure('TLabelframe.Label', font=('Segoe UI', 9, 'bold'))

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Status Display ---
        status_frame = ttk.LabelFrame(main_frame, text="Job Details", padding="10")
        status_frame.pack(fill=tk.X, expand=True)
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="Job ID:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Label(status_frame, text=job_id).grid(row=0, column=1, sticky=tk.W)

        ttk.Label(status_frame, text="Device:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Label(status_frame, text=drive_letter).grid(row=1, column=1, sticky=tk.W)

        ttk.Label(status_frame, text="Status:", style='Bold.TLabel').grid(row=2, column=0, sticky=tk.W, pady=5)
        self.status_var = tk.StringVar(value="INITIALIZED")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, style='Bold.TLabel')
        self.status_label.grid(row=2, column=1, sticky=tk.W)

        # --- Progress Bar ---
        self.progress_var = tk.IntVar(value=5)
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, expand=True, pady=10)

        # Set initial state after all widgets are created
        self.update_status("INITIALIZED")

        # --- Log Display ---
        log_frame = ttk.LabelFrame(main_frame, text="Logs", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED, height=10, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # --- Action Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, expand=True, pady=(10, 0))

        self.open_folder_button = ttk.Button(button_frame, text="Open Job Folder", command=self._open_job_folder, state=tk.DISABLED)
        self.open_folder_button.pack(side=tk.RIGHT)

    def _open_job_folder(self):
        """Opens the job's output directory in the file explorer."""
        if sys.platform == "win32":
            os.startfile(self.job_path)
        elif sys.platform == "darwin":
            subprocess.run(["open", self.job_path])
        else: # Linux
            subprocess.run(["xdg-open", self.job_path])

    def update_log(self, message: str):
        """Appends a message to the log display."""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def update_status(self, new_state: str):
        """Updates the status label, color, and progress bar."""
        self.status_var.set(new_state)
        
        # Update color
        color = STATE_COLORS.get(new_state, "#000000") # Default to black
        self.status_label.configure(foreground=color)

        # Update progress bar
        progress_value = STATE_PROGRESS.get(new_state, 0)
        self.progress_var.set(progress_value)

        # Enable open folder button on completion
        if new_state in ["SUCCESS", "FAILED_POLICY", "QUARANTINED", "FAILED"]:
            self.open_folder_button.configure(state=tk.NORMAL)

class GuiManager:
    """Manages the main application window and all job windows."""
    def __init__(self, msg_queue: queue.Queue):
        self.msg_queue = msg_queue
        self.root = tk.Tk()
        self.root.withdraw() # Hide the root window
        self.job_windows = {}

        self.process_queue()

    def process_queue(self):
        """Checks the message queue for updates from background threads."""
        try:
            while not self.msg_queue.empty():
                msg = self.msg_queue.get_nowait()
                
                event_type = msg.get("event")
                job_id = msg.get("job_id")

                if event_type == "NEW_JOB":
                    if job_id not in self.job_windows:
                        window = JobInfoWindow(self.root, job_id, msg.get("drive_letter"), msg.get("job_path"))
                        window.protocol("WM_DELETE_WINDOW", lambda j=job_id: self._on_window_close(j))
                        self.job_windows[job_id] = window
                
                elif event_type == "STATE_UPDATE":
                    if job_id in self.job_windows:
                        self.job_windows[job_id].update_status(msg.get("state"))

                elif event_type == "LOG_EVENT":
                    if job_id in self.job_windows:
                        self.job_windows[job_id].update_log(msg.get("log_message"))
                
                elif event_type == "DEVICE_REMOVED":
                    if job_id in self.job_windows:
                        print(f"Closing window for removed device job {job_id}")
                        self._on_window_close(job_id)

        finally:
            self.root.after(100, self.process_queue)

    def _on_window_close(self, job_id: str):
        """Callback to clean up when a job window is closed."""
        if job_id in self.job_windows:
            self.job_windows[job_id].destroy()
            del self.job_windows[job_id]
            print(f"Closed window for job {job_id}")

    def start(self):
        """Starts the Tkinter main loop."""
        self.root.mainloop()