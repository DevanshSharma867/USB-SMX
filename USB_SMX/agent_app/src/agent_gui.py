import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
from pathlib import Path
import threading
import os

STATE_COLORS = {
    "VERIFYING_SIGNATURE": "#007bff",
    "UNWRAPPING_KEY": "#007bff",
    "READY_FOR_ACCESS": "#17a2b8", # Changed to info color
    "DECRYPTING_ALL_FILES": "#ffc107",
    "DECRYPTION_COMPLETE": "#28a745",
    "FAILED": "#dc3545"
}

STATE_PROGRESS = {
    "VERIFYING_SIGNATURE": 25,
    "UNWRAPPING_KEY": 50,
    "READY_FOR_ACCESS": 60,
    "DECRYPTING_ALL_FILES": 75,
    "DECRYPTION_COMPLETE": 100,
    "FAILED": 100
}

class AgentGUI(tk.Toplevel):
    """A Toplevel window that displays the status of the bulk decryption process."""

    def __init__(self, parent, job_path_str: str, drive_letter: str, file_processor, gui_queue: queue.Queue):
        super().__init__(parent)
        self.job_path_str = job_path_str
        self.drive_letter = drive_letter
        self.file_processor = file_processor
        self.gui_queue = gui_queue

        self.title(f"Agent - Decrypting {drive_letter}")
        self.geometry("800x400")
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=f"Processing Secure USB: {drive_letter}").pack(fill=tk.X, pady=5)

        self.status_var = tk.StringVar(value="Initializing...")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, font=("Segoe UI", 12, "bold"))
        self.status_label.pack(fill=tk.X, pady=10)

        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)

        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self.close_button = ttk.Button(main_frame, text="Close", command=self._on_closing, state=tk.DISABLED)
        self.close_button.pack(pady=10)


    def _on_closing(self):
        if self.close_button['state'] == tk.DISABLED:
            messagebox.showwarning("Busy", "Decryption is in progress. Please wait until it is complete.")
            return
        self.destroy()

    def update_log(self, message: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def update_status(self, new_state: str):
        self.status_var.set(new_state.replace("_", " ").title())
        color = STATE_COLORS.get(new_state, "#000000")
        self.status_label.configure(foreground=color)
        progress = STATE_PROGRESS.get(new_state, 0)
        self.progress_var.set(progress)

        if new_state == "DECRYPTION_COMPLETE" or new_state == "FAILED":
            self.close_button['state'] = tk.NORMAL
            if new_state == "DECRYPTION_COMPLETE":
                self.progress_bar['value'] = 100
            if self.progress_bar['mode'] == 'indeterminate':
                self.progress_bar.stop()
        elif new_state == "DECRYPTING_ALL_FILES":
             self.progress_bar.config(mode='indeterminate')
             self.progress_bar.start()


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
                job_path_str = msg.get("job_path")

                if event_type == "NEW_JOB":
                    drive_letter = msg.get("drive_letter")
                    if job_path_str not in self.job_windows:
                        window = AgentGUI(self.root, job_path_str, drive_letter, self.file_processor, self.msg_queue)
                        self.job_windows[job_path_str] = window
                        threading.Thread(target=self.file_processor.load_job_data, 
                                         args=(Path(job_path_str), self.msg_queue, job_path_str)).start()

                elif event_type == "LOG_EVENT":
                    if job_path_str in self.job_windows:
                        self.job_windows[job_path_str].update_log(msg.get("log_message"))
                
                elif event_type == "STATUS_UPDATE":
                    if job_path_str in self.job_windows:
                        self.job_windows[job_path_str].update_status(msg.get("status"))
                        if msg.get("status") == "READY_FOR_ACCESS":
                            # Automatically start bulk decryption
                            drive_letter = self.job_windows[job_path_str].drive_letter
                            threading.Thread(target=self.file_processor.decrypt_all_files_to_usb, 
                                             args=(job_path_str, drive_letter, self.msg_queue)).start()

                elif event_type == "DEVICE_REMOVED":
                    if job_path_str in self.job_windows:
                        self.job_windows[job_path_str].destroy()
                        del self.job_windows[job_path_str]

        finally:
            self.root.after(100, self.process_queue)

    def start(self):
        self.root.mainloop()

