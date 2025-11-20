
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import os
import subprocess
import sys
from typing import List, Dict

# --- UI Configuration ---
STATE_COLORS = {
    "INITIALIZED": "#007bff",
    "ENUMERATING": "#007bff",
    "POLICY_CHECK": "#007bff",
    "SCANNING": "#007bff",
    "WAITING_AGENT_SELECTION": "#ffc107", # Yellow for waiting
    "PACKAGING": "#007bff",
    "SUCCESS": "#28a745",
    "FAILED_POLICY": "#dc3545",
    "QUARANTINED": "#dc3545",
    "FAILED": "#dc3545",
    "ABORTED": "#6c757d", # Gray for aborted
}

STATE_PROGRESS = {
    "INITIALIZED": 5,
    "ENUMERATING": 20,
    "POLICY_CHECK": 40,
    "SCANNING": 60,
    "WAITING_AGENT_SELECTION": 70,
    "PACKAGING": 80,
    "SUCCESS": 100,
    "FAILED_POLICY": 100,
    "QUARANTINED": 100,
    "FAILED": 100,
    "ABORTED": 0,
}

class AgentSelectionDialog(tk.Toplevel):
    """Modal dialog to select agents for encryption."""
    def __init__(self, parent, agent_list: List[str], job_id: str):
        super().__init__(parent)
        self.transient(parent)
        self.title(f"Select Agents for Job {job_id[:8]}")
        self.geometry("350x400")
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.result = None

        self.agent_vars = {}
        
        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Select which agents can decrypt this data:", wraplength=320).pack(pady=(0, 10))

        list_frame = ttk.Frame(main_frame, relief=tk.GROOVE, padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True)

        for agent_id in agent_list:
            var = tk.BooleanVar()
            cb = ttk.Checkbutton(list_frame, text=agent_id, variable=var)
            cb.pack(anchor=tk.W, padx=5, pady=2)
            self.agent_vars[agent_id] = var

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))

        ttk.Button(button_frame, text="Confirm", command=self.confirm).pack(side=tk.RIGHT, padx=(5,0))
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.RIGHT)
        
        self.grab_set()
        self.wait_window(self)

    def confirm(self):
        self.result = [agent_id for agent_id, var in self.agent_vars.items() if var.get()]
        if not self.result:
            messagebox.showwarning("No Agents Selected", "You must select at least one agent.", parent=self)
            return
        self.destroy()

    def cancel(self):
        self.result = []
        self.destroy()

class JobFrame(ttk.Frame):
    """A frame that displays the status and logs for a single job."""
    def __init__(self, parent, job_id: str, drive_letter: str, job_path: str):
        super().__init__(parent, padding="10", relief=tk.RIDGE)
        self.job_id = job_id
        self.job_path = job_path

        # --- Style ---
        style = ttk.Style(self)
        style.configure('Job.TLabel', font=('Segoe UI', 9))
        style.configure('JobBold.TLabel', font=('Segoe UI', 10, 'bold'))
        style.configure('JobHeader.TLabel', font=('Segoe UI', 12, 'bold'))

        # --- Status Display ---
        status_frame = ttk.Frame(self, padding="5")
        status_frame.pack(fill=tk.X, expand=True)
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="Job ID:", style='Job.TLabel').grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Label(status_frame, text=job_id, style='Job.TLabel').grid(row=0, column=1, sticky=tk.W)

        ttk.Label(status_frame, text="Device:", style='Job.TLabel').grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Label(status_frame, text=drive_letter, style='Job.TLabel').grid(row=1, column=1, sticky=tk.W)

        ttk.Label(status_frame, text="Status:", style='JobBold.TLabel').grid(row=2, column=0, sticky=tk.W, pady=5)
        self.status_var = tk.StringVar(value="INITIALIZED")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, style='JobBold.TLabel')
        self.status_label.grid(row=2, column=1, sticky=tk.W)

        # --- Progress Bar ---
        self.progress_var = tk.IntVar(value=5)
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, expand=True, pady=5)

        # --- Log Display ---
        log_frame = ttk.LabelFrame(self, text="Logs", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED, height=8, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # --- Action Buttons ---
        self.button_frame = ttk.Frame(self)
        self.button_frame.pack(fill=tk.X, expand=True, pady=(5, 0))

        self.open_folder_button = ttk.Button(self.button_frame, text="Open Job Folder", command=self._open_job_folder, state=tk.DISABLED)
        self.open_folder_button.pack(side=tk.RIGHT)
        
        self.update_status("INITIALIZED")

    def _open_job_folder(self):
        if sys.platform == "win32":
            os.startfile(self.job_path)
        else:
            subprocess.run(["open" if sys.platform == "darwin" else "xdg-open", self.job_path])

    def update_log(self, message: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def update_status(self, new_state: str):
        self.status_var.set(new_state)
        color = STATE_COLORS.get(new_state, "#000000")
        self.status_label.configure(foreground=color)
        progress_value = STATE_PROGRESS.get(new_state, 0)
        self.progress_var.set(progress_value)

        if new_state in ["SUCCESS", "FAILED_POLICY", "QUARANTINED", "FAILED"]:
            self.open_folder_button.configure(state=tk.NORMAL)

class App(tk.Tk):
    """The main application window."""
    def __init__(self, msg_queue: queue.Queue, action_queue: queue.Queue):
        super().__init__()
        self.msg_queue = msg_queue
        self.action_queue = action_queue
        self.job_frames: Dict[str, JobFrame] = {}

        self.title("SMX Gateway Portal")
        self.geometry("800x600")

        # --- Style ---
        style = ttk.Style(self)
        style.theme_use('vista')
        style.configure('TLabel', font=('Segoe UI', 9))
        style.configure('Header.TLabel', font=('Segoe UI', 16, 'bold'))

        # --- Main Layout ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        header_label = ttk.Label(main_frame, text="USB Gateway Monitor", style="Header.TLabel")
        header_label.pack(pady=5)

        self.canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.placeholder_label = ttk.Label(self.scrollable_frame, text="\n\nWaiting for USB device...", font=('Segoe UI', 12, 'italic'), foreground='grey')
        self.placeholder_label.pack(pady=50)

    def add_job_frame(self, job_id: str, drive_letter: str, job_path: str):
        self.placeholder_label.pack_forget()
        frame = JobFrame(self.scrollable_frame, job_id, drive_letter, job_path)
        frame.pack(fill=tk.X, expand=True, padx=10, pady=5)
        self.job_frames[job_id] = frame

    def remove_job_frame(self, job_id: str):
        if job_id in self.job_frames:
            self.job_frames[job_id].destroy()
            del self.job_frames[job_id]
        if not self.job_frames:
            self.placeholder_label.pack(pady=50)
            
    def request_agent_selection(self, job_id: str, agent_list: List[str]):
        """Opens a dialog and sends the user's choice back via the action queue."""
        if job_id in self.job_frames:
            dialog = AgentSelectionDialog(self, agent_list, job_id)
            selected_agents = dialog.result
            self.action_queue.put({
                "action": "AGENTS_SELECTED",
                "job_id": job_id,
                "selected_agents": selected_agents or [] # Ensure it's a list
            })

class GuiManager:
    """Manages the main application window and message queues."""
    def __init__(self, msg_queue: queue.Queue, action_queue: queue.Queue):
        self.msg_queue = msg_queue
        self.action_queue = action_queue
        self.app = App(self.msg_queue, self.action_queue)
        self.process_queue()

    def process_queue(self):
        try:
            while not self.msg_queue.empty():
                msg = self.msg_queue.get_nowait()
                event_type = msg.get("event")
                job_id = msg.get("job_id")

                if event_type == "NEW_JOB":
                    if job_id not in self.app.job_frames:
                        self.app.add_job_frame(job_id, msg.get("drive_letter"), msg.get("job_path"))
                
                elif event_type == "STATE_UPDATE":
                    if job_id in self.app.job_frames:
                        self.app.job_frames[job_id].update_status(msg.get("state"))

                elif event_type == "LOG_EVENT":
                    if job_id in self.app.job_frames:
                        self.app.job_frames[job_id].update_log(msg.get("log_message"))

                elif event_type == "REQUEST_AGENT_SELECTION":
                    agent_list = msg.get("agent_list", [])
                    self.app.request_agent_selection(job_id, agent_list)

                elif event_type == "JOB_COMPLETED" or event_type == "JOB_FAILED":
                    # Optionally, keep the frame for a while or remove immediately
                    pass

                elif event_type == "DEVICE_REMOVED":
                    if job_id in self.app.job_frames:
                        print(f"Closing frame for removed device job {job_id}")
                        self.app.remove_job_frame(job_id)

        finally:
            self.app.after(100, self.process_queue)

    def start(self):
        self.app.mainloop()
