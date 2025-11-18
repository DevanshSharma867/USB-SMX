
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
from pathlib import Path
import threading
import os

STATE_COLORS = {
    "VERIFYING_SIGNATURE": "#007bff",
    "UNWRAPPING_KEY": "#007bff",
    "READY_FOR_ACCESS": "#28a745",
    "OPENING_FILE": "#ffc107",
    "FAILED": "#dc3545"
}

STATE_PROGRESS = {
    "VERIFYING_SIGNATURE": 25,
    "UNWRAPPING_KEY": 50,
    "READY_FOR_ACCESS": 100,
    "OPENING_FILE": 75, # Intermediate state
    "FAILED": 100
}

class AgentGUI(tk.Toplevel):
    """A Toplevel window that displays the status of the decryption process and allows file access."""

    def __init__(self, parent, job_path_str: str, drive_letter: str, file_processor, gui_queue: queue.Queue):
        super().__init__(parent)
        self.job_path_str = job_path_str
        self.drive_letter = drive_letter
        self.file_processor = file_processor
        self.gui_queue = gui_queue
        self.manifest = None # To be populated after job data is loaded

        self.title(f"Agent - {drive_letter}")
        self.geometry("800x600")
        self.protocol("WM_DELETE_WINDOW", self._on_closing) # Handle window close event

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=f"Secure USB: {drive_letter} ({job_path_str})").pack(fill=tk.X, pady=5)

        self.status_var = tk.StringVar(value="Initializing...")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, font=("Segoe UI", 12, "bold"))
        self.status_label.pack(fill=tk.X, pady=5)

        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)

        # File Treeview
        file_frame = ttk.LabelFrame(main_frame, text="Files on Secure USB", padding="5")
        file_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.file_tree = ttk.Treeview(file_frame, columns=("Size", "Type"), show="tree headings")
        self.file_tree.heading("#0", text="File Name")
        self.file_tree.heading("Size", text="Size")
        self.file_tree.heading("Type", text="Type")
        self.file_tree.column("#0", width=400, anchor="w")
        self.file_tree.column("Size", width=100, anchor="e")
        self.file_tree.column("Type", width=100, anchor="w")
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tree_scroll = ttk.Scrollbar(file_frame, orient="vertical", command=self.file_tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)

        self.file_tree.bind("<Double-1>", self._on_file_double_click)

        # Log Text Area
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED, height=8)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _on_closing(self):
        if messagebox.askokcancel("Close", "Are you sure you want to close this secure access window?"):
            # Potentially add logic here to ensure all temp files are cleaned up
            # and any active file viewing processes are terminated.
            self.destroy()

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
        if new_state == "READY_FOR_ACCESS":
            self.progress_bar.stop() # Stop indeterminate mode if it was running
            self.progress_bar['value'] = 100 # Ensure it's full

    def populate_file_tree(self, manifest: dict):
        self.manifest = manifest
        self.file_tree.delete(*self.file_tree.get_children()) # Clear existing items

        # Create a dictionary to build the tree structure
        tree_items = {}

        for original_path_str, file_info in manifest["files"].items():
            path_parts = Path(original_path_str).parts
            current_parent = ''

            for i, part in enumerate(path_parts):
                full_path_part = os.path.join(current_parent, part)
                if full_path_part not in tree_items:
                    if i == len(path_parts) - 1: # It's a file
                        # For files, store the full original path string as the item ID
                        item_id = self.file_tree.insert(current_parent, 'end', text=part, values=(self._format_size(file_info.get('original_size', 0)), Path(part).suffix), iid=original_path_str)
                    else: # It's a directory
                        item_id = self.file_tree.insert(current_parent, 'end', text=part, iid=full_path_part, open=False)
                    tree_items[full_path_part] = item_id
                current_parent = full_path_part

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes / (1024**2):.1f} MB"
        else:
            return f"{size_bytes / (1024**3):.1f} GB"

    def _on_file_double_click(self, event):
        selected_item_id = self.file_tree.focus()
        if not selected_item_id:
            return

        # Check if it's a file (i.e., its iid is the original_path_str)
        # Directories will have iid as their full_path_part
        if selected_item_id in self.manifest["files"]:
            original_file_path = selected_item_id
            self.update_status("OPENING_FILE")
            # Call the file processor in a new thread to avoid freezing the GUI
            threading.Thread(target=self.file_processor.decrypt_and_open_single_file, 
                             args=(self.job_path_str, original_file_path, self.gui_queue)).start()
        else:
            # It's a directory, toggle its open state
            self.file_tree.item(selected_item_id, open=not self.file_tree.item(selected_item_id, "open"))


class GuiManager:
    """Manages the agent GUI windows."""

    def __init__(self, msg_queue: queue.Queue, file_processor):
        self.msg_queue = msg_queue
        self.root = tk.Tk()
        self.root.withdraw()
        self.job_windows = {} # Stores {job_path_str: AgentGUI_instance}
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
                        # Start loading job data in a new thread
                        threading.Thread(target=self.file_processor.load_job_data, 
                                         args=(Path(job_path_str), self.msg_queue, job_path_str)).start()

                elif event_type == "LOG_EVENT":
                    if job_path_str in self.job_windows:
                        self.job_windows[job_path_str].update_log(msg.get("log_message"))
                
                elif event_type == "STATUS_UPDATE":
                    if job_path_str in self.job_windows:
                        self.job_windows[job_path_str].update_status(msg.get("status"))
                        if msg.get("status") == "READY_FOR_ACCESS":
                            # Once ready, populate the file tree
                            job_data = self.file_processor.loaded_jobs.get(job_path_str)
                            if job_data:
                                self.job_windows[job_path_str].populate_file_tree(job_data['manifest'])

                elif event_type == "DEVICE_REMOVED":
                    if job_path_str in self.job_windows:
                        self.job_windows[job_path_str].destroy()
                        del self.job_windows[job_path_str]

        finally:
            self.root.after(100, self.process_queue)

    def start(self):
        self.root.mainloop()

