
import threading
import time
import wmi
import pythoncom
from pathlib import Path

class AgentDeviceManager:
    """Monitors for processed USB devices."""

    def __init__(self, gui_queue=None):
        self.gui_queue = gui_queue
        self._monitoring_thread = None
        self._stop_event = threading.Event()
        self.active_jobs_by_drive = {}
        self.active_jobs_lock = threading.Lock()

    def _monitor_devices(self):
        """Polls for USB devices with a .gateway_output directory."""
        pythoncom.CoInitialize()
        print("Agent device monitor started.")
        known_drives = set()

        while not self._stop_event.is_set():
            try:
                wmi_connection = wmi.WMI()
                current_drives = {drive.DeviceID for drive in wmi_connection.Win32_LogicalDisk(DriveType=2)}

                new_drives = current_drives - known_drives
                for drive_id in new_drives:
                    drive_letter = wmi_connection.Win32_LogicalDisk(DeviceID=drive_id)[0].Name
                    job_path = Path(f"{drive_letter}\\.gateway_output")
                    if job_path.exists() and (job_path / "manifest.json").exists():
                        print(f"Found processed USB at {drive_letter}")
                        with self.active_jobs_lock:
                            self.active_jobs_by_drive[drive_letter] = str(job_path)
                        if self.gui_queue:
                            self.gui_queue.put({
                                "event": "NEW_JOB",
                                "job_path": str(job_path),
                                "drive_letter": drive_letter
                            })
                
                removed_drives = known_drives - current_drives
                for drive_id in removed_drives:
                    # This is a simplification. In a real scenario, you would need to map
                    # the drive_id back to the drive letter that was removed.
                    # For this MVP, we will iterate through the active jobs and check if the drive is still present.
                    with self.active_jobs_lock:
                        drives_to_remove = []
                        for drive_letter, job_path in self.active_jobs_by_drive.items():
                            if not Path(f"{drive_letter}\\").exists():
                                drives_to_remove.append(drive_letter)
                        
                        for drive_letter in drives_to_remove:
                            job_path = self.active_jobs_by_drive.pop(drive_letter)
                            print(f"Device removed: {drive_letter}")
                            if self.gui_queue:
                                self.gui_queue.put({
                                    "event": "DEVICE_REMOVED",
                                    "job_path": job_path
                                })

                known_drives = current_drives
                time.sleep(2)
            except Exception as e:
                print(f"Error in agent device monitor: {e}")
                time.sleep(5)
        
        pythoncom.CoUninitialize()
        print("Agent device monitor stopped.")

    def start_monitoring(self):
        if self._monitoring_thread is None or not self._monitoring_thread.is_alive():
            self._stop_event.clear()
            self._monitoring_thread = threading.Thread(target=self._monitor_devices, daemon=True)
            self._monitoring_thread.start()

    def stop_monitoring(self):
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._stop_event.set()
            self._monitoring_thread.join(timeout=5)
