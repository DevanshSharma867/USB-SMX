# Handles USB device detection, metadata collection, and processing.
import threading
import time
import wmi
import pythoncom
import datetime
import socket
from .job_manager import Job, JobState, JobManager
from .file_processor import FileProcessor

class DeviceManager:
    """
    Monitors for USB device insertions and removals, and processes them.
    """
    def __init__(self, gui_queue=None):
        self._job_manager = JobManager(gui_queue)
        self._file_processor = FileProcessor(self._job_manager)
        self._monitoring_thread = None
        self._stop_event = threading.Event()
        self.gui_queue = gui_queue
        # Thread-safe mapping of drive letters to active job IDs
        self.active_jobs_by_drive = {}
        self.active_jobs_lock = threading.Lock()

        # Rate limiting for device processing
        self._last_processed_time = {}
        self.rate_limit_seconds = 30 # Default rate limit: 30 seconds

    def _is_rate_limited(self, device_id: str) -> bool:
        """
        Checks if a device is currently rate-limited.
        Returns True if rate-limited, False otherwise.
        """
        current_time = time.time()
        last_time = self._last_processed_time.get(device_id)

        if last_time and (current_time - last_time < self.rate_limit_seconds):
            print(f"Device {device_id} is rate-limited. Skipping processing.")
            return True
        
        self._last_processed_time[device_id] = current_time
        return False

    def _collect_metadata(self, wmi_connection, volume_obj):
        """Collects metadata for the specified drive volume object using multiple methods."""
        disk_drive = None
        drive_letter = volume_obj.DriveLetter
        if not drive_letter:
            print("Volume has no drive letter, cannot collect detailed metadata.")
            return None

        try:
            # Method 1: Start from the Volume object
            print("Attempting metadata collection via Volume->Partition association...")
            partitions = volume_obj.associators(wmi_result_class="Win32_DiskPartition")
            if partitions:
                disk_drive = partitions[0].associators(wmi_result_class="Win32_DiskDrive")[0]
                print("Method 1 successful.")

            # Method 2: Fallback to starting from the Logical Disk object
            if not disk_drive:
                print("Method 1 failed. Attempting fallback via LogicalDisk->Partition association...")
                logical_disks = wmi_connection.Win32_LogicalDisk(DeviceID=drive_letter)
                if logical_disks:
                    partitions = logical_disks[0].associators(wmi_result_class="Win32_DiskPartition")
                    if partitions:
                        disk_drive = partitions[0].associators(wmi_result_class="Win32_DiskDrive")[0]
                        print("Method 2 successful.")

            if not disk_drive:
                print(f"Could not find an associated Win32_DiskDrive for {drive_letter} using any method.")
                return None

            # If we found the disk_drive, collect metadata
            metadata = {
                "device_serial": disk_drive.SerialNumber.strip() if disk_drive.SerialNumber else "N/A",
                "volume_guid": volume_obj.DeviceID,
                "product_id": disk_drive.PNPDeviceID,
                "device_capacity": int(disk_drive.Size) if disk_drive.Size else 0,
                "filesystem_type": volume_obj.FileSystem,
                "insertion_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "hostname": socket.gethostname(),
                "gateway_version": "0.1.0" # Hardcoded for now
            }
            return metadata
        except IndexError:
            print(f"Could not retrieve WMI objects for {drive_letter}. It might not be a standard disk volume.")
            return None
        except Exception as e:
            print(f"An error occurred during metadata collection for {drive_letter}: {e}")
            return None

    def _handle_device_insertion(self, drive_letter):
        """
        Handles metadata collection for a new device and passes the job to the FileProcessor.
        """
        pythoncom.CoInitialize()
        wmi_connection = wmi.WMI()
        print(f"Device inserted: {drive_letter}")

        # Check for rate limiting first
        # We need a unique identifier for the device, not just the drive letter.
        # For now, we'll use the drive_letter as a proxy for device_id for rate limiting.
        # A more robust solution would involve getting the actual device's unique ID (e.g., serial number).
        # However, getting the serial number requires collecting metadata, which is part of the process we might want to rate limit.
        # So, for this MVP, we'll rate limit based on drive_letter.
        if self._is_rate_limited(drive_letter):
            pythoncom.CoUninitialize()
            return

        try:
            volume = wmi_connection.Win32_Volume(DriveLetter=drive_letter)[0]
        except IndexError:
            print(f"Could not find WMI volume object for {drive_letter}. Aborting.")
            pythoncom.CoUninitialize()
            return

        # 1. Collect Metadata
        metadata = self._collect_metadata(wmi_connection, volume)
        if not metadata:
            print("Failed to collect metadata. Aborting.")
            pythoncom.CoUninitialize()
            return
            
        print("Collected Metadata:")
        for key, value in metadata.items():
            print(f"  {key}: {value}")

        # 2. Initialize Job
        job = self._job_manager.initialize_job(metadata)
        if not job:
            print("Failed to create a job. Aborting.")
            pythoncom.CoUninitialize()
            return

        # Notify GUI that a new job has started
        if self.gui_queue:
            self.gui_queue.put({
                "event": "NEW_JOB",
                "job_id": job.job_id,
                "drive_letter": drive_letter,
                "job_path": str(job.path)
            })

        # Track the job as active for this drive
        with self.active_jobs_lock:
            self.active_jobs_by_drive[drive_letter] = job.job_id

        # 3. Delegate to File Processor
        # The FileProcessor now handles the entire pipeline from this point forward.
        try:
            self._file_processor.process_device(job, f"{drive_letter}\\", drive_letter)
        except Exception as e:
            print(f"A critical error occurred in the file processor for job {job.job_id}: {e}")
            self._job_manager.update_state(job, JobState.FAILED, {"error": f"Critical failure in FileProcessor: {e}"})
        finally:
            pythoncom.CoUninitialize()

    def _handle_device_removal(self, drive_letter):
        """
        Handles device removal by notifying the GUI to close the relevant window.
        """
        print(f"Device removed: {drive_letter}")
        job_id_to_close = None
        with self.active_jobs_lock:
            if drive_letter in self.active_jobs_by_drive:
                job_id_to_close = self.active_jobs_by_drive.pop(drive_letter)
        
        if job_id_to_close and self.gui_queue:
            print(f"Notifying GUI to close window for job {job_id_to_close}")
            self.gui_queue.put({
                "event": "DEVICE_REMOVED",
                "job_id": job_id_to_close
            })

    def _monitor_devices(self):
        pythoncom.CoInitialize()
        print("Starting USB device monitor (polling mode)...")
        
        # Initial scan to populate known_volumes with currently connected devices
        # This ensures existing drives are not treated as new insertions
        try:
            wmi_connection = wmi.WMI()
            known_volumes = {v.DeviceID: v.DriveLetter for v in wmi_connection.Win32_Volume() if v.DriveLetter}
        except Exception as e:
            print(f"Error during initial WMI scan: {e}. Starting with empty known volumes.")
            known_volumes = {} # Fallback if initial scan fails

        while not self._stop_event.is_set():
            try:
                wmi_connection = wmi.WMI() # Re-initialize WMI connection inside loop for robustness
                current_volumes = {v.DeviceID: v.DriveLetter for v in wmi_connection.Win32_Volume() if v.DriveLetter}
                
                current_device_ids = set(current_volumes.keys())
                known_device_ids = set(known_volumes.keys())

                # Check for new drives (insertions)
                new_device_ids = current_device_ids - known_device_ids
                if new_device_ids:
                    for device_id in new_device_ids:
                        drive_letter = current_volumes[device_id]
                        print(f"New drive detected: {drive_letter}")
                        handler_thread = threading.Thread(
                            target=self._handle_device_insertion, 
                            args=(drive_letter,)
                        )
                        handler_thread.start()
                
                # Check for removed drives
                removed_device_ids = known_device_ids - current_device_ids
                if removed_device_ids:
                    for device_id in removed_device_ids:
                        drive_letter = known_volumes[device_id]
                        self._handle_device_removal(drive_letter)

                # Update the set of known drives for the next iteration
                known_volumes = current_volumes # This line stays inside the loop
                
                self._stop_event.wait(2) # Poll every 2 seconds

            except Exception as e:
                print(f"An error occurred in the polling loop: {e}")
                time.sleep(5)

        print("USB device monitor stopped.")
        pythoncom.CoUninitialize()

    def start_monitoring(self):
        """Starts the monitoring thread."""
        if self._monitoring_thread is None or not self._monitoring_thread.is_alive():
            self._stop_event.clear()
            self._monitoring_thread = threading.Thread(target=self._monitor_devices, daemon=True)
            self._monitoring_thread.start()
            print("Device monitoring started in the background.")

    def stop_monitoring(self):
        """Stops the monitoring thread."""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._stop_event.set()
            self._monitoring_thread.join(timeout=5)
            print("Device monitoring stopped.")