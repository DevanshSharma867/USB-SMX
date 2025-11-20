
import threading
import time
import wmi
import pythoncom
import datetime
import socket
import platform
import getpass

class DeviceManager:
    """Monitors for USB device insertions and removals and notifies the JobManager."""
    def __init__(self, job_manager):
        self._job_manager = job_manager
        self._monitoring_thread = None
        self._stop_event = threading.Event()
        self._last_processed_time = {}
        self.rate_limit_seconds = 10 # Prevent rapid re-processing

    def _is_rate_limited(self, device_id: str) -> bool:
        current_time = time.time()
        if device_id in self._last_processed_time and \
           (current_time - self._last_processed_time[device_id] < self.rate_limit_seconds):
            print(f"Device {device_id} is rate-limited. Skipping.")
            return True
        self._last_processed_time[device_id] = current_time
        return False

    def _collect_metadata(self, wmi_connection, volume_obj):
        """Collects metadata for the specified drive volume object using a primary and fallback method."""
        drive_letter = volume_obj.DriveLetter
        disk_drive = None
        
        try:
            # Primary method: Traverse from Volume -> Partition -> DiskDrive
            partitions = volume_obj.associators(wmi_result_class="Win32_DiskPartition")
            if partitions:
                disk_drive_assoc = partitions[0].associators(wmi_result_class="Win32_DiskDrive")
                if disk_drive_assoc:
                    disk_drive = disk_drive_assoc[0]

            # Fallback method: If the first method fails, try via LogicalDisk
            if not disk_drive:
                print(f"Metadata Method 1 failed for {drive_letter}. Trying fallback...")
                logical_disks = wmi_connection.Win32_LogicalDisk(DeviceID=drive_letter)
                if logical_disks:
                    partitions = logical_disks[0].associators(wmi_result_class="Win32_DiskPartition")
                    if partitions:
                        disk_drive_assoc = partitions[0].associators(wmi_result_class="Win32_DiskDrive")
                        if disk_drive_assoc:
                            disk_drive = disk_drive_assoc[0]

            if not disk_drive:
                print(f"Could not find an associated Win32_DiskDrive for {drive_letter} using any method.")
                return None

            # If we found the disk_drive, collect and return metadata
            return {
                "device_info": {
                    "device_serial": disk_drive.SerialNumber.strip() if disk_drive.SerialNumber else "N/A",
                    "volume_guid": volume_obj.DeviceID,
                    "product_id": disk_drive.PNPDeviceID,
                    "device_capacity": int(disk_drive.Size) if disk_drive.Size else 0,
                    "filesystem_type": volume_obj.FileSystem,
                },
                "gateway_info": {
                    "hostname": socket.gethostname(),
                    "ip_address": socket.gethostbyname(socket.gethostname()),
                    "os_version": platform.platform(),
                    "user": getpass.getuser(),
                    "gateway_version": "0.2.1", # Version bump for the fix
                    "insertion_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                }
            }
        except Exception as e:
            print(f"An unhandled exception occurred during metadata collection for {drive_letter}: {e}")
            return None

    def _handle_device_insertion(self, drive_letter: str, device_id: str):
        pythoncom.CoInitialize()
        wmi_connection = wmi.WMI()
        print(f"Handling insertion of device {drive_letter} ({device_id})")

        if self._is_rate_limited(device_id):
            pythoncom.CoUninitialize()
            return

        try:
            volume = wmi_connection.Win32_Volume(DriveLetter=drive_letter)[0]
            metadata = self._collect_metadata(wmi_connection, volume)
            if metadata:
                print(f"Collected metadata for {drive_letter}, passing to Job Manager.")
                self._job_manager.start_new_job(drive_letter, metadata)
            else:
                print(f"Failed to collect metadata for {drive_letter}. Aborting.")
        except IndexError:
            print(f"Could not find WMI volume object for {device_id}. Aborting.")
        finally:
            pythoncom.CoUninitialize()

    def _monitor_devices(self):
        pythoncom.CoInitialize()
        print("Starting USB device monitor...")
        
        try:
            wmi_connection = wmi.WMI()
            known_volumes = {v.DeviceID: v.DriveLetter for v in wmi_connection.Win32_Volume() if v.DriveLetter}
        except Exception as e:
            print(f"Error during initial WMI scan: {e}. Starting with empty set.")
            known_volumes = {}

        while not self._stop_event.is_set():
            try:
                wmi_connection = wmi.WMI()
                current_volumes = {v.DeviceID: v.DriveLetter for v in wmi_connection.Win32_Volume() if v.DriveLetter}
                
                # Insertions
                new_device_ids = set(current_volumes.keys()) - set(known_volumes.keys())
                for dev_id in new_device_ids:
                    drive_letter = current_volumes[dev_id]
                    # Offload the handling to a new thread to keep the monitor responsive
                    threading.Thread(target=self._handle_device_insertion, args=(drive_letter, dev_id)).start()
                
                # Removals
                removed_device_ids = set(known_volumes.keys()) - set(current_volumes.keys())
                for dev_id in removed_device_ids:
                    drive_letter = known_volumes[dev_id]
                    print(f"Device {drive_letter} removed. Notifying Job Manager.")
                    self._job_manager.handle_device_removal(drive_letter)

                known_volumes = current_volumes
                self._stop_event.wait(2)
            except Exception as e:
                print(f"Error in device monitor loop: {e}")
                time.sleep(5)

        print("USB device monitor stopped.")
        pythoncom.CoUninitialize()

    def start_monitoring(self):
        if self._monitoring_thread is None or not self._monitoring_thread.is_alive():
            self._stop_event.clear()
            self._monitoring_thread = threading.Thread(target=self._monitor_devices, daemon=True)
            self._monitoring_thread.start()
            print("Device monitoring started.")

    def stop_monitoring(self):
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._stop_event.set()
            self._monitoring_thread.join(timeout=5)
            print("Device monitoring stopped.")
