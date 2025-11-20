# Main entry point for the Gateway Service.
import sys
import time
import queue
import threading
import subprocess
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent
sys.path.insert(0, str(SRC_PATH))

from gateway.device_manager import DeviceManager
from gateway.job_manager import JobManager
from gateway.gui import GuiManager

def check_defender_status():
    """Checks the status of the Windows Defender service."""
    try:
        # Using PowerShell for a more robust check
        cmd = "Get-Service -Name WinDefend | Select-Object -ExpandProperty Status"
        result = subprocess.run(['powershell', '-NoProfile', '-Command', cmd], capture_output=True, text=True, check=True)
        status = result.stdout.strip()
        if status == "Running":
            print("INFO: Windows Defender (WinDefend) service is running.")
        else:
            print(f"WARNING: Windows Defender (WinDefend) service is in '{status}' state.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"ERROR: Could not determine the status of Windows Defender service: {e}")

def main():
    """Initializes and runs the background services and the main GUI."""
    print("--- SMX Gateway Portal --- ")
    check_defender_status()
    
    # Queues for cross-thread communication
    gui_queue = queue.Queue() # From backend services to GUI
    action_queue = queue.Queue() # From GUI to backend services

    # Initialize backend managers
    # The JobManager will now handle the lifecycle of each job.
    job_manager = JobManager(gui_queue, action_queue)
    
    # The DeviceManager now only detects devices and passes them to the JobManager.
    device_manager = DeviceManager(job_manager)

    # Start the device monitoring in a background thread
    monitor_thread = threading.Thread(target=device_manager.start_monitoring, daemon=True)
    monitor_thread.start()
    print("INFO: Started USB device monitoring.")

    # Start the job manager's action processing loop in a background thread
    job_thread = threading.Thread(target=job_manager.process_actions, daemon=True)
    job_thread.start()
    print("INFO: Started Job Manager action processor.")

    # Initialize and start the GUI Manager in the main thread.
    # This will block until the GUI is closed.
    print("INFO: Launching main application window...")
    gui_manager = GuiManager(gui_queue, action_queue)
    
    try:
        gui_manager.start()
    except KeyboardInterrupt:
        print("\nShutdown signal received.")
    finally:
        print("INFO: Main window closed. Shutting down background services...")
        device_manager.stop_monitoring()
        job_manager.shutdown()
        print("--- SMX Gateway Portal Closed ---")

if __name__ == '__main__':
    main()