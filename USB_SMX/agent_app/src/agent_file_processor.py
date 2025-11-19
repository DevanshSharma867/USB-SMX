import sys
import json
from pathlib import Path
import queue
import os
import subprocess
import time
import threading

# --- Add project root to sys.path ---
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
# ---------------------------------------------------

from agent_crypto import AgentCryptoManager
from cryptography.exceptions import InvalidTag

class AgentFileProcessor:
    """
    Handles the processing of encrypted jobs for the agent, including
    loading job data, unwrapping CEKs, and decrypting/opening single files on demand.
    """

    def __init__(self):
        self.crypto_manager = AgentCryptoManager()
        self.loaded_jobs = {} # Stores {job_path_str: {'manifest': manifest, 'cek': cek, 'data_path': data_path}}

    def _send_log(self, gui_queue: queue.Queue, job_path_str: str, message: str):
        if gui_queue:
            gui_queue.put({"event": "LOG_EVENT", "job_path": job_path_str, "log_message": message})

    def _send_status(self, gui_queue: queue.Queue, job_path_str: str, status: str):
        if gui_queue:
            gui_queue.put({"event": "STATUS_UPDATE", "job_path": job_path_str, "status": status})

    def load_job_data(self, job_path: Path, gui_queue: queue.Queue, job_path_str: str) -> bool:
        """
        Loads the manifest and unwraps the CEK for a given encrypted job.
        Does NOT decrypt files.
        """
        manifest_path = job_path / "manifest.json"
        data_path = job_path / "data"

        if not all([manifest_path.exists(), data_path.exists()]):
            self._send_log(gui_queue, job_path_str, "Error: Job directory is incomplete (missing manifest.json or data folder).")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return False

        # 1. Load and Verify Manifest
        self._send_status(gui_queue, job_path_str, "VERIFYING_SIGNATURE")
        self._send_log(gui_queue, job_path_str, "Loading manifest...")
        try:
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
        except Exception as e:
            self._send_log(gui_queue, job_path_str, f"Error: Could not read manifest.json: {e}")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return False
        
        if not self.crypto_manager.verify_manifest_signature(manifest.copy()):
            self._send_log(gui_queue, job_path_str, "Error: Manifest signature is invalid. Aborting.")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return False
        self._send_log(gui_queue, job_path_str, "Manifest signature verified.")

        # 2. Unwrap CEK using the new asymmetric method
        self._send_log(gui_queue, job_path_str, "Unwrapping content key...")
        cek = self.crypto_manager.unwrap_cek(manifest)
        
        if not cek:
            self._send_log(gui_queue, job_path_str, "FATAL: Failed to unwrap content key. The key may be missing, corrupt, or this agent may not be authorized.")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return False
        
        self._send_log(gui_queue, job_path_str, "Content key unwrapped successfully.")
        
        # Store loaded job data
        self.loaded_jobs[job_path_str] = {
            'manifest': manifest,
            'cek': cek,
            'data_path': data_path
        }
        self._send_status(gui_queue, job_path_str, "READY_FOR_ACCESS")
        return True

    def decrypt_and_open_single_file(self, job_path_str: str, original_file_path: str, gui_queue: queue.Queue):
        """
        Decrypts a single file to a temporary location and opens it with the default application.
        Monitors the application and securely deletes the temporary file upon closure.
        """
        job_data = self.loaded_jobs.get(job_path_str)
        if not job_data:
            self._send_log(gui_queue, job_path_str, f"Error: Job data not loaded for {job_path_str}.")
            return

        manifest = job_data['manifest']
        cek = job_data['cek']
        data_path = job_data['data_path']
        
        file_info = manifest["files"].get(original_file_path)
        if not file_info:
            self._send_log(gui_queue, job_path_str, f"Error: File '{original_file_path}' not found in manifest.")
            return

        self._send_log(gui_queue, job_path_str, f"Attempting to open: {original_file_path}")
        
        encrypted_blob_name = file_info["encrypted_blob_name"]
        encrypted_file_path = data_path / encrypted_blob_name
        nonce = bytes.fromhex(file_info["nonce"])
        tag = bytes.fromhex(file_info["tag"])

        try:
            plaintext = self.crypto_manager.decrypt_file(encrypted_file_path, cek, nonce, tag)
            if not plaintext:
                self._send_log(gui_queue, job_path_str, f"Failed to decrypt {original_file_path}.")
                return

            # Create a temporary file
            original_path_obj = Path(original_file_path)
            temp_dir = Path(os.environ.get('TEMP', os.environ.get('TMP', '/tmp'))) / "smx_agent_temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            temp_file_path = temp_dir / f"{original_path_obj.name}"
            
            with open(temp_file_path, 'wb') as f:
                f.write(plaintext)
            
            self._send_log(gui_queue, job_path_str, f"Decrypted to temporary file: {temp_file_path}")

            # Open the temporary file with the default application
            # We use commands that wait for the application to close before returning.
            if sys.platform == "win32":
                # On Windows, 'start /WAIT' launches the application and waits.
                # We build the command as a single string with quotes around the path to be safe.
                command = f'start "" /WAIT "{temp_file_path}"'
                process = subprocess.Popen(command, shell=True)
            elif sys.platform == "darwin":
                # On macOS, 'open -W' waits for the application to close.
                process = subprocess.Popen(['open', '-W', str(temp_file_path)])
            else:
                # On Linux, 'xdg-open' does not have a wait flag, so this will still have the
                # original bug where the file is deleted immediately. A more complex solution
                # would be needed for Linux (e.g., using psutil to find the process).
                process = subprocess.Popen(['xdg-open', str(temp_file_path)])
            
            self._send_log(gui_queue, job_path_str, f"Launched application for {original_file_path}. Waiting for it to close...")

            # Monitor the process and delete the temp file when it closes
            def monitor_and_cleanup():
                try:
                    # For Windows/macOS, this now correctly waits.
                    # For Linux, this will return immediately.
                    process.wait() 
                    self._send_log(gui_queue, job_path_str, f"Application for {original_file_path} closed. Deleting temporary file.")
                    # Add a small delay to ensure the file handle is released by the OS
                    time.sleep(0.5)
                    os.remove(temp_file_path)
                    self._send_log(gui_queue, job_path_str, f"Temporary file {temp_file_path} deleted.")
                except Exception as cleanup_e:
                    self._send_log(gui_queue, job_path_str, f"Error during cleanup of {temp_file_path}: {cleanup_e}")

            threading.Thread(target=monitor_and_cleanup).start()

        except Exception as e:
            self._send_log(gui_queue, job_path_str, f"Error opening {original_file_path}: {e}")
            if 'temp_file_path' in locals() and temp_file_path.exists():
                try:
                    os.remove(temp_file_path)
                    self._send_log(gui_queue, job_path_str, f"Cleaned up failed temporary file {temp_file_path}.")
                except Exception as cleanup_e:
                    self._send_log(gui_queue, job_path_str, f"Error during cleanup of failed temporary file {temp_file_path}: {cleanup_e}")

