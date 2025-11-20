

import queue
import uuid
import json
import time
import threading
import subprocess
import tempfile
import datetime
import os
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field
from gateway.crypto import CryptoManager

JOB_ROOT_DIR = Path(__file__).parent.parent.parent / "jobs"

class JobState(Enum):
    INITIALIZED = "INITIALIZED"
    ENUMERATING = "ENUMERATING"
    POLICY_CHECK = "POLICY_CHECK"
    SCANNING = "SCANNING"
    WAITING_AGENT_SELECTION = "WAITING_AGENT_SELECTION"
    PACKAGING = "PACKAGING"
    SUCCESS = "SUCCESS"
    FAILED_POLICY = "FAILED_POLICY"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"

@dataclass
class Job:
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    drive_letter: str = ""
    state: JobState = JobState.INITIALIZED
    files_to_process: list = field(default_factory=list, init=False)
    gateway_info: dict = field(default_factory=dict, init=False)
    _path: Path = field(default=None, init=False)
    
    @property
    def path(self) -> Path:
        if self._path is None:
            return JOB_ROOT_DIR / self.job_id
        return self._path

class JobManager:
    def __init__(self, gui_queue, action_queue):
        self.gui_queue = gui_queue
        self.action_queue = action_queue
        self.crypto_manager = CryptoManager() # Create a single instance
        self.active_jobs: dict[str, Job] = {}
        self.job_threads: dict[str, threading.Thread] = {}
        self.lock = threading.Lock()
        self._shutdown_flag = threading.Event()
        JOB_ROOT_DIR.mkdir(parents=True, exist_ok=True)

    def start_new_job(self, drive_letter: str, device_metadata: dict):
        job = self._initialize_job(drive_letter, device_metadata)
        if not job:
            return

        with self.lock:
            self.active_jobs[job.job_id] = job
        
        self.gui_queue.put({
            "event": "NEW_JOB",
            "job_id": job.job_id,
            "drive_letter": drive_letter,
            "job_path": str(job.path)
        })

        thread = threading.Thread(target=self._process_job, args=(job.job_id,), daemon=True)
        self.job_threads[job.job_id] = thread
        thread.start()

    def _initialize_job(self, drive_letter: str, device_metadata: dict) -> Job | None:
        job = Job(drive_letter=drive_letter)
        job.gateway_info = device_metadata.get("gateway_info", {})
        try:
            # Create the directory first to prevent a race condition with logging
            job.path.mkdir(parents=True, exist_ok=False)
            
            self.log_event(job, "JOB_INIT_START", {"job_id": job.job_id, "device": drive_letter})
            self.log_event(job, "JOB_DIR_CREATED", {"path": str(job.path)})

            self._write_json_atomically(job.path / "metadata.json", device_metadata)
            self.update_state(job, JobState.INITIALIZED, {"detail": "Job created."})
            return job
        except Exception as e:
            # If initialization fails, we might not have a job path to log to,
            # so we print directly to the console as a fallback.
            print(f"[ERROR] Failed to initialize job {job.job_id}: {e}")
            self.log_event(job, "JOB_INIT_FAILED", {"job_id": job.job_id, "error": str(e)})
            return None

    def _find_defender_path(self) -> Path | None:
        """Finds the path to the Windows Defender command-line scanner."""
        self.log_event(Job(job_id="SYSTEM"), "FIND_MPCMDRUN_START", {})
        possible_paths = [
            Path(os.environ["ProgramFiles"]) / "Windows Defender" / "MpCmdRun.exe",
            Path(os.environ["ProgramFiles(x86)"]) / "Windows Defender" / "MpCmdRun.exe",
        ]
        for path in possible_paths:
            self.log_event(Job(job_id="SYSTEM"), "FIND_MPCMDRUN_CHECKING", {"path": str(path)})
            if path.exists():
                self.log_event(Job(job_id="SYSTEM"), "FIND_MPCMDRUN_FOUND", {"path": str(path)})
                return path
        self.log_event(Job(job_id="SYSTEM"), "FIND_MPCMDRUN_NOT_FOUND", {})
        return None

    def _process_job(self, job_id: str):
        with self.lock:
            job = self.active_jobs.get(job_id)
        if not job:
            return

        # --- 1. File Enumeration ---
        self.update_state(job, JobState.ENUMERATING, {"detail": "Starting file discovery."})
        self.log_event(job, "ENUMERATION_START", {"root_path": job.drive_letter})
        try:
            # Ensure the root path has a trailing slash for correct path joining
            root_path_str = job.drive_letter
            if not root_path_str.endswith("\\"):
                root_path_str += "\\"
            
            root_path = Path(root_path_str)
            output_dir_name = "SMX_Encrypted_Output"
            job.files_to_process = [p for p in root_path.rglob('*') if p.is_file() and output_dir_name not in p.parts]
            self.log_event(job, "ENUMERATION_COMPLETE", {"file_count": len(job.files_to_process)})
        except Exception as e:
            self.log_event(job, "ENUMERATION_FAILED", {"error": str(e)})
            self.update_state(job, JobState.FAILED, {"detail": "File enumeration failed."})
            return
        
        if not job.files_to_process:
            self.log_event(job, "NO_FILES_FOUND", {})
            self.update_state(job, JobState.SUCCESS, {"detail": "No files to process."})
            return

        # --- 2. Malware Scanning ---
        self.update_state(job, JobState.SCANNING, {"detail": "Starting malware scan."})
        defender_path = self._find_defender_path()
        if not defender_path:
            self.update_state(job, JobState.FAILED, {"detail": "Windows Defender scanner not found."})
            return
        
        self.log_event(job, "SCANNING_START", {"scanner": "Windows Defender", "file_count": len(job.files_to_process)})
        threat_found = False
        for file_path in job.files_to_process:
            try:
                command = [str(defender_path), "-Scan", "-ScanType", "3", "-File", str(file_path), "-DisableRemediation"]
                self.log_event(job, "DEFENDER_SCAN_START", {"command": " ".join(command)})
                
                result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
                
                stdout_lower = result.stdout.lower()
                is_error = "failed with hr" in stdout_lower or "error" in stdout_lower

                self.log_event(job, "DEFENDER_SCAN_COMPLETE", {"returncode": result.returncode, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()})
                
                # MpCmdRun exits with 2 for threats found, but also for scan errors.
                # We must check stdout to be sure.
                if result.returncode == 2 and not is_error:
                    threat_found = True
                    self.log_event(job, "THREAT_DETECTED", {"file": str(file_path), "details": result.stdout.strip()})
                    break 
                elif result.returncode != 0:
                    self.log_event(job, "SCAN_ERROR", {"file": str(file_path), "code": result.returncode, "output": result.stdout.strip()})
                # If returncode is 0, the file is clean. No log needed to reduce noise.

            except subprocess.TimeoutExpired:
                self.log_event(job, "SCAN_TIMEOUT", {"file": str(file_path)})
            except Exception as e:
                self.log_event(job, "SCAN_CRITICAL_ERROR", {"file": str(file_path), "error": str(e)})
                self.update_state(job, JobState.FAILED, {"detail": "A critical error occurred during malware scan."})
                return

        if threat_found:
            self.update_state(job, JobState.QUARANTINED, {"detail": "A threat was detected. Job quarantined."})
            return

        self.log_event(job, "SCAN_COMPLETED_CLEAN", {"files_scanned": len(job.files_to_process)})

        # --- 3. Wait for Agent Selection ---
        self.update_state(job, JobState.WAITING_AGENT_SELECTION, {"detail": "Scan complete. Awaiting user input."})
        agent_list = list(self.crypto_manager.get_available_agents().keys())
        
        self.gui_queue.put({
            "event": "REQUEST_AGENT_SELECTION",
            "job_id": job.job_id,
            "agent_list": agent_list
        })
        
    def process_actions(self):
        """Run in a dedicated thread to process actions from the GUI."""
        while not self._shutdown_flag.is_set():
            try:
                action = self.action_queue.get(timeout=1)
                if action.get("action") == "AGENTS_SELECTED":
                    self._handle_agent_selection(action)
            except queue.Empty:
                continue

    def _handle_agent_selection(self, action: dict):
        job_id = action.get("job_id")
        selected_agents = action.get("selected_agents")

        with self.lock:
            job = self.active_jobs.get(job_id)
        if not job:
            return

        drive_path_str = job.drive_letter
        if not drive_path_str.endswith("\\"):
            drive_path_str += "\\"
        drive_path = Path(drive_path_str)

        if not drive_path.exists():
            self.update_state(job, JobState.ABORTED, {"detail": "Device removed before agent selection."})
            return
            
        if not selected_agents:
            self.update_state(job, JobState.ABORTED, {"detail": "User cancelled agent selection."})
            return

        # --- 4. Packaging ---
        self.update_state(job, JobState.PACKAGING)
        self.log_event(job, "PACKAGING_START", {"selected_agents": selected_agents})
        
        # Define output directory on the USB drive
        output_dir = drive_path / "SMX_Encrypted_Output"
        data_dir = output_dir / "data"
        try:
            output_dir.mkdir(exist_ok=True)
            data_dir.mkdir(exist_ok=True)
            self.log_event(job, "OUTPUT_DIR_CREATED", {"path": str(output_dir)})
        except Exception as e:
            self.update_state(job, JobState.FAILED, {"detail": f"Could not create output directory on USB drive: {e}"})
            return

        cek = self.crypto_manager.generate_cek()
        wrapped_ceks = self.crypto_manager.wrap_cek_for_selected_agents(cek, selected_agents)

        if not wrapped_ceks:
            self.update_state(job, JobState.FAILED, {"detail": "Failed to wrap CEK for selected agents."})
            self.log_event(job, "PACKAGING_FAILED", {"reason": "CEK wrapping returned no keys."})
            return
        
        file_metadata = {}
        for file_path in job.files_to_process:
            self.log_event(job, "ENCRYPTING_FILE", {"file": str(file_path)})
            
            encryption_result = self.crypto_manager.encrypt_file(file_path, cek)
            if not encryption_result:
                self.log_event(job, "ENCRYPTION_FAILED", {"file": str(file_path)})
                # Decide if one failure fails the job. For now, we'll just log and continue.
                continue

            ciphertext, nonce, tag, original_size = encryption_result
            
            # Save the encrypted file
            # Use the string of the full, unique path to generate the hash for the filename
            encrypted_filename = self.crypto_manager.get_sha256_hash(str(file_path).encode())
            encrypted_file_path = data_dir / encrypted_filename
            
            try:
                with open(encrypted_file_path, 'wb') as f:
                    f.write(ciphertext)
            except Exception as e:
                self.log_event(job, "FILE_WRITE_FAILED", {"file": str(encrypted_file_path), "error": str(e)})
                continue

            # Store metadata for the manifest
            relative_path = str(file_path.relative_to(drive_path))
            file_metadata[relative_path] = {
                "encrypted_filename": encrypted_filename,
                "original_size": original_size,
                "sha256_hash_encrypted": self.crypto_manager.get_sha256_hash(ciphertext),
                "nonce": nonce.hex(),
                "tag": tag.hex()
            }

        # Create and write the final manifest
        manifest = self.crypto_manager.create_manifest(
            job, 
            file_metadata, 
            wrapped_ceks, 
            job.gateway_info,
            pendrive_output_path=str(output_dir)
        )
        signed_manifest = self.crypto_manager.sign_manifest(manifest)
        
        # Write to the USB output directory
        self._write_json_atomically(output_dir / "manifest.json", signed_manifest)
        # Also write a copy to the local job folder
        self._write_json_atomically(job.path / "manifest.json", signed_manifest)

        self.log_event(job, "PACKAGING_COMPLETE", {"manifest_file": str(output_dir / "manifest.json"), "encrypted_files": len(file_metadata)})
        self.update_state(job, JobState.SUCCESS, {"detail": f"Successfully packaged {len(file_metadata)} files."})


    def update_state(self, job: Job, new_state: JobState, details: dict = None):
        job.state = new_state
        self.log_event(job, "STATE_TRANSITION", {"new_state": new_state.value, "details": details or {}})
        
        state_payload = { "current_state": new_state.value, "timestamp": datetime.datetime.utcnow().isoformat() + "Z" }
        self._write_json_atomically(job.path / "state.json", state_payload)

        if self.gui_queue:
            self.gui_queue.put({"event": "STATE_UPDATE", "job_id": job.job_id, "state": new_state.value})

    def log_event(self, job: Job, event_type: str, data: dict):
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "data": data
        }
        try:
            with open(job.path / "logs.jsonl", 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            # Fallback for logging before job dir exists
            if "No such file or directory" in str(e):
                print(f"Fallback Log for {job.job_id}: {event_type} - {data}")
            else:
                print(f"Warning: Failed to write log for {job.job_id}: {e}")

        if self.gui_queue:
            # Create a simple, human-readable message for the GUI
            gui_message = f"{event_type}: {json.dumps(data)}"
            self.gui_queue.put({"event": "LOG_EVENT", "job_id": job.job_id, "log_message": gui_message})

    def _write_json_atomically(self, file_path: Path, data: dict):
        fd, tmp_path_str = tempfile.mkstemp(dir=file_path.parent)
        try:
            with os.fdopen(fd, 'w') as tmp_file:
                json.dump(data, tmp_file, indent=4)
            Path(tmp_path_str).replace(file_path)
        except Exception as e:
            if Path(tmp_path_str).exists():
                Path(tmp_path_str).unlink()
            raise
    
    def handle_device_removal(self, drive_letter: str):
        with self.lock:
            job_to_remove = None
            for job_id, job in self.active_jobs.items():
                if job.drive_letter == drive_letter:
                    job_to_remove = job_id
                    break
            
            if job_to_remove:
                job = self.active_jobs[job_to_remove]
                # If job is waiting, it's a user-driven abort. Otherwise, it's an unexpected failure.
                if job.state == JobState.WAITING_AGENT_SELECTION:
                    self.update_state(job, JobState.ABORTED, {"detail": "Device removed before agents were selected."})
                else:
                    self.update_state(job, JobState.FAILED, {"detail": "Device removed unexpectedly during processing."})
                
                # Signal the job thread to stop (not implemented in this simplified version)
                # and notify the GUI.
                self.gui_queue.put({"event": "DEVICE_REMOVED", "job_id": job.job_id})

    def shutdown(self):
        self._shutdown_flag.set()
        self.log_event(Job(job_id="SYSTEM"), "SHUTDOWN", {})
